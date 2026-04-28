"""Shield — main entry point for Qise security framework.

Wires together: GuardPipeline, ModelRouter, SecurityContextProvider, ShieldConfig,
ThreatPatternLoader, BaselineManager, and all enabled Guards.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from qise.core.config import ShieldConfig
from qise.core.event_logger import EventLogger
from qise.core.guard_base import AIGuardBase
from qise.core.models import GuardContext, GuardResult, GuardVerdict, PipelineResult
from qise.core.pipeline import GuardPipeline
from qise.core.session_tracker import SessionTracker
from qise.data.baseline_manager import BaselineManager
from qise.data.pattern_loader import ThreatPatternLoader
from qise.models.router import ModelConfig, ModelRouter
from qise.providers.security_context import SecurityContextProvider


# Guard imports
from qise.guards.audit import AuditGuard
from qise.guards.command import CommandGuard
from qise.guards.context import ContextGuard
from qise.guards.credential import CredentialGuard
from qise.guards.exfil import ExfilGuard
from qise.guards.filesystem import FilesystemGuard
from qise.guards.network import NetworkGuard
from qise.guards.output import OutputGuard
from qise.guards.prompt import PromptGuard
from qise.guards.reasoning import ReasoningGuard
from qise.guards.resource import ResourceGuard
from qise.guards.supply_chain import SupplyChainGuard
from qise.guards.tool_policy import ToolPolicyGuard, ToolPolicyProfile
from qise.guards.tool_sanity import ToolSanityGuard

# Guard name → factory class mapping
_GUARD_FACTORIES: dict[str, type[AIGuardBase]] = {
    "prompt": PromptGuard,
    "command": CommandGuard,
    "credential": CredentialGuard,
    "reasoning": ReasoningGuard,
    "filesystem": FilesystemGuard,
    "network": NetworkGuard,
    "exfil": ExfilGuard,
    "resource": ResourceGuard,
    "audit": AuditGuard,
    "tool_sanity": ToolSanityGuard,
    "context": ContextGuard,
    "output": OutputGuard,
    "tool_policy": ToolPolicyGuard,
    "supply_chain": SupplyChainGuard,
}


class Shield:
    """Main entry point for Qise security framework.

    Usage:
        shield = Shield.from_config("shield.yaml")
        result = await shield.check_tool_call("bash", {"command": "rm -rf /"})
        context = shield.get_security_context("bash", {"command": "rm -rf /"})
    """

    def __init__(
        self,
        config: ShieldConfig | None = None,
        pipeline: GuardPipeline | None = None,
        model_router: ModelRouter | None = None,
        context_provider: SecurityContextProvider | None = None,
        pattern_loader: ThreatPatternLoader | None = None,
        session_tracker: SessionTracker | None = None,
        event_logger: EventLogger | None = None,
        baseline_manager: BaselineManager | None = None,
    ) -> None:
        self.config = config or ShieldConfig.default()
        self.model_router = model_router or self._build_model_router()
        self.context_provider = context_provider or self._build_context_provider()
        self.pattern_loader = pattern_loader or self._build_pattern_loader()
        self.session_tracker = session_tracker or SessionTracker()
        self.event_logger = event_logger or EventLogger(
            level=self.config.logging.level,
            output=self.config.logging.output,
        )
        self.baseline_manager = baseline_manager or self._build_baseline_manager()

        # Build guards and pipeline
        self.pipeline = pipeline or self._build_guards()

        # Wire model router into all guards
        for guard in self.pipeline.all_guards:
            guard.set_model_router(self.model_router)

    @classmethod
    def from_config(cls, path: str | Path | None = None) -> Shield:
        """Create a Shield from a shield.yaml file.

        If path is None, looks for ./shield.yaml, then falls back to defaults.
        """
        if path is None:
            default_path = Path("shield.yaml")
            path = default_path if default_path.exists() else Path("nonexistent")

        config = ShieldConfig.from_yaml(path)
        return cls(config=config)

    async def check(self, context: GuardContext) -> PipelineResult:
        """Run applicable guard pipelines and return aggregate result."""
        guard_modes = {
            name: self.config.guard_mode(name)
            for name in self.config.guards.enabled
        }

        # Determine which pipelines to run based on context
        if context.trust_boundary is not None:
            return self.pipeline.run_ingress(context, guard_modes)

        return self.pipeline.run_egress(context, guard_modes)

    async def check_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        **kwargs: Any,
    ) -> PipelineResult:
        """Convenience method: build GuardContext and run egress check."""
        context = GuardContext(
            tool_name=tool_name,
            tool_args=tool_args,
            **kwargs,
        )
        guard_modes = {
            name: self.config.guard_mode(name)
            for name in self.config.guards.enabled
        }
        return self.pipeline.run_egress(context, guard_modes)

    def get_security_context(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
    ) -> str:
        """Get rendered security context for injection into agent observation."""
        return self.context_provider.render_for_agent(tool_name, tool_args)

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    def _build_model_router(self) -> ModelRouter:
        """Build ModelRouter from config."""
        return ModelRouter(
            slm_config=self.config.models.slm,
            llm_config=self.config.models.llm,
            embedding_config=self.config.models.embedding,
        )

    def _build_context_provider(self) -> SecurityContextProvider:
        """Build SecurityContextProvider from config data path."""
        contexts_dir = Path(self.config.data.security_contexts_dir)
        return SecurityContextProvider(contexts_dir)

    def _build_pattern_loader(self) -> ThreatPatternLoader:
        """Build ThreatPatternLoader from config data path."""
        patterns_dir = Path(self.config.data.threat_patterns_dir)
        return ThreatPatternLoader(patterns_dir)

    def _build_baseline_manager(self) -> BaselineManager:
        """Build BaselineManager from config data path."""
        baselines_dir = Path(self.config.data.baselines_dir)
        return BaselineManager(baselines_dir)

    def _build_guards(self) -> GuardPipeline:
        """Build GuardPipeline with enabled guards from config.

        Pipeline assignment:
          Ingress: prompt, reasoning, tool_sanity, context, supply_chain
          Egress: command, filesystem, network, exfil, resource, tool_policy
          Output: credential, audit, output
        """
        pipeline = GuardPipeline()

        for guard_name in self.config.guards.enabled:
            if not self.config.is_guard_enabled(guard_name):
                continue

            guard = self._create_guard(guard_name)
            if guard is None:
                continue

            # Assign to pipeline based on guard role
            if guard_name in ("prompt", "reasoning", "tool_sanity", "context", "supply_chain"):
                pipeline.ingress.add_guard(guard)
            elif guard_name in ("command", "filesystem", "network", "exfil", "resource", "tool_policy"):
                pipeline.egress.add_guard(guard)
            elif guard_name in ("credential", "audit", "output"):
                pipeline.output.add_guard(guard)
            else:
                # Default: egress for unknown guards
                pipeline.egress.add_guard(guard)

        return pipeline

    def _create_guard(self, guard_name: str) -> AIGuardBase | None:
        """Create a guard instance by name, injecting dependencies as needed."""
        factory = _GUARD_FACTORIES.get(guard_name)
        if factory is None:
            return None

        # Pass shared resources to guards that need them
        if guard_name == "prompt":
            return factory(pattern_loader=self.pattern_loader)

        if guard_name == "audit":
            return factory(
                session_tracker=self.session_tracker,
                event_logger=self.event_logger,
            )

        if guard_name == "tool_sanity":
            return factory(
                baseline_manager=self.baseline_manager,
                pattern_loader=self.pattern_loader,
            )

        if guard_name == "context":
            return factory(
                baseline_manager=self.baseline_manager,
                pattern_loader=self.pattern_loader,
            )

        if guard_name == "supply_chain":
            return factory(baseline_manager=self.baseline_manager)

        if guard_name == "tool_policy":
            return factory(
                profiles=self._build_tool_policy_profiles(),
                active_profile=self.config.tool_policy.active_profile,
            )

        return factory()

    def _build_tool_policy_profiles(self) -> dict[str, ToolPolicyProfile]:
        """Build tool policy profiles from config."""
        profiles: dict[str, ToolPolicyProfile] = {}
        for name, profile_cfg in self.config.tool_policy.profiles.items():
            profiles[name] = ToolPolicyProfile(
                deny=profile_cfg.deny,
                require_approval=profile_cfg.require_approval,
                owner_only=profile_cfg.owner_only,
                allow_all=profile_cfg.allow_all,
            )
        return profiles
