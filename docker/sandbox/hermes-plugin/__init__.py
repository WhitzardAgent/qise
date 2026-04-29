"""Qise Security Plugin for Hermes — installed as user plugin."""
from __future__ import annotations

import logging
import os

logger = logging.getLogger("qise.hermes_plugin")


def register(ctx):
    """Register Qise security plugin with Hermes."""
    from qise import Shield
    from qise.adapters.hermes import QiseHermesPlugin

    config_path = os.getenv("QISE_CONFIG", "/root/.hermes/shield.yaml")
    shield = Shield.from_config(config_path)
    plugin = QiseHermesPlugin(shield)
    plugin.register(ctx)
    logger.info(
        "Qise plugin registered with %d guards", len(shield.pipeline.all_guards)
    )
