# Dataset Catalog & Coverage Analysis

**Last updated**: 2026-05-03
**Purpose**: Catalog all available public datasets for QiseGuard-SLM training, analyze coverage across 10 classification tasks, and identify gaps requiring synthetic data generation.

---

## 1. Public Dataset Catalog

### 1.1 Datasets Already Integrated in Qise

| Dataset | HF/GitHub ID | Size | Format | License | Current Use |
|---------|-------------|------|--------|---------|-------------|
| AgentDojo | `ffuuugor/agentdojo-dump` | 13,913 rows | Parquet/JSON | Unspecified | eval/converters/agentdojo.py |
| AgentHarm | `ai-safety-institute/AgentHarm` | 468 rows (208 harmful + 208 benign + 52 chat) | Parquet | MIT (+ safety clause) | eval/converters/agentharm.py |
| CyberSecEval 4 | Meta PurpleLlama (GitHub) | 3,005 rows (251 PI + 1004 multi-lang + 1000 MITRE + 750 FRR) | JSON | MIT | eval/converters/cyberseceval.py |

### 1.2 HuggingFace Datasets — Prompt Injection & Agent Attacks

| Dataset | HF ID | Size | Format | License | Applicable Tasks |
|---------|-------|------|--------|---------|-----------------|
| Prompt Injection Mechanisms | `Smooth-3/llm-prompt-injection-attacks` | 55,000 (49.5k train / 5.5k val) | Parquet | Apache 2.0 | Task 1, 3 (5 labels: BENIGN/JAILBREAK/INSTRUCTION_OVERRIDE/ROLE_HIJACK/DATA_EXFILTRATION) |
| Indirect PI Detection (BIPIA+GPT) | `MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT` | 70,000 (35k malicious + 35k benign) | JSON | CC BY-SA 4.0 | Task 1 (indirect injection) |
| PI Attack Dataset | `xxz224/prompt-injection-attack-dataset` | 3,750 | CSV/Parquet | Unspecified | Task 1 (5 attack types) |
| PI Detection Multilingual | `Octavio-Santana/prompt-injection-attack-detection-multilingual` | 7,924 (6,340 train / 1,590 test) | Parquet | GPL | Task 1 (multilingual) |
| HarmBench | `walledai/HarmBench` | 400 behaviors | Parquet | MIT | Task 1, 2, 3 |
| HarmBench (swiss-ai) | `swiss-ai/harmbench` | 2,400 (400 DirectRequest + ~2,000 HumanJailbreaks) | Parquet | — | Task 1, 2, 3 |
| Agent-SafetyBench | `thu-coai/Agent-SafetyBench` | Complex nested JSON | JSON | MIT | Task 1, 2, 9 |
| Adversarial Agent Intent 240K | `yatin-superintelligence/Adversarial-Agent-Intent-Safety-Analysis-240K` | 242,454 | Parquet | Open RAIL-D | Task 1, 2, 4, 10 (intent analysis + sophistication levels) |
| Multi-turn Jailbreak | `tom-gibbs/multi-turn_jailbreak_attack_datasets` | 6,918 (4,136 harmful + 2,782 benign) | CSV | MIT | Task 10 (multi-turn chains) |
| AgentDojo Trajectories | `changdae/agentdojo-trajectories-qwen35-gemma4` | 97 utility + 949 attack trajectories | JSON | Apache 2.0 | Task 1, 10 (full conversation trajectories) |
| MCP Tool Use Quality | `rogue-security/mcp-tool-use-quality-benchmark` | 1K-10K | Parquet | Gated | Task 6 (tool poisoning + param errors) |

### 1.3 HuggingFace Datasets — PII & Credential Detection

| Dataset | HF ID | Size | Format | License | Applicable Tasks |
|---------|-------|------|--------|---------|-----------------|
| PII Masking 200K | `ai4privacy/pii-masking-200k` | 209K rows, 54 PII classes | Parquet/JSON | Unspecified | Task 9 |
| PII Detection English | `Ari-S-123/pii-detection-english-consolidated` | 156,688 (125k train / 31k test) | Parquet | MIT | Task 9 (17 PII types including SSN, CREDITCARD, PASSPORT) |
| PII Intent Multilingual | `gorkem371/pii-intent-detection-multilingual` | 41,427 (35k train / 6k val) | JSON/Parquet | Apache 2.0 | Task 9 (PII sharing intent detection) |
| PII Detection Fixtures | `mukunda1729/pii-detection-fixtures` | 25 | JSON | MIT | Task 9 (api_key, aws_access_key, github_token, jwt) |
| PII in Python Code | `bigcode/pseudo-labeled-python-data-pii-detection-filtered` | 18,000 | Parquet | Gated | Task 9 (PII in source code) |

### 1.4 GitHub Datasets — Agent Security

| Dataset | GitHub URL | Size | Format | License | Applicable Tasks |
|---------|-----------|------|--------|---------|-----------------|
| AgentPoison | `AI-secure/AgentPoison` | 3 agent domains, optimized triggers | JSON/YAML | MIT | Task 5 (memory/KB poisoning) |
| AgentDojo (source) | `ethz-spylab/agentdojo` | Full benchmark suite | Python pkg | MIT | Task 1 |
| HarmBench (source) | `centerforaisafety/HarmBench` | 400 behaviors + classifier | CSV/YAML | MIT | Task 1, 2, 3 |
| InjecAgent | `uiuc-kang-lab/InjecAgent` | 1,054 test cases (17 user tools, 62 attacker tools) | JSONL | MIT | Task 1, 3, 9 (indirect injection + data stealing) |
| AgentDyn | `SaFo-Lab/AgentDyn` | 60 user tasks + 560 injection cases | Python pkg | MIT | Task 1, 2, 9 |
| PIArena | `sleeepeer/PIArena` | HF-hosted, 10 attack types, 9+ defenses | HF Dataset | MIT | Task 1, 2 |
| InjectLab | `ahow2004/injectlab` | 19 techniques across 6 tactics | YAML | MIT | Task 1, 2, 3, 4, 9, 10 |
| MCPTox-Benchmark | `zhiqiangwang4/MCPTox-Benchmark` | Real-world MCP servers | JSON | Unspecified | Task 6 (tool poisoning) |
| MCP Injection Experiments | `invariantlabs-ai/mcp-injection-experiments` | 3 attack PoCs (sleeper rug-pull, hidden exfil) | Python | Unspecified | Task 6, 3 |
| AgentDefense-Bench | `arunsanna/AgentDefense-Bench` | 35,989 total (35,546 attack + 443 benign) | JSON (MCP JSON-RPC) | Apache 2.0 | Task 1, 2, 3, 5, 6, 7, 10 (17 MCP attack vectors) |
| AgentSeal | `getagentseal/agentseal` | 225+ probes (82 extraction + 143 injection + 45 MCP poison + 28 RAG poison) | SARIF/JSON/YAML | FSL-1.1 | Task 1, 6, 7 |
| Skill Audit MCP | `eltociear/skill-audit-mcp` | 68+ malicious patterns | Python/JSON | MIT | Task 6, 7 |
| Agent Egress Bench | `luckyPipewrench/agent-egress-bench` | 143 cases (106 malicious + 37 benign) | JSON/JSONL | Apache 2.0 | Task 3, 6, 9 (16 attack categories, OWASP mapping) |
| AgentShield Benchmark | `doronp/agentshield-benchmark` | 537 total (8 categories, 87 exfil tests) | JSONL/JSON | Apache 2.0 | Task 3, 1, 9 |
| Contemporary Agent Attacks | `AndrewSispoidis/contemporary-agent-attacks` | 1,669 total (497 attacks + 1,172 benign) | .txt | CC BY 4.0 | Task 2, 3, 5, 9 (credential exfil 44, PII 20, exfil 28) |
| AgentTrust | `chenglin1112/AgentTrust` | 300 scenarios + 630 tests + 192 unit tests | Python/JSON | AGPL-3.0 | Task 2, 3, 7, 9, 10 (RiskChain: 7 multi-step attack patterns, ShellNormalizer deobfuscation) |
| ClawSafety | `weibowen555/ClawSafety` | 120 adversarial test cases (50+ file workspaces, 64-turn) | Python/tar.gz | MIT+CC-BY-4.0 | Task 1, 3, 6, 9 |
| MINJA | `dsh3n77/MINJA` | 3 agent systems (RAP, EHR, QA) | Python/Jupyter | Unspecified | Task 5 (query-only memory injection) |
| ISC-Bench | `wuyoscar/ISC-bench` | 84 templates across 9 domains | JSON | Academic only | Task 2, 9, 10 |
| OWASP Agentic Security | `evolutionstorm/owasp-agentic-security-dataset` | 10 ASI entries, 80+ mitigations, 70+ attack scenarios | JSON/YAML | CC BY-SA 4.0 | Task 7, 10, all (OWASP Top 10 for Agentic Apps 2026) |
| Tinman OpenClaw Eval | `tinmanlabsl/tinman-openclaw-eval` | 288 attack probes across 12 categories | Markdown/JSON/SARIF | Apache 2.0 | Task 1, 5, 6, 7 |
| PurpleLlama | `meta-llama/PurpleLlama` | CyberSecEval 4 datasets | JSON | MIT | Task 1, 2 |

### 1.5 Qise Internal Datasets

| Dataset | Path | Size | Format | Applicable Tasks |
|---------|------|------|--------|-----------------|
| Injection Attacks | `eval/datasets/injection_attacks.yaml` | 15+ cases | YAML | Task 1 |
| Exfil Attacks | `eval/datasets/exfil_attacks.yaml` | 10+ cases | YAML | Task 3 |
| Reasoning Attacks | `eval/datasets/reasoning_attacks.yaml` | 10+ cases | YAML | Task 4 |
| Safe Operations | `eval/datasets/safe_operations.yaml` | 50+ cases | YAML | All tasks (negative samples) |

---

## 2. Coverage Analysis by Task

### Task 1: Injection Detection (PromptGuard)

| Source | Attack Samples | Safe Samples | Notes |
|--------|---------------|-------------|-------|
| AgentDojo | ~10,000+ | ~86 | Main injection dataset; tool_result, web, email vectors |
| Prompt Injection Mechanisms (HF) | ~49,500 | ~49,500 | 5-label classification; largest injection dataset |
| Indirect PI BIPIA+GPT (HF) | ~35,000 | ~35,000 | Indirect injection specific; 70K total |
| InjecAgent | 1,054 | — | 17 user tools + 62 attacker tools |
| CyberSecEval PI | 251 + 1,004 | 0 | Direct + multilingual injection |
| HarmBench | 200+ | 0 | Harmful behavior prompts |
| InjectLab | ~57 (19 techniques) | — | ATT&CK-style LLM threat matrix |
| AgentDefense-Bench | 35,546 (all attack vectors) | 443 | MCP JSON-RPC format |
| **Total available** | **~130,000+** | **~85,000+** | |

**Coverage**: EXCELLENT — the best-covered task by far. Need to sample strategically to avoid class imbalance with other tasks.

**Gap**: Safe samples with injection-like keywords (code with "ignore errors", docs with "important note") — partially covered by HF datasets.

### Task 2: Command Safety (CommandGuard)

| Source | Attack Samples | Safe Samples | Notes |
|--------|---------------|-------------|-------|
| CyberSecEval MITRE | 1,000 | 0 | MITRE ATT&CK mapped commands |
| CyberSecEval FRR | 0 | 750 | Benign command baselines |
| AgentTrust | 630+ tests | — | ShellNormalizer deobfuscation |
| Contemporary Agent Attacks | ~50 (credential exfil cmds) | 1,172 benign | CC BY 4.0 |
| ISC-Bench | 84 templates | — | 9 domains, shell access eval |
| **Total available** | **~1,780+** | **~1,920+** | |

**Coverage**: GOOD — attack and safe data both available.

**Gap**: Obfuscated command variants (hex, ${IFS}, backslash escape) — AgentTrust has ShellNormalizer but not as training data.

### Task 3: Exfiltration Detection (ExfilGuard)

| Source | Attack Samples | Safe Samples | Notes |
|--------|---------------|-------------|-------|
| Prompt Injection Mechanisms (HF) | ~11,000 (DATA_EXFILTRATION label) | — | Dedicated exfiltration label in 55K dataset |
| AgentShield Benchmark | 87 exfil tests | — | 8 categories, Ed25519 integrity |
| Contemporary Agent Attacks | 44 credential exfil + 28 exfil | — | CC BY 4.0 |
| Agent Egress Bench | 106 malicious cases | 37 benign | 16 attack categories, OWASP mapping |
| AgentTrust | — | — | RiskChain includes exfil chains |
| Qise internal | 10+ | 5+ | Custom exfil cases |
| **Total available** | **~11,200+** | **~42+** | |

**Coverage**: DRAMATICALLY IMPROVED — the 55K HF dataset with DATA_EXFILTRATION label is a game changer.

**Gap**: Covert channel detection (base64 encoding, DNS exfil patterns) — still needs synthetic data.

### Task 4: Reasoning Safety (ReasoningGuard)

| Source | Attack Samples | Safe Samples | Notes |
|--------|---------------|-------------|-------|
| InjectLab (Output Manipulation) | ~9 (3 techniques) | — | Output manipulation tactics |
| Adversarial Agent Intent 240K | ~242K (intent analysis) | — | Contains reasoning/intent analysis |
| Qise internal | 10+ | 5+ | Custom reasoning attack cases |
| **Total available** | **~10 (direct)** | **~5** | |

**Coverage**: CRITICAL — no dedicated reasoning manipulation dataset. The Adversarial Agent Intent 240K has intent analysis but not specifically agent reasoning chains.

**Gap**: Still entirely needs synthetic generation for:
- Exfiltration intent in reasoning (~50)
- Bypass intent in reasoning (~50)
- Privilege escalation intent (~30)
- Injection compliance reasoning (~40)
- Evasion planning reasoning (~30)
- Safe reasoning about security concepts (~50)

### Task 5: Context Poisoning (ContextGuard)

| Source | Attack Samples | Safe Samples | Notes |
|--------|---------------|-------------|-------|
| AgentPoison | ~100+ (poisoned passages) | ~100+ (clean passages) | KB poisoning with optimized triggers |
| MINJA | 3 agent systems | — | Query-only memory injection |
| ClawSafety | 120 adversarial (incl. skill/email/web) | — | 50+ file workspaces |
| AgentSeal RAG Probes | 28 RAG poisoning probes | 0 | Probes for RAG injection |
| **Total available** | **~350+** | **~100+** | |

**Coverage**: MODERATE — improved by MINJA and ClawSafety.

**Gap**: Memory poisoning (distinct from KB), subtle manipulation, safe context with edge cases (~80).

### Task 6: Tool Poisoning (ToolSanityGuard)

| Source | Attack Samples | Safe Samples | Notes |
|--------|---------------|-------------|-------|
| MCPTox-Benchmark | Real-world MCP servers | — | AAAI 2026 |
| MCP Injection Experiments | 3 attack PoCs | — | Sleeper rug-pull, hidden exfil |
| AgentDefense-Bench | 35,546 (incl. tool attacks) | 443 | 17 MCP attack vectors |
| AgentSeal MCP Probes | 45 MCP tool poisoning probes | 0 | MCP-specific poisoning |
| MCP Tool Use Quality (HF) | 1K-10K (incl. tool errors) | — | VALID_CALL/TOOL_ERROR/PARAM errors |
| Tinman OpenClaw Eval | 288 probes (12 categories) | — | Includes MCP category |
| Skill Audit MCP | 68 malicious patterns | 0 | Pattern-based detection |
| **Total available** | **~36,000+** | **~443** | |

**Coverage**: STRONG for attacks, but safe samples still very limited.

**Gap**: Safe tool descriptions (~150), rug-pull variations (~50).

### Task 7: Supply Chain (SupplyChainGuard)

| Source | Attack Samples | Safe Samples | Notes |
|--------|---------------|-------------|-------|
| AgentDefense-Bench | (included in 35,989) | 443 | Package squatting, rug pull, config drift |
| OWASP Agentic Security | 70+ attack scenarios | — | OWASP Top 10 for Agentic Apps 2026 |
| AgentSeal MCP Registry | 6,600+ MCP servers (trust scores) | — | Registry data |
| Contemporary Agent Attacks | (included in 497) | — | Some supply chain attacks |
| **Total available** | **~70+ (dedicated)** | **~443** | |

**Coverage**: IMPROVED — OWASP dataset and AgentDefense-Bench provide real supply chain attack scenarios.

**Gap**: Still needs dedicated supply chain Skill/MCP configurations with malicious patterns (~40).

### Task 8: Resource Abuse (ResourceGuard)

| Source | Attack Samples | Safe Samples | Notes |
|--------|---------------|-------------|-------|
| AgentShield Benchmark | (latency category included) | — | Some resource abuse cases |
| **Total available** | **~0-10** | **0** | |

**Coverage**: CRITICAL — still the most under-covered task. No dedicated resource abuse dataset exists.

**Gap**: Entirely synthetic:
- Infinite loop patterns in tool calls (~50)
- Behavioral anomaly sequences (~30)
- Resource exhaustion patterns (~30)
- Safe iterative patterns (debugging loops, retries) (~50)

### Task 9: Output Leakage (OutputGuard)

| Source | Attack Samples | Safe Samples | Notes |
|--------|---------------|-------------|-------|
| PII Masking 200K (HF) | 209K (PII examples) | — | 54 PII classes |
| PII Detection English (HF) | 156,688 | 31,688 test | 17 PII types |
| PII Intent Multilingual (HF) | 41,427 | — | PII sharing intent |
| PII Detection Fixtures (HF) | 25 | — | api_key, aws_access_key, github_token |
| Contemporary Agent Attacks | 20 PII leakage | — | CC BY 4.0 |
| Agent Egress Bench | (included in 143 cases) | 37 | DLP-focused |
| **Total available** | **~407K+** (needs adaptation) | **~31,700+** | |

**Coverage**: EXCELLENT for PII — multiple large datasets available. Need adaptation for agent output context.

**Gap**: KB content leakage (not PII, but proprietary content), credential fragments.

### Task 10: Attack Chain Correlation (AuditGuard)

| Source | Attack Samples | Safe Samples | Notes |
|--------|---------------|-------------|-------|
| AgentTrust | 7 multi-step attack chain patterns (RiskChain) | — | Order-aware matching |
| AgentDefense-Bench | 35,546 (incl. composed attacks) | 443 | Multi-step MCP chains |
| Multi-turn Jailbreak (HF) | 4,136 harmful conversations | 2,782 benign | Multi-turn attack patterns |
| OWASP Agentic Security | 70+ scenarios (some multi-step) | — | Real-world incident tracking |
| ISC-Bench | 84 templates | — | Task-Validator-Data architecture |
| **Total available** | **~4,300+** | **~3,200+** | |

**Coverage**: MODERATE — significantly improved by multi-turn and composed attack datasets. Not directly "attack chain" labeled but can be adapted.

**Gap**: Labeled sequential tool-call chains showing recon→exploit→exfil progression.

---

## 3. Coverage Summary Matrix (Updated)

| Task | Public Attack Data | Public Safe Data | Coverage Level | Gap Severity |
|------|-------------------|-----------------|----------------|-------------|
| 1. Injection Detection | ~130,000+ | ~85,000+ | EXCELLENT | LOW |
| 2. Command Safety | ~1,780+ | ~1,920+ | GOOD | LOW |
| 3. Exfiltration | ~11,200+ | ~42 | GOOD→MODERATE | MEDIUM (safe samples + covert channels) |
| 4. Reasoning Safety | ~10 | ~5 | CRITICAL | CRITICAL |
| 5. Context Poisoning | ~350+ | ~100+ | MODERATE | MEDIUM |
| 6. Tool Poisoning | ~36,000+ | ~443 | STRONG (attacks) | LOW-MEDIUM (safe samples) |
| 7. Supply Chain | ~70+ (dedicated) | ~443 | MODERATE | MEDIUM |
| 8. Resource Abuse | ~0-10 | 0 | CRITICAL | CRITICAL |
| 9. Output Leakage | ~407K+ (PII) | ~31,700+ | EXCELLENT (PII) | LOW-MEDIUM (KB leak) |
| 10. Attack Chain | ~4,300+ | ~3,200+ | MODERATE | MEDIUM |

**Overall**: Only 2 tasks remain CRITICAL (Task 4 Reasoning, Task 8 Resource Abuse). The rest have at least MODERATE coverage.

### Key Improvement vs Initial Analysis

| Task | Before | After | Reason |
|------|--------|-------|--------|
| Task 1 Injection | HIGH | EXCELLENT | Found 55K+70K HF datasets |
| Task 3 Exfil | VERY LOW | GOOD→MODERATE | 55K HF dataset has DATA_EXFILTRATION label; AgentShield, Agent Egress Bench |
| Task 6 Tool Poison | MEDIUM-LOW | STRONG | AgentDefense-Bench 35K+, MCPTox, MCP Injection |
| Task 7 Supply Chain | VERY LOW | MODERATE | OWASP Agentic Security, AgentDefense-Bench |
| Task 9 Output Leak | MEDIUM | EXCELLENT | 156K+41K PII datasets on HF |
| Task 10 Attack Chain | NONE | MODERATE | AgentTrust RiskChain, Multi-turn Jailbreak 6.9K |

---

## 4. Data Synthesis Strategy

### 4.1 Tier 1: CRITICAL — Tasks 4 & 8 (still need full synthetic)

**Task 4 (Reasoning Safety)**: No public dataset exists. Must use:
1. Template-based generation (already implemented in `scripts/synthesize.py`)
2. LLM-based generation (use GPT-4/Claude to generate diverse reasoning manipulation examples)
3. Augment from InjectLab's Output Manipulation tactics

**Task 8 (Resource Abuse)**: No public dataset exists. Must use:
1. Template-based generation (already implemented)
2. Tool call history sequence generation

### 4.2 Tier 2: MODERATE — Tasks 3, 5, 7, 10 (need targeted augmentation)

**Task 3**: Public data covers credential/PII exfil well. Gap: covert channels (base64, DNS, chunked transfer). Need ~100 synthetic covert channel samples.

**Task 5**: AgentPoison + MINJA cover KB poisoning. Gap: memory-specific poisoning and safe context edge cases. Need ~80 synthetic.

**Task 7**: OWASP + AgentDefense-Bench cover real scenarios. Gap: dedicated Skill/MCP config with malicious logic. Need ~40 synthetic.

**Task 10**: Multi-turn datasets provide conversation chains. Gap: labeled sequential tool-call attack chains. Need ~50 synthetic.

### 4.3 Tier 3: Data Quality Tasks — Deduplication & Adaptation

For tasks with ABUNDANT data (Tasks 1, 6, 9):
1. Sample strategically (don't use all 130K injection samples — cap at ~5K per task)
2. Deduplicate across sources
3. Adapt PII datasets to agent output context
4. Ensure safe/attack balance (1:1 ratio)

---

## 5. Updated Target Dataset Sizes

| Task | Public (sampled) | Synthetic | **Total** |
|------|-----------------|-----------|-----------|
| 1. Injection | 3,000 (from 130K) | 500 | **3,500** |
| 2. Command | 2,000 (from 3.7K) | 400 | **2,400** |
| 3. Exfiltration | 2,000 (from 11K) | 300 | **2,300** |
| 4. Reasoning | 10 | 800 | **810** |
| 5. Context | 300 (from 450) | 200 | **500** |
| 6. Tool Poison | 2,000 (from 36K) | 300 | **2,300** |
| 7. Supply Chain | 300 (from OWASP+ADB) | 200 | **500** |
| 8. Resource | 10 | 400 | **410** |
| 9. Output Leak | 3,000 (from 407K PII) | 300 | **3,300** |
| 10. Attack Chain | 2,000 (from 7.5K) | 300 | **2,300** |
| **Total** | **14,620** | **3,500** | **18,320** |

---

## 6. Download Script Sources

The `scripts/download.py` supports these sources:

### HuggingFace (via `datasets` library)
- `ffuuugor/agentdojo-dump`
- `ai-safety-institute/AgentHarm`
- `walledai/HarmBench`
- `Smooth-3/llm-prompt-injection-attacks`
- `MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT`
- `Ari-S-123/pii-detection-english-consolidated`
- `gorkem371/pii-intent-detection-multilingual`
- `ai4privacy/pii-masking-200k`

### GitHub (via git clone)
- `AI-secure/AgentPoison`
- `ethz-spylab/agentdojo`
- `centerforaisafety/HarmBench`
- `uiuc-kang-lab/InjecAgent`
- `ahow2004/injectlab`
- `arunsanna/AgentDefense-Bench`
- `getagentseal/agentseal`
- `invariantlabs-ai/mcp-injection-experiments`
- `doronp/agentshield-benchmark`
- `chenglin1112/AgentTrust`
- `evolutionstorm/owasp-agentic-security-dataset`

### URL Downloads (CyberSecEval)
- Meta PurpleLlama JSON files
