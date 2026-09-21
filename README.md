# 🛡️ ASAP: Active Safe-Agentic Pipeline

> **Agnostic runtime guardrails, behavioral monitoring, and transactional rollback framework for software engineering agents (LangChain, LangGraph, CrewAI, AutoGen, and custom ReAct loops).**

---

## 📌 What is ASAP?

When an AI agent is granted direct access to a terminal and file system, critical failure modes often emerge:
* **Infinite reasoning and execution loops:** The agent repeatedly issues failing commands without making progress.
* **Corrupted codebases and destructive operations:** Accidental or unconstrained system mutations (`rm -rf`, broken patches, or overwriting unintended files).
* **Prompt injection and credential exfiltration:** Indirect attacks reading and leaking `.env` files, SSH keys, or API tokens.
* **Proxy gaming and metric subversion (Reward Hacking):** The agent tampers with unit tests or assertions to force a "passing" status without solving the actual issue.

**ASAP** serves as an **in-line safety interceptor (middleware)** between the agent and the operating system. It monitors execution in real time, creates instantaneous atomic snapshots, and **automatically rolls back changes** if an anomaly, safety violation, or tool failure occurs.

---

## 🧱 ASAP Defense Architecture

```text
         [ AI Agent (e.g., LangChain / ReAct) ]
                            │ (proposes tool / bash action)
                            ▼
     ┌──────────────────────────────────────────────┐
     │ 1. CAITLYN (Tier-1 Intent Guard)             │ ──► Blocks credential exfiltration & prompt injections
     ├──────────────────────────────────────────────┤
     │ 2. LIVEPLAN (Deterministic Process Monitor)  │ ──► Halts oscillations (A -> B -> A) & phase stagnation
     ├──────────────────────────────────────────────┤
     │ 3. ACTSAFE (Pessimistic Safety Barrier)      │ ──► Evaluates uncertainty via PyTorch (Apple Silicon / CPU)
     ├──────────────────────────────────────────────┤
     │ 4. Transactional Sandbox (APFS CoW Snapshot) │ ──► Instantaneous Copy-on-Write snapshot (< 30ms)
     │    └── Isolated Execution (SubprocessRunner) │
     ├──────────────────────────────────────────────┤
     │ 5. EST (Evaluator Stress Test)               │ ──► AST mutations to expose fake test passes (Proxy Gaming)
     └──────────────────────────────────────────────┘
                            │
               ✅ Safe      │  ❌ Violation / Tool Error
                            ▼
                   [ Commit State ]        [ Atomic Rollback ]
```

---

## 🚀 Quickstart

### 1. Requirements & Installation

ASAP uses [`uv`](https://github.com/astral-sh/uv) for fast, deterministic dependency management, optimized for both macOS (Apple Silicon MPS) and Linux/Windows (CPU):

```bash
# Clone the repository and sync virtual environment
git clone <repo-url>
cd security_agents_workshoop
uv sync
```

### 2. Run the Test Suite

Run the full automated test suite (20 unit and integration tests):

```bash
uv run pytest -v
```

### 3. Run the Interactive LangChain Demo

Experience the guardrail in action as it simulates a LangChain agent encountering benign requests, injection attacks, tool errors, and reasoning loops:

```bash
uv run python examples/demo_langchain_agent.py
```

---

## 💡 How to Integrate with Your Agents

### Option A: LangChain / LangGraph (Plug-and-Play Callback)

Attach the `ASAPCallbackHandler` directly to your agent's execution configuration:

```python
from asap import ASAPPipeline

# 1. Initialize the pipeline for your target workspace
pipeline = ASAPPipeline(workspace_dir="./my_workspace")

# 2. Get the LangChain-compatible callback handler
asap_callback = pipeline.get_langchain_callback()

# 3. Attach to your LangChain agent executor
# agent_executor.invoke(
#     {"input": "Resolve issue #104"},
#     config={"callbacks": [asap_callback]}
# )
```

### Option B: Universal `@asap_guard` Decorator

Guard individual functions or tools across arbitrary frameworks (CrewAI, AutoGen, or custom tool loops):

```python
from asap import ASAPPipeline, asap_guard

pipeline = ASAPPipeline(workspace_dir="./my_workspace")

@asap_guard(pipeline, action_type="bash")
def run_terminal_command(command: str):
    # If the command violates policy, ASAP raises a PermissionError before execution.
    # If execution crashes or times out, all workspace mutations are cleanly rolled back.
    import subprocess
    return subprocess.check_output(command, shell=True).decode()
```

### Option C: Direct Guarded Bash Execution

```python
from asap import ASAPPipeline

pipeline = ASAPPipeline(workspace_dir="./my_workspace")

verdict, result = pipeline.execute_bash("pytest tests/")
if not verdict.is_safe:
    print(f"Action blocked: {verdict.message}")
else:
    print(f"Output:\n{result.stdout}")
```

---

## 📂 Project Structure

```text
security_agents_workshoop/
├── pyproject.toml              # Project dependencies (PyTorch, LangChain Core, PyTest)
├── asap/                       # Main ASAP framework package
│   ├── core/                  # Base types, dataclasses, and Apple Silicon MPS device configuration
│   ├── sandbox/               # ACID snapshots with APFS Copy-on-Write and isolated runner
│   ├── monitors/              # LIVEPLAN: GRAPHECTORY (trajectory cycles) and LANGUTORY (phases)
│   ├── evaluators/            # EST: AST mutator and Proxy Gaming score calculator G(y)
│   ├── planner/               # ACTSAFE: Epistemic uncertainty ensemble and LBSGD optimizer
│   ├── adapters/              # Integrations: LangChain callback, CAITLYN (Tier-1), and @asap_guard
│   └── pipeline.py            # Master orchestrator unifying all 5 security layers
├── examples/
│   └── demo_langchain_agent.py # End-to-end runnable demo protecting a LangChain agent
└── tests/                     # Comprehensive test suite (APFS, monitors, EST, ACTSAFE, pipeline)
```

---

## 👤 Author

* **Franco Ariel Demare**
* **Email:** [frandemare@gmail.com](mailto:frandemare@gmail.com)

---

## 📄 License

Developed for experimental security research and software engineering agent safety workshops (2026).
