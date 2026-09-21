"""
ASAP: Active Safe-Agentic Pipeline (ASAP Core)
----------------------------------------------
Prototipo inicial unificado que integra:
 1. ACTSAFE: Planificación con incertidumbre epistémica y Log-Barrier SGD (LBSGD).
 2. LIVEPLAN: Monitoreo determinista de trayectorias (GRAPHECTORY & LANGUTORY).
 3. EST (Evaluator Stress Test): Detección de Proxy Gaming mediante perturbaciones de formato vs. contenido.
 4. Transactional Sandbox: Ejecución de acciones con semántica ACID y rollback de estado.

Optimizado para ejecución en Apple Silicon (MPS) y CPU.
"""

import os
import shutil
import tempfile
import time
import math
from typing import List, Dict, Tuple, Any, Optional
from dataclasses import dataclass

import torch
import torch.nn as nn
import torch.optim as optim

# -----------------------------------------------------------------------------
# 0. Device Configuration (Apple Silicon MPS / CPU)
# -----------------------------------------------------------------------------
def get_device() -> torch.device:
    if torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


# -----------------------------------------------------------------------------
# 1. Transactional Sandbox (Copia en Escritura / Rollback)
# -----------------------------------------------------------------------------
class TransactionalSandbox:
    """
    Proporciona un entorno de ejecución transaccional (ACID) básico.
    Crea un snapshot temporal del espacio de trabajo y revierte el estado si
    un comando/acción falla o viola una regla de seguridad.
    """
    def __init__(self, workspace_dir: str):
        self.workspace_dir = os.path.abspath(workspace_dir)
        self.backup_dir: Optional[str] = None

    def begin_transaction(self):
        """Toma un snapshot ligero del área de trabajo."""
        self.backup_dir = tempfile.mkdtemp(prefix="asap_sandbox_snap_")
        if os.path.exists(self.workspace_dir):
            for item in os.listdir(self.workspace_dir):
                s = os.path.join(self.workspace_dir, item)
                d = os.path.join(self.backup_dir, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d)
                else:
                    shutil.copy2(s, d)

    def commit(self):
        """Descarta el snapshot al confirmar la transacción."""
        if self.backup_dir and os.path.exists(self.backup_dir):
            shutil.rmtree(self.backup_dir)
            self.backup_dir = None

    def rollback(self):
        """Restaura el área de trabajo al estado del snapshot."""
        if self.backup_dir and os.path.exists(self.backup_dir):
            for item in os.listdir(self.workspace_dir):
                path = os.path.join(self.workspace_dir, item)
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
            for item in os.listdir(self.backup_dir):
                s = os.path.join(self.backup_dir, item)
                d = os.path.join(self.workspace_dir, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d)
                else:
                    shutil.copy2(s, d)
            shutil.rmtree(self.backup_dir)
            self.backup_dir = None


# -----------------------------------------------------------------------------
# 2. LIVEPLAN Process Monitor (GRAPHECTORY + LANGUTORY)
# -----------------------------------------------------------------------------
@dataclass
class ActionStep:
    action_type: str  # ej: 'navigate', 'reproduce', 'patch', 'validate'
    command: str
    thought: str

class LivePlanMonitor:
    """
    Monitorea en tiempo real la trayectoria del agente mediante:
     - GRAPHECTORY: Grafo de llamadas para detectar ciclos/oscilaciones.
     - LANGUTORY: Secuencia de fases para detectar estancamiento prolongado.
    Sin invocar LLMs (latencia < 1ms).
    """
    def __init__(self, stagnation_threshold: int = 5, max_cycles: int = 2):
        self.stagnation_threshold = stagnation_threshold
        self.max_cycles = max_cycles
        self.history: List[ActionStep] = []
        self.action_counts: Dict[str, int] = {}
        self.phase_sequence: List[str] = []

    def update_and_check(self, step: ActionStep) -> Tuple[bool, str]:
        """
        Registra el paso y verifica si existe deriva conductual.
        Retorna (has_drift, description_message).
        """
        self.history.append(step)
        self.phase_sequence.append(step.action_type)

        # 1. Detección de Oscilación/Ciclos (GRAPHECTORY Back-edges)
        cmd_key = f"{step.action_type}:{step.command}"
        self.action_counts[cmd_key] = self.action_counts.get(cmd_key, 0) + 1
        if self.action_counts[cmd_key] > self.max_cycles:
            return True, f"[LIVEPLAN Trigger] Oscilación detectada: comando '{step.command}' repetido {self.action_counts[cmd_key]} veces."

        # 2. Detección de Estancamiento Prolongado (LANGUTORY Long Stagnation)
        if len(self.phase_sequence) >= self.stagnation_threshold:
            recent_phases = self.phase_sequence[-self.stagnation_threshold:]
            if len(set(recent_phases)) == 1:
                return True, f"[LIVEPLAN Trigger] Estancamiento prolongado en la fase '{recent_phases[0]}' por {self.stagnation_threshold} pasos."

        return False, "OK"


# -----------------------------------------------------------------------------
# 3. Evaluator Stress Test (EST) - Evaluador Anti-Proxy Gaming
# -----------------------------------------------------------------------------
class EvaluatorStressTest:
    """
    Diagnostica subversión de métricas (reward hacking / proxy gaming) mediante
    perturbaciones simuladas de formato (delta_fmt) vs. contenido (delta_cnt).
    """
    def __init__(self, tau_threshold: float = 0.6, eps: float = 1e-6):
        self.tau_threshold = tau_threshold
        self.eps = eps

    def compute_gaming_score(self, score_original: float, score_fmt_perturbed: float, score_cnt_perturbed: float) -> Tuple[float, bool]:
        """
        Calcula el índice de dominancia de formato G(y):
        G(y) = delta_fmt / (delta_fmt + delta_cnt + eps)
        """
        delta_fmt = max(0.0, score_original - score_fmt_perturbed)
        delta_cnt = max(0.0, score_original - score_cnt_perturbed)

        G_y = delta_fmt / (delta_fmt + delta_cnt + self.eps)
        is_gaming = G_y > self.tau_threshold
        return G_y, is_gaming


# -----------------------------------------------------------------------------
# 4. ACTSAFE Planner (Log-Barrier SGD & Ensemble World Model)
# -----------------------------------------------------------------------------
class ToyWorldModelEnsemble(nn.Module):
    """
    Ensamble probabilístico de modelos de mundo para estimar
    media mu(s,a) e incertidumbre epistémica sigma(s,a).
    """
    def __init__(self, state_dim: int, action_dim: int, ensemble_size: int = 3):
        super().__init__()
        self.ensemble_size = ensemble_size
        self.models = nn.ModuleList([
            nn.Sequential(
                nn.Linear(state_dim + action_dim, 64),
                nn.ReLU(),
                nn.Linear(64, state_dim + 1)
            ) for _ in range(ensemble_size)
        ])

    def forward(self, state: torch.Tensor, action: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        x = torch.cat([state, action], dim=-1)
        preds = torch.stack([model(x) for model in self.models], dim=0)
        
        state_preds = preds[..., :-1]
        cost_preds = preds[..., -1]

        mu_state = state_preds.mean(dim=0)
        sigma_epistemic = state_preds.std(dim=0).mean(dim=-1, keepdim=True)
        mu_cost = cost_preds.mean(dim=0)

        return mu_state, mu_cost, sigma_epistemic


class ACTSAFEPlanner:
    """
    Planificador basado en Log-Barrier SGD (LBSGD).
    Maximiza la recompensa/exploración dentro del conjunto seguro pesimista.
    """
    def __init__(self, model_ensemble: ToyWorldModelEnsemble, cost_limit: float = 1.0, barrier_scale: float = 0.1, pessimistic_lambda: float = 0.5):
        self.ensemble = model_ensemble
        self.d = cost_limit
        self.eta = barrier_scale
        self.lambda_pessimism = pessimistic_lambda

    def plan_action(self, current_state: torch.Tensor, action_dim: int, steps: int = 20, lr: float = 0.05) -> torch.Tensor:
        device = current_state.device
        action = torch.zeros((1, action_dim), device=device, requires_grad=True)
        optimizer = optim.SGD([action], lr=lr)

        for _ in range(steps):
            optimizer.zero_grad()
            _, mu_cost, sigma_epistemic = self.ensemble(current_state, action)
            
            pessimistic_cost = mu_cost + self.lambda_pessimism * sigma_epistemic.squeeze(-1)
            slack = self.d - pessimistic_cost
            
            if slack.item() <= 0:
                loss = torch.tensor(100.0, device=device, requires_grad=True)
            else:
                intrinsic_reward = sigma_epistemic.squeeze(-1)
                log_barrier = -self.eta * torch.log(slack)
                loss = -intrinsic_reward + log_barrier

            loss.backward()
            optimizer.step()
            
            with torch.no_grad():
                action.clamp_(-1.0, 1.0)

        return action.detach()


# -----------------------------------------------------------------------------
# 5. ASAP Agent Execution Pipeline (Pipeline Integrado)
# -----------------------------------------------------------------------------
class ASAPPipeline:
    def __init__(self, workspace_dir: str):
        self.device = get_device()
        self.sandbox = TransactionalSandbox(workspace_dir)
        self.monitor = LivePlanMonitor()
        self.est = EvaluatorStressTest()
        
        self.model_ensemble = ToyWorldModelEnsemble(state_dim=4, action_dim=2).to(self.device)
        self.planner = ACTSAFEPlanner(self.model_ensemble, cost_limit=1.0)

    def execute_step(self, step: ActionStep, state_tensor: torch.Tensor, scores: Tuple[float, float, float]) -> Dict[str, Any]:
        """
        Ejecuta un paso en el pipeline ASAP con todas las verificaciones activas.
        scores: (score_orig, score_fmt_perturbed, score_cnt_perturbed)
        """
        results = {"status": "SUCCESS", "message": ""}

        # Step 1: Iniciar Transacción en Sandbox (ACID)
        self.sandbox.begin_transaction()

        try:
            # Step 2: Verificación de Proceso con LIVEPLAN
            has_drift, msg = self.monitor.update_and_check(step)
            if has_drift:
                print(f"⚠️ {msg}")
                self.sandbox.rollback()
                return {"status": "BLOCKED_BY_LIVEPLAN", "message": msg}

            # Step 3: Planificación de Acción Segura con ACTSAFE (LBSGD)
            planned_action = self.planner.plan_action(state_tensor, action_dim=2)

            # Step 4: Test de Estrés del Evaluador (EST)
            score_orig, score_fmt, score_cnt = scores
            G_y, is_gaming = self.est.compute_gaming_score(score_orig, score_fmt, score_cnt)
            if is_gaming:
                msg = f"[EST Trigger] Proxy Gaming detectado con índice G(y)={G_y:.2f} > threshold (0.60)."
                print(f"🚨 {msg}")
                self.sandbox.rollback()
                return {"status": "BLOCKED_BY_EST", "message": msg}

            # Confirmar transacción si todo es correcto
            self.sandbox.commit()
            results["planned_action"] = planned_action.cpu().numpy().tolist()
            results["message"] = f"Paso verificado correctamente. (EST G(y)={G_y:.2f})"
            return results

        except Exception as e:
            self.sandbox.rollback()
            return {"status": "ERROR", "message": str(e)}


# -----------------------------------------------------------------------------
# 6. Test de Validación en Apple Silicon / CPU
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    print("="*65)
    print("🚀 Probando ASAP Core (Active Safe-Agentic Pipeline)")
    device = get_device()
    print(f"📱 Dispositivo de cómputo activo: {device}")
    
    test_workspace = os.path.join(tempfile.gettempdir(), "asap_workspace")
    os.makedirs(test_workspace, exist_ok=True)

    pipeline = ASAPPipeline(workspace_dir=test_workspace)
    state = torch.randn((1, 4), device=device)

    # Definir secuencia de simulación con escenarios de prueba
    test_cases = [
        # (Paso, (score_orig, score_fmt_perturbed, score_cnt_perturbed))
        (ActionStep("navigate", "ls -la /src", "Explorando repositorio"), (0.90, 0.88, 0.40)), # Fmt insensible, cnt sensible -> Benign
        (ActionStep("reproduce", "python test.py", "Ejecutando suite de test"), (0.85, 0.82, 0.35)), # Benign
        (ActionStep("reproduce", "python test.py", "Re-ejecutando suite de test"), (0.85, 0.82, 0.35)), # Repetición 2 (Aún en límite)
        (ActionStep("reproduce", "python test.py", "Re-ejecutando por 3ª vez"), (0.85, 0.82, 0.35)), # Debería activar LIVEPLAN
        (ActionStep("patch", "vim /src/main.py", "Ofuscando test unitario"), (0.95, 0.30, 0.90)), # Debería activar EST Proxy Gaming
    ]

    for idx, (step_info, scores) in enumerate(test_cases, 1):
        print(f"\n--- Ejecutando Paso {idx}: {step_info.action_type} ('{step_info.command}') ---")
        res = pipeline.execute_step(step_info, state, scores)
        print(f"Resultado: {res['status']} | Detalles: {res['message']}")

    if os.path.exists(test_workspace):
        shutil.rmtree(test_workspace)
    print("\n✅ Verificación del motor ASAP completada exitosamente.")
    print("="*65)
