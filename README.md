# 🛡️ ASAP: Active Safe-Agentic Pipeline

> **Capa de seguridad, control en tiempo de ejecución y rollback transaccional para agentes de software (LangChain, LangGraph, ReAct y agentes personalizados).**

---

## 📌 ¿Qué es ASAP?

Cuando un agente de Inteligencia Artificial tiene acceso a la terminal y al sistema de archivos, pueden ocurrir fallos críticos:
* **Entrar en bucles infinitos** repitiendo comandos que fallan una y otra vez.
* **Romper el código del repositorio** o ejecutar comandos destructivos accidentales (`rm -rf`, sobreescritura errónea).
* **Sufrir inyecciones de prompt** o intentos de exfiltrar credenciales (`.env`, llaves SSH).
* **Hacer trampa en las pruebas (Proxy Gaming)** modificando tests para que pasen artificialmente sin arreglar el bug.

**ASAP** actúa como un **interceptor de seguridad (middleware)** entre el agente y el sistema operativo. Supervisa cada paso en tiempo real, toma un punto de restauración ultrarrápido y, si algo sale mal o el agente se desvía, **revierte los cambios automáticamente**.

---

## 🧱 Las Capas de Protección de ASAP

```text
       [ Agente de IA (ej: LangChain) ]
                      │ (propone ejecutar una herramienta / bash)
                      ▼
   ┌──────────────────────────────────────────────┐
   │ 1. CAITLYN (Filtro Tier-1)                  │ ──► Bloquea exfiltración e inyecciones de prompt
   ├──────────────────────────────────────────────┤
   │ 2. LIVEPLAN (Detector de bucles)            │ ──► Corta oscilaciones (A -> B -> A) y estancamiento
   ├──────────────────────────────────────────────┤
   │ 3. ACTSAFE (Barrera de riesgo)              │ ──► Evalúa incertidumbre con PyTorch (Apple Silicon / CPU)
   ├──────────────────────────────────────────────┤
   │ 4. Transactional Sandbox (Snapshot APFS)     │ ──► Punto de restauración Copy-on-Write en < 30ms
   │    └── Ejecución real del comando / tool    │
   ├──────────────────────────────────────────────┤
   │ 5. EST (Anti-Proxy Gaming)                  │ ──► Mutaciones de código para detectar trampas en tests
   └──────────────────────────────────────────────┘
                      │
           ✅ Seguro  │  ❌ Violación / Error
                      ▼
             [ Commit Cambios ]        [ Rollback Automático ]
```

---

## 🚀 Inicio Rápido

### 1. Requisitos e Instalación

El proyecto utiliza [`uv`](https://github.com/astral-sh/uv) para la gestión de dependencias y optimización en macOS (Apple Silicon MPS) o Linux/Windows (CPU):

```bash
# Clonar el repositorio y sincronizar el entorno
git clone <url-del-repo>
cd security_agents_workshoop
uv sync
```

### 2. Ejecutar la Suite de Pruebas

Verifica que las 20 pruebas unitarias y de integración pasen correctamente:

```bash
uv run pytest -v
```

### 3. Probar la Demostración Interactiva

Ejecuta el script de ejemplo que simula un agente de LangChain intentando acciones benignas, ataques y bucles:

```bash
uv run python examples/demo_langchain_agent.py
```

---

## 💡 ¿Cómo Integrarlo con tus Agentes?

### Opción A: Con LangChain / LangGraph

Simplemente pasa el callback de ASAP al invocar tu agente:

```python
from asap import ASAPPipeline

# 1. Inicializar ASAP en el directorio de trabajo del agente
pipeline = ASAPPipeline(workspace_dir="./mi_proyecto")

# 2. Obtener el callback handler para LangChain
asap_callback = pipeline.get_langchain_callback()

# 3. Vincularlo a la ejecución de tu agente
# agent_executor.invoke({"input": "Resuelve el issue #42"}, config={"callbacks": [asap_callback]})
```

### Opción B: Decorador Universal `@asap_guard`

Protege cualquier función o herramienta en frameworks como CrewAI, AutoGen o código propio:

```python
from asap import ASAPPipeline, asap_guard

pipeline = ASAPPipeline(workspace_dir="./mi_proyecto")

@asap_guard(pipeline, action_type="bash")
def ejecutar_comando_terminal(comando: str):
    # Si la acción es peligrosa, ASAP lanza una excepción antes de ejecutarla.
    # Si la función falla, el espacio de trabajo se restaura automáticamente.
    import subprocess
    return subprocess.check_output(comando, shell=True).decode()
```

### Opción C: Ejecución Directa de Comandos Bash

```python
from asap import ASAPPipeline

pipeline = ASAPPipeline(workspace_dir="./mi_proyecto")

verdict, result = pipeline.execute_bash("pytest tests/")
if not verdict.is_safe:
    print(f"Comando bloqueado: {verdict.message}")
else:
    print(f"Salida: {result.stdout}")
```

---

## 📂 Estructura del Proyecto

```text
security_agents_workshoop/
├── pyproject.toml              # Dependencias (PyTorch, LangChain Core, PyTest)
├── asap/                       # Paquete principal de ASAP
│   ├── core/                  # Tipos base, dataclasses y detección de hardware (MPS/CPU)
│   ├── sandbox/               # Snapshots ACID con APFS Copy-on-Write y runner seguro
│   ├── monitors/              # LIVEPLAN: GRAPHECTORY (grafos de ciclos) y LANGUTORY (fases)
│   ├── evaluators/            # EST: Mutador AST y detector de Proxy Gaming
│   ├── planner/               # ACTSAFE: Ensamble de modelos de mundo y optimizador LBSGD
│   ├── adapters/              # Integraciones: LangChain, CAITLYN (Tier-1) y decorador @asap_guard
│   └── pipeline.py            # Orquestador central de las capas de seguridad
├── examples/
│   └── demo_langchain_agent.py # Ejemplo de uso protegiendo un agente LangChain
└── tests/                     # Suite de pruebas automatizadas
```

---

## 👤 Autor

* **Franco Ariel Demare**
* **Email:** [frandemare@gmail.com](mailto:frandemare@gmail.com)

---

## 📄 Licencia

Desarrollado para experimentación y talleres de seguridad en agentes de software (2026).

