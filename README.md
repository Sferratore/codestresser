# CodeStresser

A static code analysis tool powered by **Machine Learning** that scans Python source code for security vulnerabilities, estimates their **severity** and **confidence level**, and generates a structured JSON report with suggested fixes.

---

## How It Works

CodeStresser operates in two phases: **static analysis** and **ML-based classification**.

### Phase 1 — Static Analysis

The `StaticAnalyzer` parses the target source code using two complementary techniques:

**AST (Abstract Syntax Tree) analysis** — The analyzer walks the parsed syntax tree using Python's `ast.NodeVisitor` pattern. Each node type (assignments, function calls, control structures, try blocks) triggers a dedicated `visit_*` method that inspects the code for security issues. The analyzer tracks *taint propagation*: variables assigned from untrusted sources (`input()`, `sys.argv`, `os.environ`, `request.GET/POST/args/form`) are marked as **tainted**, and taint flows through assignments, binary operations, and f-strings. When a tainted variable reaches a **sink** (`eval`, `exec`, `os.system`, `subprocess.*`, `cursor.execute`), the analyzer flags it.

Detected vulnerability types from AST analysis include:

- **Generally Dangerous Function Call** — direct use of dangerous sinks like `eval`, `exec`, `os.system`
- **Critical Sink Needing Try** — calls to functions that can fail at runtime (file I/O, JSON parsing, type conversions, SQL execution) used without a surrounding `try/except` block
- **Tainted Parameter Source** — tainted data flowing directly into a dangerous sink as an argument
- **Dangerous Dynamic SQL Query** — SQL queries built via string concatenation or f-strings with tainted input (SQL injection risk)
- **Unsafe Deserialization** — use of `pickle.load`, which can execute arbitrary code on untrusted data
- **Excessive Control Structure Nesting** — functions with more than 3 levels of nested `if`/`for`/`while` blocks, indicating high complexity

**CFG (Control Flow Graph) analysis** — Using the `radon` library, the analyzer builds a control flow graph and scans for **TOCTOU (Time-Of-Check to Time-Of-Use)** vulnerabilities. It detects patterns where a file existence/permission check (`os.path.exists`, `os.access`, `pathlib.Path.exists`, etc.) is followed by a file operation (`open`, `os.remove`, `shutil.move`, etc.) on the same resource — a race condition that attackers can exploit.

### Phase 2 — ML Classification

Each detected vulnerability is converted into a **13-dimensional feature vector** (counts of each vulnerability type) and fed into two pre-trained models:

- **Severity model** — a `RandomForestClassifier` that predicts a severity label: `Low`, `Medium`, `High`, or `Critical`
- **Confidence model** — a `RandomForestRegressor` that outputs a confidence score between 0 and 1

Both models are trained on a labeled dataset of 120 samples (`training_data/training_data.csv`) with features normalized via `StandardScaler`. The training pipeline splits the data 75/25 for train/test and reports accuracy (severity) and R² score (confidence).

### Output

The final output is a JSON report (`report/report.json`) where each entry contains:

```json
{
  "problematic_function": "cursor.execute",
  "problematic_variable": "--",
  "file": "code/code.py",
  "line": 14,
  "issue": "Dangerous Dynamic SQL Query",
  "severity": "High",
  "confidence": 0.85,
  "suggested_fix": "Use parameterized queries instead of string concatenation."
}
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.10+ |
| Parsing | `ast` (standard library) |
| Complexity analysis | `radon` |
| ML models | scikit-learn (Random Forest) |
| Serialization | joblib |
| Data handling | pandas |

---

## Project Structure

### `prod/` — Core application

| File | Role |
|---|---|
| `main.py` | Entry point — trains models, then generates the report |
| `StaticAnalyzer.py` | AST/CFG vulnerability detection engine |
| `VulnerabilityModelTrainingPipeline.py` | ML training pipeline (severity + confidence) |
| `VulnerabilityReportGenerator.py` | Orchestrates analysis and builds the JSON report |
| `CodeReader.py` | Reads source files by extension; supports multi-language via config |
| `support_functions.py` | Converts vulnerability lists into feature vectors for the models |

### `model/` — Pre-trained artifacts

| File | Role |
|---|---|
| `severity_model.pkl` | Random Forest classifier — predicts Low / Medium / High / Critical |
| `confidence_model.pkl` | Random Forest regressor — outputs a 0–1 confidence score |
| `scaler.pkl` | StandardScaler fitted on training data |

### Other directories

| Path | Role |
|---|---|
| `training_data/training_data.csv` | Labeled dataset (120 samples, 13 features) |
| `code/` | Sample vulnerable Python files used for testing the analyzer |
| `report/report.json` | Generated analysis report (output) |
| `tests/` | Unit tests for all modules |
| `CodeStresser PPT.pptx` | Project presentation |

---

## Installation

**Prerequisites:** Python >= 3.10

```bash
git clone https://github.com//CodeStresser.git
cd CodeStresser
```

Create a virtual environment (recommended):

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
```

Install dependencies:

```bash
pip install pandas scikit-learn joblib radon
```

---

## Usage

### Quick Start — Train + Analyze in One Step

```bash
python prod/main.py
```

This will train both ML models on the dataset and then analyze all `.py` files in the `code/` directory, saving the report to `report/report.json`.

### Train Models Only

To retrain the models (e.g. after updating `training_data.csv`):

```bash
python prod/VulnerabilityModelTrainingPipeline.py
```

Output:

```
[*] Loading data...
[*] Preprocessing...
[*] Training models...
[+] Severity model accuracy: 0.XX
[+] Confidence model R² score: 0.XX
[*] Saving models and scaler...
```

The trained models are saved to `model/`.

### Analyze Your Own Code

Place the Python files you want to scan inside the `code/` directory (or any directory), then run:

```bash
python prod/main.py
```

The tool recursively scans all `.py` files in the target directory. To analyze a different path, edit the `CODE_DIR` variable in `main.py`.

### Read the Report

Open `report/report.json`. Each entry tells you the file, line number, issue type, predicted severity, confidence score, and a suggested fix.

### Run Tests

```bash
python -m pytest tests/
```

---

## Detected Vulnerability Types

| Vulnerability | Detection Method | Example Trigger |
|---|---|---|
| Dangerous function call | AST — sink detection | `eval(user_input)` |
| Critical sink without try/except | AST — try-block tracking | `open(path)` outside try |
| Tainted parameter in sink | AST — taint propagation | `exec(input())` |
| SQL injection | AST — tainted dynamic queries | `cursor.execute("SELECT * " + name)` |
| Unsafe deserialization | AST — pickle detection | `pickle.load(file)` |
| Excessive nesting | AST — control depth tracking | 4+ nested `if`/`for`/`while` |
| TOCTOU race condition | CFG — check-then-use pattern | `os.path.exists()` → `open()` |

---

## Author

[Sferratore](https://github.com/Sferratore)
