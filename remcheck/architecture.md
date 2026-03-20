# architecture.md — remcheck v0.1.0
## System Architecture Document (Default Challenge — Part A)

---

## What remcheck is

remcheck is a command-line tool that accepts a finding record as JSON input,
selects the correct verification strategy based on the finding type, runs the
full test suite, and produces a tamper-evident evidence report.

```
remcheck --finding finding.json --output ./evidence/
```

The system is already partially implemented — the deserialization verifier
(`src/verify_deserial.py`) and its mock target (`src/mock_server.py`) form the
working core engine for the `insecure_deserialization` finding type.

---

## Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        remcheck CLI                         │
│              verify_deserial.py  --finding  --output        │
└───────────────────────────┬─────────────────────────────────┘
                            │  loads
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      finding.json                           │
│         { finding_id, type, target, payloads, ... }         │
└───────────────────────────┬─────────────────────────────────┘
                            │  type field
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Strategy Router                          │
│                                                             │
│   "insecure_deserialization" → DeserializationVerifier      │
│   "sql_injection"            → SQLInjectionVerifier         │
│   "ssrf_cloud_metadata"      → SSRFVerifier                 │
│   "jwt_algorithm_confusion"  → JWTVerifier                  │
│   [new type]                 → [new strategy, no core edit] │
└───────────────────────────┬─────────────────────────────────┘
                            │  runs
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Strategy (e.g. DeserializationVerifier)        │
│                                                             │
│   decode_payload()     → hex / base64 → raw bytes           │
│   run_with_retry()     → 3 runs per test (Bonus B)          │
│   detect_anomalies()   → behavioral / temporal / OOB        │
│   compute_verdict()    → DETERMINISTIC — AI cannot override │
│   get_ai_analysis()    → advisory only via Groq             │
└───────────────────────────┬─────────────────────────────────┘
                            │  fires payloads at
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Target Server                            │
│         mock_server.py (local) or real endpoint             │
└───────────────────────────┬─────────────────────────────────┘
                            │  responses feed back into
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Evidence Builder                         │
│                                                             │
│   build_report()  → structured JSON with all test results   │
│   SHA-256 hash    → computed before report_hash field added │
│   save_evidence() → evidence/FIND-XXXX_TIMESTAMP.json       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                    exit code 0 / 1 / 2
              (pipeline integration via shell)
```

---

## Q1 — Routing logic and adding new finding types

The `type` field in the finding JSON is the only routing key. The core engine
reads it and maps it to a strategy class. In the current implementation this is
a simple dictionary lookup:

```python
STRATEGY_REGISTRY = {
    "insecure_deserialization": DeserializationVerifier,
    "sql_injection":            SQLInjectionVerifier,
    "ssrf_cloud_metadata":      SSRFVerifier,
}

strategy = STRATEGY_REGISTRY.get(finding["type"])
if not strategy:
    print(f"[ERROR] Unknown finding type: {finding['type']}")
    sys.exit(2)
```

**Adding a new finding type without modifying the core engine:**

Every strategy implements the same interface:

```python
class BaseVerifier:
    def decode_payload(self, encoding, data) -> bytes
    def run_with_retry(self, ...) -> tuple[dict, dict]
    def detect_anomalies(self, result, expected, description) -> list[str]
    def compute_verdict(self, test_results) -> str
```

To add `graphql_introspection` as a new finding type, you would:

1. Create `src/strategies/graphql_verifier.py` implementing `BaseVerifier`
2. Add one line to `STRATEGY_REGISTRY`: `"graphql_introspection": GraphQLVerifier`
3. Create `finding_examples/graphql_example.json` with the correct `type` field
4. Touch zero other files — core engine, anomaly detector, report builder,
   and evidence store all remain unchanged

The routing is open for extension, closed for modification.

---

## Q2 — Evidence model and tamper-evidence

Every test run produces a structured JSON evidence report saved to `evidence/`.
The report contains the full finding ID, engine version, timestamp, all test
results with raw measurements, AI advisory analysis, and a final verdict.

**Tamper-evidence mechanism:**

The SHA-256 hash is computed over the complete JSON report serialized with
`sort_keys=True` — before the `report_hash` field itself is added. This means:

```python
report_json       = json.dumps(report, sort_keys=True)   # hash computed here
report["report_hash"] = "sha256:" + hashlib.sha256(      # field added after
    report_json.encode()
).hexdigest()
```

If any field in the report is modified after generation — verdict changed,
response time altered, anomaly removed — recomputing the hash will produce a
different value, immediately revealing the tampering.

**Auditability:** The report stores the full prompt sent to the AI, the raw AI
response, all retry run measurements (not just the worst case), and the exact
timestamp of generation. A third party can reproduce the verdict from the raw
measurements without needing to re-run the tool.

---

## Q3 — Anomaly detection generalization across finding types

Three signal classes are universal across all finding types:

| Signal Class | What it measures | Implementation |
|-------------|------------------|----------------|
| **Behavioral** | Status code deviation from expected | `status_code != expected_rejection_code` |
| **Temporal** | Response time exceeding baseline | `response_time > threshold` (5s for deserialization) |
| **Content** | Canary string present in response body | `canary_token in body_snippet.lower()` |

One signal class is finding-specific:

| Finding Type | Finding-Specific Signal |
|-------------|------------------------|
| insecure_deserialization | OOB callback to canary domain (confirms RCE without relying on response) |
| sql_injection | Boolean blind timing difference, error string in body |
| ssrf_cloud_metadata | OOB HTTP callback containing IAM credential patterns |
| jwt_algorithm_confusion | Accepted response with none/HS256 algorithm-confused token |

The `detect_anomalies()` function in the base interface handles the three
universal signals. Each strategy subclass can override or extend it to add
finding-specific signals without breaking the shared interface.

---

## Q4 — Handling inconsistent results across three runs 

This is directly implemented in `run_with_retry()`. Every test runs exactly 3
times. After all 3 runs the consistency engine evaluates:

```python
failures = len([r for r in results if is_fail(r)])

if failures == 0:        flag = "CONSISTENT_PASS"
elif failures == retries: flag = "CONSISTENT_FAIL"
else:                     flag = "INCONSISTENT - FLAG FOR REVIEW"
```

**Finalization logic:**

- `CONSISTENT_FAIL (3/3)` → `result = FAIL` → contributes to `REMEDIATION_FAILED`
- `CONSISTENT_PASS (0/3)` → `result = PASS` → contributes to `REMEDIATION_VERIFIED`
- `INCONSISTENT (1/3 or 2/3)` → `result = INCONCLUSIVE` → verdict becomes `INCONCLUSIVE`

An `INCONCLUSIVE` verdict means the tool detected something anomalous on some
runs but not all. It does not mark the finding as fixed or failed — it flags it
for manual analyst review. This prevents both false positives (fluke network
latency causing a single bad run) and false negatives (intermittent vulnerability
that only fires sometimes).

The consistency score is stored in the evidence report alongside all three
individual response times and status codes, giving the analyst the full picture.

---

## How the Default Challenge maps to our implementation

| Default Challenge requirement | Our implementation |
|------------------------------|-------------------|
| Accept any finding record as JSON input | `--finding finding.json` CLI argument |
| Select correct verification strategy | `STRATEGY_REGISTRY` dict keyed on `type` field |
| Run full test suite | `run_with_retry()` × number of payloads |
| Detect anomalies across three signal classes | `detect_anomalies()` — behavioral, temporal, content |
| Produce structured JSON evidence report | `build_report()` + `save_evidence()` |
| Tamper-evident report hash | SHA-256 over `sort_keys=True` JSON before hash field added |
| Exit codes for pipeline integration | 0 = VERIFIED, 1 = FAILED, 2 = INCONCLUSIVE |
| AI advisory layer | `get_ai_analysis()` via Groq — stored separately, never overrides verdict |

Currently implemented finding type: `insecure_deserialization`
Designed but not yet implemented: `sql_injection`, `ssrf_cloud_metadata`
