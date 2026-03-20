#!/usr/bin/env python3
# remcheck.py - Automated Remediation Checker
# Default Challenge — supports sql_injection, ssrf_cloud_metadata, insecure_deserialization
# Usage: python3 src/remcheck.py --finding finding_examples/sqli_example.json --output ./evidence

import json
import sys
import time
import uuid
import hashlib
import base64
import argparse
import os
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("[ERROR] requests not found. Run: pip3 install requests")
    sys.exit(1)

ENGINE_VERSION = "0.1.0"

# ─────────────────────────────────────────
# ANSI colors with fallback
# ─────────────────────────────────────────
def supports_color():
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

GREEN  = "\033[92m" if supports_color() else ""
RED    = "\033[91m" if supports_color() else ""
YELLOW = "\033[93m" if supports_color() else ""
BOLD   = "\033[1m"  if supports_color() else ""
RESET  = "\033[0m"  if supports_color() else ""

# ─────────────────────────────────────────
# STRATEGY ROUTER
# To add a new finding type: add one entry here. Nothing else changes.
# ─────────────────────────────────────────
def get_strategy(finding_type):
    registry = {
        "sql_injection"           : run_sqli_suite,
        "ssrf_cloud_metadata"     : run_ssrf_suite,
        "insecure_deserialization": run_deserial_suite,
    }
    return registry.get(finding_type)

# ─────────────────────────────────────────
# SHARED UTILITIES
# ─────────────────────────────────────────
def decode_payload(encoding, data):
    if encoding == "hex":
        return bytes.fromhex(data)
    elif encoding == "base64":
        return base64.b64decode(data)
    else:
        raise ValueError(f"Unknown encoding: {encoding}")

def hash_body(body_text):
    return hashlib.sha256(body_text.encode()).hexdigest()[:16]

def check_oob(oob_poll_url):
    if not oob_poll_url or "yourplatform.com" in oob_poll_url:
        return False, "OOB polling skipped (demo mode)"
    try:
        r = requests.get(oob_poll_url, timeout=10)
        hit = r.status_code == 200 and (
            "hit" in r.text.lower() or "callback" in r.text.lower()
        )
        return hit, r.text
    except Exception as e:
        return False, str(e)

# ─────────────────────────────────────────
# SHARED ANOMALY DETECTOR
# Universal signals: behavioral, temporal, content
# Finding-specific signals handled per strategy
# ─────────────────────────────────────────
def detect_anomalies(status_code, response_time, body,
                     baseline_status, baseline_p95,
                     canary=None, oob_hit=False, is_control=False):
    anomalies = []

    # Behavioral — skip for control tests
    if not is_control and status_code != baseline_status and status_code != 0:
        anomalies.append(
            f"BEHAVIORAL: status {status_code} (expected {baseline_status})"
        )

    # Temporal — response time > 2x baseline p95
    if baseline_p95 and response_time > baseline_p95 * 2:
        anomalies.append(
            f"TEMPORAL: {response_time}s exceeds 2x baseline p95 ({baseline_p95}s)"
        )

    # Content — canary string in body
    if canary and canary.lower() in body.lower():
        anomalies.append(f"CONTENT: canary string '{canary}' found in response body")

    # OOB callback
    if oob_hit:
        anomalies.append("OOB CALLBACK: canary domain hit — code execution confirmed")

    return anomalies

# ─────────────────────────────────────────
# BONUS B — Retry + Consistency Engine
# ─────────────────────────────────────────
def run_with_retry(request_fn, retries=3):
    results = []
    for i in range(retries):
        r = request_fn()
        results.append(r)
        if i < retries - 1:
            time.sleep(1)

    failures = [r for r in results if r.get("is_fail", False)]
    count    = len(failures)
    score    = f"{count}/{retries}"

    if count == 0:        flag = "CONSISTENT_PASS"
    elif count == retries: flag = "CONSISTENT_FAIL"
    else:                  flag = "INCONSISTENT - FLAG FOR REVIEW"

    best = failures[0] if failures else results[0]
    best["consistency"] = {
        "runs": retries, "failures": count, "score": score, "flag": flag,
        "all_times":   [r["response_time"] for r in results],
        "all_statuses":[r["status_code"]   for r in results]
    }
    return best

# ─────────────────────────────────────────
# VERDICT
# ─────────────────────────────────────────
def compute_verdict(test_results):
    if any(t["result"] == "FAIL" for t in test_results):
        return "REMEDIATION_FAILED"
    if any("INCONSISTENT" in t.get("consistency", {}).get("flag", "")
           for t in test_results):
        return "INCONCLUSIVE"
    return "REMEDIATION_VERIFIED"

# ─────────────────────────────────────────
# REPORT BUILDER
# ─────────────────────────────────────────
def build_report(finding, test_results, verdict, strategy_name):
    report = {
        "report_id"     : str(uuid.uuid4()),
        "finding_id"    : finding["finding_id"],
        "generated_at"  : datetime.now(timezone.utc).isoformat(),
        "engine_version": ENGINE_VERSION,
        "strategy"      : strategy_name,
        "verdict"       : verdict,
        "test_results"  : test_results,
        "ai_analysis"   : None,
        "summary": {
            "total"       : len(test_results),
            "passed"      : sum(1 for t in test_results if t["result"] == "PASS"),
            "failed"      : sum(1 for t in test_results if t["result"] == "FAIL"),
            "inconclusive": sum(1 for t in test_results if t["result"] == "INCONCLUSIVE")
        }
    }
    report_json        = json.dumps(report, sort_keys=True)
    report["report_hash"] = "sha256:" + hashlib.sha256(
        report_json.encode()
    ).hexdigest()
    return report

def save_evidence(report, output_dir, finding_id):
    os.makedirs(output_dir, exist_ok=True)
    ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filepath = os.path.join(output_dir, f"{finding_id}_{ts}.json")
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)
    return filepath

# ─────────────────────────────────────────
# AI RESULT ANALYZER (Part C — Option 2)
# Advisory only — never overrides verdict
# ─────────────────────────────────────────
def get_ai_analysis(test_results, verdict, finding_id, finding_type):
    api_key = os.environ.get("GROQ_API_KEY", "")
    if not api_key:
        return {"status": "skipped", "reason": "GROQ_API_KEY not set", "analysis": None}

    lines = []
    for t in test_results:
        a = "; ".join(t.get("anomalies", [])) or "none"
        c = t.get("consistency", {})
        lines.append(
            f"- {t['test_id']} ({t.get('category','')}) "
            f"status={t['status_code']} time={t['response_time']}s "
            f"result={t['result']} consistency={c.get('score','?')} "
            f"({c.get('flag','?')}) anomalies=[{a}]"
        )

    prompt = (
        f"You are a security analysis assistant reviewing automated remediation "
        f"verification results.\n\n"
        f"Finding ID: {finding_id}\n"
        f"Vulnerability type: {finding_type}\n"
        f"Deterministic verdict: {verdict}\n\n"
        f"Test results:\n" + "\n".join(lines) + "\n\n"
        f"Provide advisory analysis covering:\n"
        f"1. Whether the fix appears complete, partial, or bypassed\n"
        f"2. Which test results are most significant and why\n"
        f"3. Any residual risk even if REMEDIATION_VERIFIED\n"
        f"4. Recommended next steps\n\n"
        f"Important: advisory only. Do not override the deterministic verdict. "
        f"Under 200 words."
    )

    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}",
                     "Content-Type": "application/json"},
            json={
                "model": "llama-3.1-8b-instant",
                "messages": [
                    {"role": "system",
                     "content": "You are a security analysis assistant. Be concise."},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 400, "temperature": 0.3
            },
            timeout=30
        )
        r.raise_for_status()
        analysis = r.json()["choices"][0]["message"]["content"]
        return {
            "status": "completed", "model": "llama-3.1-8b-instant via Groq",
            "prompt": prompt, "analysis": analysis,
            "advisory_only": True,
            "note": "This analysis does not override the deterministic verdict"
        }
    except Exception as e:
        return {"status": "failed", "reason": str(e), "analysis": None}

# ─────────────────────────────────────────
# CLI PRINTER
# ─────────────────────────────────────────
def print_test(tc, quiet, verbose):
    if quiet:
        return
    result = tc["result"]
    color  = GREEN if result == "PASS" else RED if result == "FAIL" else YELLOW
    c      = tc.get("consistency", {})
    oob    = "YES" if tc.get("oob_hit") else "NO"

    print(f"  {tc['test_id']:<8} {tc.get('category',''):<25} "
          f"{color}{result}{RESET} [{tc['response_time']}s]")

    if tc.get("anomalies") and not quiet:
        for a in tc["anomalies"]:
            print(f"           {RED}⚠ {a}{RESET}")

    if c:
        flag_color = YELLOW if "INCONSISTENT" in c.get("flag","") else ""
        print(f"           Consistency: {c.get('score')} "
              f"— {flag_color}{c.get('flag')}{RESET}")

    if verbose:
        print(f"           Status: {tc['status_code']} | OOB: {oob}")
        print(f"           Body:   {tc.get('body_snippet','')[:200]}")

# ═══════════════════════════════════════════════════════════════
# STRATEGY 1 — SQL INJECTION
# ═══════════════════════════════════════════════════════════════
SQLI_PAYLOADS = [
    {"id": "TC-01", "category": "classic_injection",
     "payload": "' OR '1'='1", "note": "basic OR bypass"},
    {"id": "TC-02", "category": "union_based",
     "payload": "' UNION SELECT NULL,NULL--", "note": "union enumeration"},
    {"id": "TC-03", "category": "boolean_blind_true",
     "payload": "' AND 1=1--", "note": "always true condition"},
    {"id": "TC-04", "category": "boolean_blind_false",
     "payload": "' AND 1=2--", "note": "always false condition"},
    {"id": "TC-05", "category": "time_based",
     "payload": "'; WAITFOR DELAY '0:0:5'--", "note": "5s sleep (MSSQL)"},
    {"id": "TC-06", "category": "encoding_bypass",
     "payload": "%27%20OR%20%271%27%3D%271", "note": "URL-encoded quote"},
    {"id": "TC-07", "category": "second_order",
     "payload": "admin'--", "note": "stored injection attempt"},
    {"id": "TC-08", "category": "error_based",
     "payload": "' AND extractvalue(1,concat(0x7e,version()))--",
     "note": "MySQL error extraction"},
]

def run_sqli_suite(finding, args, quiet, verbose):
    base_url   = finding["base_url"]
    endpoint   = finding["endpoint"]
    parameter  = finding["parameter"]
    baseline   = finding.get("baseline", {})
    auth       = finding.get("auth", {})
    db_engine  = finding.get("metadata", {}).get("db_engine", "mysql")

    # Build full URL — endpoint is like "POST /api/v1/login"
    method, path = endpoint.split(" ", 1)
    url = base_url.rstrip("/") + path

    headers = {"Content-Type": "application/json"}
    if auth.get("type") == "bearer":
        headers["Authorization"] = f"Bearer {auth.get('token','')}"

    baseline_status = baseline.get("status_code", 200)
    baseline_p95    = baseline.get("response_time_p95", 1.0)
    baseline_hash   = baseline.get("response_hash", "")

    test_results = []

    for p in SQLI_PAYLOADS:
        def make_request(payload=p["payload"]):
            start = time.time()
            try:
                body_data = json.dumps({parameter: payload})
                resp = requests.post(url, data=body_data,
                                     headers=headers, timeout=15)
                elapsed = round(time.time() - start, 3)
                body    = resp.text
                return {
                    "status_code"  : resp.status_code,
                    "response_time": elapsed,
                    "body_snippet" : body[:200],
                    "response_hash": hash_body(body),
                    "oob_hit"      : False,
                    "error"        : None,
                    "is_fail"      : (
                        resp.status_code != baseline_status or
                        elapsed > baseline_p95 * 2
                    )
                }
            except requests.RequestException as e:
                elapsed = round(time.time() - start, 3)
                return {
                    "status_code": 0, "response_time": elapsed,
                    "body_snippet": f"FAILED: {e}", "response_hash": "",
                    "oob_hit": False, "error": str(e), "is_fail": True
                }

        result = run_with_retry(make_request, retries=args.retries)

        anomalies = detect_anomalies(
            status_code    = result["status_code"],
            response_time  = result["response_time"],
            body           = result["body_snippet"],
            baseline_status= baseline_status,
            baseline_p95   = baseline_p95,
            canary         = "sql",
        )

        # Time-based: if time_based payload and response > 4s, that's suspicious
        if p["category"] == "time_based" and result["response_time"] > 4.0:
            anomalies.append(
                f"TEMPORAL: time-based payload caused {result['response_time']}s delay "
                f"— time-based blind SQLi likely still working"
            )

        consistency = result.get("consistency", {})
        if "INCONSISTENT" in consistency.get("flag", ""):
            tc_result = "INCONCLUSIVE"
        elif anomalies:
            tc_result = "FAIL"
        else:
            tc_result = "PASS"

        tc = {
            "test_id"      : p["id"],
            "category"     : p["category"],
            "payload"      : p["payload"],
            "status_code"  : result["status_code"],
            "response_time": result["response_time"],
            "response_hash": result["response_hash"],
            "body_snippet" : result["body_snippet"],
            "oob_hit"      : result["oob_hit"],
            "anomalies"    : anomalies,
            "result"       : tc_result,
            "consistency"  : consistency
        }
        test_results.append(tc)
        print_test(tc, quiet, verbose)

    return test_results, "SQLInjectionVerifier"

# ═══════════════════════════════════════════════════════════════
# STRATEGY 2 — SSRF via Cloud Metadata
# ═══════════════════════════════════════════════════════════════
SSRF_PAYLOADS = [
    {"id": "TC-01", "category": "direct_ip",
     "url": "http://169.254.169.254/latest/meta-data/",
     "note": "direct IMDS IPv4"},
    {"id": "TC-02", "category": "decimal_encoding",
     "url": "http://2852039166/latest/meta-data/",
     "note": "decimal-encoded IP"},
    {"id": "TC-03", "category": "hex_encoding",
     "url": "http://0xa9fea9fe/latest/meta-data/",
     "note": "hex-encoded IP"},
    {"id": "TC-04", "category": "octal_encoding",
     "url": "http://0251.0376.0251.0376/latest/meta-data/",
     "note": "octal-encoded IP"},
    {"id": "TC-05", "category": "ipv6_mapped",
     "url": "http://[::ffff:169.254.169.254]/latest/meta-data/",
     "note": "IPv6-mapped IPv4"},
    {"id": "TC-06", "category": "iam_credentials",
     "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "note": "IAM credential path"},
    {"id": "TC-07", "category": "redirect_chain",
     "url": "http://169.254.169.254/latest/meta-data/",
     "note": "redirect chain simulation"},
    {"id": "TC-08", "category": "ipv6_imds",
     "url": "http://[fd00:ec2::254]/latest/meta-data/",
     "note": "IPv6 IMDS endpoint"},
]

SSRF_CANARY_STRINGS = [
    "AccessKeyId", "SecretAccessKey", "Token",
    "ami-id", "instance-id", "iam"
]

def run_ssrf_suite(finding, args, quiet, verbose):
    base_url  = finding["base_url"]
    endpoint  = finding["endpoint"]
    parameter = finding["parameter"]
    baseline  = finding.get("baseline", {})
    auth      = finding.get("auth", {})

    method, path = endpoint.split(" ", 1)
    url = base_url.rstrip("/") + path

    headers = {"Content-Type": "application/json"}
    if auth.get("type") == "bearer":
        headers["Authorization"] = f"Bearer {auth.get('token','')}"

    baseline_status = baseline.get("status_code", 400)
    baseline_p95    = baseline.get("response_time_p95", 1.0)
    oob_poll_url    = finding.get("oob_poll_url", "")

    test_results = []

    for p in SSRF_PAYLOADS:
        def make_request(ssrf_url=p["url"]):
            start = time.time()
            try:
                body_data = json.dumps({parameter: ssrf_url})
                resp = requests.post(url, data=body_data,
                                     headers=headers, timeout=15)
                elapsed = round(time.time() - start, 3)
                body    = resp.text

                # Check for credential canary strings in body
                canary_hit = any(c in body for c in SSRF_CANARY_STRINGS)

                time.sleep(2)
                oob_hit, _ = check_oob(oob_poll_url)

                return {
                    "status_code"  : resp.status_code,
                    "response_time": elapsed,
                    "body_snippet" : body[:200],
                    "response_hash": hash_body(body),
                    "oob_hit"      : oob_hit,
                    "canary_hit"   : canary_hit,
                    "error"        : None,
                    "is_fail"      : (
                        resp.status_code != baseline_status or
                        canary_hit or oob_hit
                    )
                }
            except requests.RequestException as e:
                elapsed = round(time.time() - start, 3)
                return {
                    "status_code": 0, "response_time": elapsed,
                    "body_snippet": f"FAILED: {e}", "response_hash": "",
                    "oob_hit": False, "canary_hit": False,
                    "error": str(e), "is_fail": True
                }

        result = run_with_retry(make_request, retries=args.retries)

        anomalies = detect_anomalies(
            status_code    = result["status_code"],
            response_time  = result["response_time"],
            body           = result["body_snippet"],
            baseline_status= baseline_status,
            baseline_p95   = baseline_p95,
            oob_hit        = result["oob_hit"],
        )

        # SSRF-specific: credential canary strings in body
        if result.get("canary_hit"):
            anomalies.append(
                "CONTENT: AWS credential canary string found in response — "
                "SSRF reaching IMDS and reflecting credentials"
            )

        consistency = result.get("consistency", {})
        if "INCONSISTENT" in consistency.get("flag", ""):
            tc_result = "INCONCLUSIVE"
        elif anomalies:
            tc_result = "FAIL"
        else:
            tc_result = "PASS"

        tc = {
            "test_id"      : p["id"],
            "category"     : p["category"],
            "payload"      : p["url"],
            "status_code"  : result["status_code"],
            "response_time": result["response_time"],
            "response_hash": result["response_hash"],
            "body_snippet" : result["body_snippet"],
            "oob_hit"      : result["oob_hit"],
            "anomalies"    : anomalies,
            "result"       : tc_result,
            "consistency"  : consistency
        }
        test_results.append(tc)
        print_test(tc, quiet, verbose)

    return test_results, "SSRFVerifier"

# ═══════════════════════════════════════════════════════════════
# STRATEGY 3 — INSECURE DESERIALIZATION
# (same logic as verify_deserial.py, integrated here)
# ═══════════════════════════════════════════════════════════════
def run_deserial_suite(finding, args, quiet, verbose):
    target        = finding["target"]
    content_type  = finding["content_type"]
    expected_code = finding["expected_rejection_code"]
    oob_poll_url  = finding.get("oob_poll_url", "")
    payloads      = finding["payloads"]

    test_results = []

    for p in payloads:
        try:
            raw_bytes = decode_payload(p["encoding"], p["data"])
        except ValueError as e:
            print(f"{RED}[SKIP] {p['id']}: {e}{RESET}")
            continue

        is_control = "control" in p["description"].lower() or \
                     "benign"  in p["description"].lower()

        def make_request(rb=raw_bytes, ct=content_type, ic=is_control):
            start = time.time()
            try:
                resp    = requests.post(target, data=rb,
                                        headers={"Content-Type": ct}, timeout=15)
                elapsed = round(time.time() - start, 3)
                body    = resp.text
                time.sleep(2)
                oob_hit, _ = check_oob(oob_poll_url)

                fail = (
                    (not ic and resp.status_code != expected_code
                     and resp.status_code != 0) or
                    elapsed > 5.0 or oob_hit
                )
                return {
                    "status_code"  : resp.status_code,
                    "response_time": elapsed,
                    "body_snippet" : body[:200],
                    "response_hash": hash_body(body),
                    "oob_hit"      : oob_hit,
                    "error"        : None,
                    "is_fail"      : fail
                }
            except requests.RequestException as e:
                elapsed = round(time.time() - start, 3)
                return {
                    "status_code": 0, "response_time": elapsed,
                    "body_snippet": f"FAILED: {e}", "response_hash": "",
                    "oob_hit": False, "error": str(e), "is_fail": True
                }

        result = run_with_retry(make_request, retries=args.retries)

        anomalies = []
        if not is_control and result["status_code"] != expected_code \
                and result["status_code"] != 0:
            anomalies.append(
                f"BEHAVIORAL: status {result['status_code']} "
                f"(expected {expected_code})"
            )
        if result["response_time"] > 5.0:
            anomalies.append(
                f"TEMPORAL: {result['response_time']}s exceeds 5s threshold"
            )
        if result["oob_hit"]:
            anomalies.append("OOB CALLBACK: code execution confirmed")
        if "find0139" in result["body_snippet"].lower():
            anomalies.append("CONTENT: canary string in response body")

        consistency = result.get("consistency", {})
        if "INCONSISTENT" in consistency.get("flag", ""):
            tc_result = "INCONCLUSIVE"
        elif anomalies:
            tc_result = "FAIL"
        else:
            tc_result = "PASS"

        tc = {
            "test_id"      : p["id"],
            "category"     : p.get("description", ""),
            "payload"      : p["data"][:32] + "...",
            "status_code"  : result["status_code"],
            "response_time": result["response_time"],
            "response_hash": result["response_hash"],
            "body_snippet" : result["body_snippet"],
            "oob_hit"      : result["oob_hit"],
            "anomalies"    : anomalies,
            "result"       : tc_result,
            "consistency"  : consistency
        }
        test_results.append(tc)
        print_test(tc, quiet, verbose)

    return test_results, "DeserializationVerifier"

# ─────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="remcheck v0.1.0 — Automated Remediation Checker"
    )
    parser.add_argument("--finding", required=True,
                        help="Path to finding JSON file")
    parser.add_argument("--output",  default="./evidence",
                        help="Output directory for evidence reports")
    parser.add_argument("--quiet",   action="store_true",
                        help="Show only final verdict")
    parser.add_argument("--verbose", action="store_true",
                        help="Show full request/response per test")
    parser.add_argument("--retries", type=int, default=3,
                        help="Retry count per test (Bonus B)")
    args = parser.parse_args()

    # Load finding
    try:
        with open(args.finding) as f:
            finding = json.load(f)
    except FileNotFoundError:
        print(f"{RED}[ERROR] File not found: {args.finding}{RESET}")
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"{RED}[ERROR] Invalid JSON: {e}{RESET}")
        sys.exit(2)

    finding_type = finding.get("type", "unknown")
    finding_id   = finding.get("finding_id", "UNKNOWN")

    # Route to strategy
    strategy_fn = get_strategy(finding_type)
    if not strategy_fn:
        print(f"{RED}[ERROR] Unknown finding type: '{finding_type}'{RESET}")
        print(f"  Supported types: sql_injection, ssrf_cloud_metadata, "
              f"insecure_deserialization")
        sys.exit(2)

    # Header
    if not args.quiet:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        target = finding.get("base_url", finding.get("target", ""))
        baseline = finding.get("baseline", {})
        print(f"\n{BOLD}remcheck v{ENGINE_VERSION}{RESET}")
        print(f"  Loading finding : {finding_id} ({finding_type})")
        print(f"  Target          : {target}")
        print(f"  Strategy        : {finding_type} verifier")
        if baseline:
            print(f"  Baseline        : status={baseline.get('status_code')} "
                  f"p95={baseline.get('response_time_p95')}s")
        print(f"  Retries         : {args.retries} per test (Bonus B)\n")
        payload_count = len(finding.get("payloads",
                            SQLI_PAYLOADS if finding_type == "sql_injection"
                            else SSRF_PAYLOADS))
        print(f"  Running test suite ({payload_count} tests)...\n")

    # Run strategy
    test_results, strategy_name = strategy_fn(finding, args,
                                               args.quiet, args.verbose)

    # Verdict
    verdict       = compute_verdict(test_results)
    verdict_color = (GREEN if verdict == "REMEDIATION_VERIFIED" else
                     RED   if verdict == "REMEDIATION_FAILED"   else YELLOW)
    failed = sum(1 for t in test_results if t["result"] == "FAIL")

    # AI analysis
    ai = get_ai_analysis(test_results, verdict, finding_id, finding_type)

    # Build + save report
    report = build_report(finding, test_results, verdict, strategy_name)
    report["ai_analysis"] = ai
    filepath = save_evidence(report, args.output, finding_id)

    # Footer
    if not args.quiet:
        print(f"\n  {BOLD}Verdict    : "
              f"{verdict_color}{verdict}{RESET}")
        print(f"  Evidence   : {filepath}")
        print(f"  Report hash: {report['report_hash'][:40]}...")
        print(f"  Failed     : {failed}/{len(test_results)}\n")
    else:
        print(f"{verdict_color}{verdict}{RESET}")

    sys.exit({"REMEDIATION_VERIFIED": 0,
               "REMEDIATION_FAILED": 1,
               "INCONCLUSIVE": 2}.get(verdict, 2))

if __name__ == "__main__":
    main()
