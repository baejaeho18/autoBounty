#!/usr/bin/env python3
"""
findings.json에 발견사항 추가 (중복 제거 포함)
"""
import json, hashlib, argparse, os
from datetime import datetime

DB_PATH = os.path.expanduser("~/bounty-autopilot/data/findings.json")

def load_db():
    if os.path.exists(DB_PATH):
        with open(DB_PATH) as f:
            return json.load(f)
    return {"findings": [], "stats": {"total": 0, "pending_review": 0, "submitted": 0, "paid": 0}}

def save_db(db):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

def finding_hash(track, domain, finding):
    raw = f"{track}|{domain}|{finding.get('type','')}|{finding.get('endpoint', finding.get('file', finding.get('contract','')))}|{finding.get('description','')[:100]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--track", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--report", default="")
    args = parser.parse_args()

    db = load_db()
    existing_hashes = {f["hash"] for f in db["findings"]}

    try:
        with open(args.file) as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        print(f"[add_finding] 파일 파싱 실패: {args.file}")
        return

    findings_key = "candidates" if "candidates" in data else "findings"
    new_count = 0

    for finding in data.get(findings_key, []):
        sev = finding.get("severity", "LOW")
        if sev not in ("HIGH", "CRITICAL"):
            continue

        h = finding_hash(args.track, args.domain, finding)
        if h in existing_hashes:
            continue

        entry = {
            "hash": h,
            "track": args.track,
            "domain": args.domain,
            "date": datetime.now().strftime("%Y-%m-%d"),
            "severity": sev,
            "type": finding.get("type", finding.get("endpoint", "unknown")),
            "description": finding.get("description", finding.get("test_scenario", "")),
            "report_path": args.report,
            "status": "pending_review",  # pending_review → verified → submitted → paid/rejected
            "notes": ""
        }
        db["findings"].append(entry)
        existing_hashes.add(h)
        new_count += 1

    db["stats"]["total"] = len(db["findings"])
    db["stats"]["pending_review"] = len([f for f in db["findings"] if f["status"] == "pending_review"])

    save_db(db)
    if new_count:
        print(f"[add_finding] {args.track}/{args.domain}: {new_count}건 추가 (총 {db['stats']['total']}건)")

if __name__ == "__main__":
    main()
