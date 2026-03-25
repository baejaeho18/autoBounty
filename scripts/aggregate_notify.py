#!/usr/bin/env python3
"""
ReDoS 발견사항 취합 + Discord 웹훅 알림
"""
import json, os, urllib.request
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(SCRIPT_DIR)
DB_PATH = os.path.join(BASE, "data", "findings.json")
CONFIG_PATH = os.path.join(BASE, "config.json")
TODAY = datetime.now().strftime("%Y-%m-%d")

def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return {}

def send_discord(webhook_url, message):
    if not webhook_url or webhook_url == "YOUR_DISCORD_WEBHOOK_URL":
        print(f"[notify] Discord 미설정 — 콘솔 출력:\n{message}")
        return
    payload = json.dumps({"content": message}).encode()
    req = urllib.request.Request(webhook_url, data=payload, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req)
        print("[notify] Discord 알림 전송 완료")
    except Exception as e:
        print(f"[notify] Discord 전송 실패: {e}")

def main():
    config = load_json(CONFIG_PATH)
    db = load_json(DB_PATH)

    if not db:
        print("[aggregate] findings.json 없음")
        return

    today_findings = [f for f in db.get("findings", []) if f.get("date") == TODAY]
    pending = [f for f in db.get("findings", []) if f.get("status") == "pending_review"]

    if not today_findings and not pending:
        print("[aggregate] 오늘 새 발견 없음, 대기 중인 건 없음")
        return

    lines = [f"**ReDoS Scanner 일일 리포트 ({TODAY})**\n"]

    if today_findings:
        lines.append(f"오늘 새 발견: {len(today_findings)}건")
        for f in today_findings:
            lines.append(f"  [{f['severity']}] {f['domain']} — {f['type']}")

    if pending:
        lines.append(f"\n검증 대기 중: {len(pending)}건")
        for f in pending[:5]:
            lines.append(f"  - {f['domain']} ({f['date']})")
        if len(pending) > 5:
            lines.append(f"  ... 외 {len(pending)-5}건")

    stats = db.get("stats", {})
    lines.append(f"\n누적: 총 {stats.get('total',0)} | 대기 {stats.get('pending_review',0)} | 제출 {stats.get('submitted',0)} | 보상 {stats.get('paid',0)}")

    message = "\n".join(lines)

    webhook = config.get("general", {}).get("notification", {}).get("discord_webhook", "")
    send_discord(webhook, message)

    log_dir = os.path.join(BASE, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{TODAY}-summary.txt")
    with open(log_path, "w") as f:
        f.write(message)
    print(f"[aggregate] 요약 저장: {log_path}")

if __name__ == "__main__":
    main()
