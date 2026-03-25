#!/usr/bin/env python3
"""
Human Review Queue — 발견사항 검토 + 상태 관리 CLI
이것이 사람이 개입하는 유일한 지점입니다.

사용법:
  python3 review.py              # 대기 중인 건 목록
  python3 review.py --show 3     # 3번 건 상세 + 리포트
  python3 review.py --verify 3   # 3번 건 → verified (수동 검증 완료)
  python3 review.py --submit 3   # 3번 건 → submitted (리포트 제출 완료)
  python3 review.py --reject 3   # 3번 건 → rejected (false positive)
  python3 review.py --paid 3     # 3번 건 → paid (바운티 수령)
  python3 review.py --stats      # 전체 통계
"""
import json, os, sys, argparse

DB_PATH = os.path.expanduser("~/bounty-autopilot/data/findings.json")

COLORS = {
    "CRITICAL": "\033[91m", "HIGH": "\033[93m",
    "MEDIUM": "\033[96m", "LOW": "\033[37m",
    "RESET": "\033[0m", "BOLD": "\033[1m", "DIM": "\033[2m"
}

STATUS_EMOJI = {
    "pending_review": "⏳", "verified": "✅",
    "submitted": "📨", "paid": "💰", "rejected": "❌"
}

def load_db():
    with open(DB_PATH) as f:
        return json.load(f)

def save_db(db):
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

def list_pending(db):
    pending = [(i, f) for i, f in enumerate(db["findings"]) if f["status"] == "pending_review"]
    if not pending:
        print("\n  🎉 대기 중인 건 없음!\n")
        return

    print(f"\n  ⏳ 검증 대기: {len(pending)}건\n")
    print(f"  {'#':>3}  {'심각도':8}  {'트랙':6}  {'타겟':20}  {'유형':25}  {'날짜'}")
    print(f"  {'─'*3}  {'─'*8}  {'─'*6}  {'─'*20}  {'─'*25}  {'─'*10}")

    for idx, f in pending:
        c = COLORS.get(f["severity"], "")
        r = COLORS["RESET"]
        print(f"  {idx:>3}  {c}{f['severity']:8}{r}  {f['track']:6}  {f['domain']:20}  {f['type'][:25]:25}  {f['date']}")

    print(f"\n  💡 상세 보기: python3 review.py --show [번호]")
    print(f"  💡 검증 완료: python3 review.py --verify [번호]\n")

def show_detail(db, idx):
    if idx >= len(db["findings"]):
        print(f"  ❌ #{idx} 없음")
        return

    f = db["findings"][idx]
    c = COLORS.get(f["severity"], "")
    r = COLORS["RESET"]

    print(f"\n  {'═'*60}")
    print(f"  #{idx} {STATUS_EMOJI.get(f['status'],'')} {c}{f['severity']}{r} | {f['track']} | {f['domain']}")
    print(f"  {'═'*60}")
    print(f"  유형: {f['type']}")
    print(f"  날짜: {f['date']}")
    print(f"  상태: {f['status']}")
    print(f"  설명: {f['description'][:200]}")

    if f.get("report_path") and os.path.exists(f["report_path"]):
        print(f"\n  📝 리포트 미리보기:")
        print(f"  {'─'*60}")
        with open(f["report_path"]) as rf:
            content = rf.read()[:1000]
            for line in content.split("\n"):
                print(f"  {line}")
        if len(content) >= 1000:
            print(f"  ... (전체 보기: cat {f['report_path']})")
    print()

def update_status(db, idx, new_status):
    if idx >= len(db["findings"]):
        print(f"  ❌ #{idx} 없음")
        return
    old = db["findings"][idx]["status"]
    db["findings"][idx]["status"] = new_status

    # 통계 갱신
    for key in ["pending_review", "verified", "submitted", "paid", "rejected"]:
        db["stats"][key if key != "verified" else key] = len([f for f in db["findings"] if f["status"] == key])

    save_db(db)
    emoji = STATUS_EMOJI.get(new_status, "")
    print(f"  {emoji} #{idx}: {old} → {new_status}")

def show_stats(db):
    findings = db["findings"]
    print(f"\n  📊 전체 통계")
    print(f"  {'─'*40}")
    print(f"  총 발견:      {len(findings)}")

    for status, emoji in STATUS_EMOJI.items():
        count = len([f for f in findings if f["status"] == status])
        if count:
            print(f"  {emoji} {status:16} {count}")

    print(f"\n  트랙별:")
    for track in ["idor", "oss", "web3"]:
        count = len([f for f in findings if f["track"] == track])
        if count:
            print(f"    {track:6} {count}건")
    print()

def main():
    parser = argparse.ArgumentParser(description="Bug Bounty 발견사항 검토")
    parser.add_argument("--show", type=int, help="상세 보기")
    parser.add_argument("--verify", type=int, help="검증 완료 처리")
    parser.add_argument("--submit", type=int, help="제출 완료 처리")
    parser.add_argument("--reject", type=int, help="False positive 처리")
    parser.add_argument("--paid", type=int, help="바운티 수령 처리")
    parser.add_argument("--stats", action="store_true", help="통계")
    args = parser.parse_args()

    if not os.path.exists(DB_PATH):
        print("  findings.json 없음 — 아직 파이프라인이 실행되지 않았습니다")
        return

    db = load_db()

    if args.show is not None:
        show_detail(db, args.show)
    elif args.verify is not None:
        update_status(db, args.verify, "verified")
    elif args.submit is not None:
        update_status(db, args.submit, "submitted")
    elif args.reject is not None:
        update_status(db, args.reject, "rejected")
    elif args.paid is not None:
        update_status(db, args.paid, "paid")
    elif args.stats:
        show_stats(db)
    else:
        list_pending(db)

if __name__ == "__main__":
    main()
