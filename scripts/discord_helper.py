#!/usr/bin/env python3
"""
Discord 알림 헬퍼 — track4_redos.sh에서 호출
각 파이프라인 단계별 알림 전송/편집을 담당.

사용법:
  python3 discord_helper.py <command> [options]

Commands:
  repo-start     레포 스캐닝 시작 알림
  static-found   정적 분석 검출 알림 (message_id 반환)
  llm-result     LLM 결과 → 정적 분석 메시지 편집
  repo-done      레포 완료 요약 (진행률 포함)
  report         리포트 내용 알림
  pipeline-done  65개 전체 완료 알림
"""
import argparse
import json
import os
import sys
import requests as _requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
}


def get_webhook():
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        return cfg.get("general", {}).get("notification", {}).get("discord_webhook", "")
    except:
        return ""


def send(webhook, payload):
    """메시지 전송, message_id 반환"""
    try:
        resp = _requests.post(
            webhook + "?wait=true", json=payload, headers=HEADERS, timeout=15
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("id", "")
    except Exception as e:
        print(f"[discord] send 실패: {e}", file=sys.stderr)
        return ""


def edit(webhook, message_id, payload):
    """기존 메시지 편집"""
    try:
        resp = _requests.patch(
            f"{webhook}/messages/{message_id}",
            json=payload,
            headers=HEADERS,
            timeout=15,
        )
        resp.raise_for_status()
    except Exception as e:
        print(f"[discord] edit 실패: {e}", file=sys.stderr)


# ─── Commands ───


def cmd_repo_start(args):
    webhook = get_webhook()
    if not webhook:
        return
    embed = {
        "title": f"\U0001f50d [{args.index}/{args.total}] {args.name}",
        "description": (
            f"**Tier:** {args.tier} | **Lang:** {args.lang}\n"
            f"[\U0001f517 GitHub](https://github.com/{args.name.replace('_', '/', 1)})"
        ),
        "color": 0x5865F2,
        "footer": {"text": f"autoBounty ReDoS Scanner \u2022 {args.index}/{args.total}"},
    }
    msg_id = send(webhook, {"embeds": [embed]})
    print(msg_id)  # stdout으로 message_id 반환


def cmd_static_found(args):
    webhook = get_webhook()
    if not webhook:
        return

    severity_text = []
    if args.critical > 0:
        severity_text.append(f"CRITICAL: **{args.critical}**")
    if args.high > 0:
        severity_text.append(f"HIGH: **{args.high}**")
    if args.medium > 0:
        severity_text.append(f"MEDIUM: {args.medium}")
    if args.low > 0:
        severity_text.append(f"LOW: {args.low}")

    crit_high = args.critical + args.high
    if crit_high > 0:
        color = 0xFF8C00
        emoji = "\u26a0\ufe0f"
    else:
        color = 0xFFCC00
        emoji = "\U0001f50e"

    embed = {
        "title": f"{emoji} Static: {args.name} \u2014 {args.findings}\uac74 \ubc1c\uacac",
        "description": " / ".join(severity_text),
        "color": color,
        "footer": {"text": "\u23f3 LLM \ubd84\uc11d \ub300\uae30 \uc911..."},
    }

    # findings 상세 (있으면)
    if args.details:
        try:
            details = json.loads(args.details)
            detail_lines = []
            for d in details[:8]:
                detail_lines.append(
                    f"`[{d.get('severity','?')}]` {d.get('vuln_type','?')} \u2192 `{d.get('file','?')}:{d.get('line','?')}`"
                )
            if len(details) > 8:
                detail_lines.append(f"... \uc678 {len(details)-8}\uac74")
            embed["fields"] = [
                {"name": "Findings", "value": "\n".join(detail_lines), "inline": False}
            ]
        except:
            pass

    msg_id = send(webhook, {"embeds": [embed]})
    print(msg_id)


def cmd_llm_result(args):
    webhook = get_webhook()
    if not webhook or not args.edit_msg_id:
        return

    if args.tp > 0:
        color = 0xFF0000
        emoji = "\U0001f6a8"
        result_text = f"**TP {args.tp}\uac74** / FP {args.fp}\uac74"
    else:
        color = 0x00CC00
        emoji = "\u2705"
        result_text = f"TP 0\uac74 / FP {args.fp}\uac74 (\uc804\ubd80 \uc624\ud0d0)"

    severity_text = []
    if args.critical > 0:
        severity_text.append(f"CRITICAL: **{args.critical}**")
    if args.high > 0:
        severity_text.append(f"HIGH: **{args.high}**")
    if args.medium > 0:
        severity_text.append(f"MEDIUM: {args.medium}")
    if args.low > 0:
        severity_text.append(f"LOW: {args.low}")

    embed = {
        "title": f"{emoji} LLM Result: {args.name} \u2014 {result_text}",
        "description": " / ".join(severity_text) if severity_text else "\ubaa8\ub450 FP \ud310\uc815",
        "color": color,
        "footer": {"text": "autoBounty LLM Triage"},
    }

    # TP 상세 정보
    if args.tp_details:
        try:
            details = json.loads(args.tp_details)
            for d in details[:5]:
                embed.setdefault("fields", []).append({
                    "name": f"\U0001f41b [{d.get('severity','?')}] {d.get('vuln_type','?')}",
                    "value": (
                        f"`{d.get('file','?')}`\n"
                        f"Pattern: `{d.get('pattern','?')[:80]}`\n"
                        f"{d.get('reasoning','')[:200]}"
                    ),
                    "inline": False,
                })
        except:
            pass

    edit(webhook, args.edit_msg_id, {"embeds": [embed]})
    print("edited")


def cmd_repo_done(args):
    webhook = get_webhook()
    if not webhook:
        return

    pct = round(args.index / args.total * 100) if args.total > 0 else 0
    bar_filled = pct // 5
    bar = "\u2588" * bar_filled + "\u2591" * (20 - bar_filled)

    if args.tp > 0:
        color = 0xFF0000
        status = f"\U0001f6a8 TP {args.tp}\uac74 \ubc1c\uacac!"
    elif args.static > 0:
        color = 0xFFCC00
        status = f"\u26a0\ufe0f \uc815\uc801 {args.static}\uac74 (LLM: \ubaa8\ub450 FP)"
    else:
        color = 0x00CC00
        status = "\u2705 Clean"

    embed = {
        "title": f"\u2705 [{args.index}/{args.total}] {args.name} \uc644\ub8cc",
        "description": (
            f"{status}\n"
            f"\uc815\uc801 \ubd84\uc11d: {args.static}\uac74 | LLM TP: {args.tp}\uac74\n\n"
            f"`{bar}` **{pct}%** ({args.index}/{args.total})"
        ),
        "color": color,
        "footer": {"text": "autoBounty ReDoS Scanner"},
    }
    send(webhook, {"embeds": [embed]})


def cmd_report(args):
    webhook = get_webhook()
    if not webhook:
        return

    # 리포트 내용 읽기
    content = ""
    try:
        with open(args.report_file) as f:
            content = f.read()
    except:
        content = "(리포트 읽기 실패)"

    # Discord embed description 4096자 제한
    if len(content) > 3800:
        content = content[:3800] + "\n\n... (truncated)"

    github_repo = "baejaeho18/autoBounty"
    branch = args.branch or "redos-scanner"
    rel_path = os.path.relpath(args.report_file, BASE_DIR)
    report_url = f"https://github.com/{github_repo}/blob/{branch}/{rel_path}"

    embed = {
        "title": f"\U0001f4dd Report: {args.name}",
        "description": content,
        "color": 0xFF0000,
        "fields": [
            {
                "name": "\U0001f517 GitHub",
                "value": f"[\uc804\uccb4 \ub9ac\ud3ec\ud2b8 \ubcf4\uae30]({report_url})",
                "inline": False,
            }
        ],
        "footer": {"text": "autoBounty ReDoS Scanner"},
    }
    send(webhook, {"embeds": [embed]})


def cmd_pipeline_done(args):
    webhook = get_webhook()
    if not webhook:
        return

    if args.tp_total > 0:
        emoji = "\U0001f6a8"
        status = f"**{args.tp_total}\uac74\uc758 \uc2e4\uc81c ReDoS \ucde8\uc57d\uc810 \ud655\uc778!**"
        color = 0xFF0000
    elif args.static_crit + args.static_high > 0:
        emoji = "\u26a0\ufe0f"
        status = "\uc815\uc801 \ubd84\uc11d \ud6c4\ubcf4 \ubc1c\uacac (LLM \uac80\uc99d \uc644\ub8cc)"
        color = 0xFF8C00
    else:
        emoji = "\u2705"
        status = "\ud2b9\uc774\uc0ac\ud56d \uc5c6\uc74c"
        color = 0x00CC00

    embed = {
        "title": f"{emoji} ReDoS Scanner \uc644\ub8cc ({args.date})",
        "description": status,
        "color": color,
        "fields": [
            {
                "name": "\U0001f50d \uc815\uc801 \ubd84\uc11d",
                "value": (
                    f"\uc2a4\ucea8 \ub808\ud3ec: **{args.total_repos}\uac1c**\n"
                    f"\ucd1d \ud0d0\uc9c0: **{args.static_total}\uac74**\n"
                    f"CRITICAL: {args.static_crit} / HIGH: {args.static_high} / "
                    f"MEDIUM: {args.static_med} / LOW: {args.static_low}"
                ),
                "inline": False,
            },
            {
                "name": "\U0001f916 LLM \uc815\ubc00 \ubd84\uc11d",
                "value": (
                    f"\uc644\ub8cc: **{args.llm_done}\uac1c** \ud504\ub85c\uc81d\ud2b8\n"
                    f"\ubbf8\uc644\ub8cc: {args.llm_pending}\uac1c\n"
                    f"TP (\uc9c4\uc591\uc131): **{args.tp_total}\uac74**"
                ),
                "inline": False,
            },
            {
                "name": "\U0001f4c4 \ub9ac\ud3ec\ud2b8",
                "value": f"\uc0dd\uc131: **{args.report_count}\uac74**",
                "inline": False,
            },
        ],
        "footer": {"text": "autoBounty ReDoS Scanner"},
    }
    send(webhook, {"embeds": [embed]})


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")

    # repo-start
    p = sub.add_parser("repo-start")
    p.add_argument("--name", required=True)
    p.add_argument("--tier", default="?")
    p.add_argument("--lang", default="?")
    p.add_argument("--index", type=int, required=True)
    p.add_argument("--total", type=int, required=True)

    # static-found
    p = sub.add_parser("static-found")
    p.add_argument("--name", required=True)
    p.add_argument("--findings", type=int, default=0)
    p.add_argument("--critical", type=int, default=0)
    p.add_argument("--high", type=int, default=0)
    p.add_argument("--medium", type=int, default=0)
    p.add_argument("--low", type=int, default=0)
    p.add_argument("--details", default="")

    # llm-result
    p = sub.add_parser("llm-result")
    p.add_argument("--name", required=True)
    p.add_argument("--edit-msg-id", required=True)
    p.add_argument("--tp", type=int, default=0)
    p.add_argument("--fp", type=int, default=0)
    p.add_argument("--critical", type=int, default=0)
    p.add_argument("--high", type=int, default=0)
    p.add_argument("--medium", type=int, default=0)
    p.add_argument("--low", type=int, default=0)
    p.add_argument("--tp-details", default="")

    # repo-done
    p = sub.add_parser("repo-done")
    p.add_argument("--name", required=True)
    p.add_argument("--index", type=int, required=True)
    p.add_argument("--total", type=int, required=True)
    p.add_argument("--static", type=int, default=0)
    p.add_argument("--tp", type=int, default=0)

    # report
    p = sub.add_parser("report")
    p.add_argument("--name", required=True)
    p.add_argument("--report-file", required=True)
    p.add_argument("--branch", default="redos-scanner")

    # pipeline-done
    p = sub.add_parser("pipeline-done")
    p.add_argument("--date", required=True)
    p.add_argument("--total-repos", type=int, default=65)
    p.add_argument("--static-total", type=int, default=0)
    p.add_argument("--static-crit", type=int, default=0)
    p.add_argument("--static-high", type=int, default=0)
    p.add_argument("--static-med", type=int, default=0)
    p.add_argument("--static-low", type=int, default=0)
    p.add_argument("--llm-done", type=int, default=0)
    p.add_argument("--llm-pending", type=int, default=0)
    p.add_argument("--tp-total", type=int, default=0)
    p.add_argument("--report-count", type=int, default=0)

    args = parser.parse_args()
    cmds = {
        "repo-start": cmd_repo_start,
        "static-found": cmd_static_found,
        "llm-result": cmd_llm_result,
        "repo-done": cmd_repo_done,
        "report": cmd_report,
        "pipeline-done": cmd_pipeline_done,
    }
    fn = cmds.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
