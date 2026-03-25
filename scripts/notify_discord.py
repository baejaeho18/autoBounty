#!/usr/bin/env python3
"""
ReDoS 발견 시 Discord 웹훅으로 리포트 요약 + GitHub 링크 전송.

사용법:
  python3 notify_discord.py \
    --report data/track4/reports/angular_angular_redos_2025-01-01_report.md \
    --project angular_angular \
    --repo-url https://github.com/angular/angular \
    --analysis data/track4/analysis/angular_angular_redos_2025-01-01.json \
    --branch claude/redos-vulnerability-scanner-4sHOd
"""
import json
import os
import sys
import urllib.request
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

# GitHub 레포 정보 (리포트 파일 링크 생성용)
GITHUB_REPO = "baejaeho18/autoBounty"


def load_config():
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except:
        return {}


def get_webhook_url():
    config = load_config()
    return config.get("general", {}).get("notification", {}).get("discord_webhook", "")


def read_report_summary(report_path, max_lines=30):
    """리포트에서 Summary와 Vulnerability Details 추출"""
    try:
        with open(report_path, "r") as f:
            content = f.read()
    except:
        return "리포트 읽기 실패"

    # 너무 길면 자르기 (Discord 2000자 제한 고려)
    lines = content.split("\n")
    summary_lines = []
    in_section = False

    for line in lines:
        if line.startswith("# ") or line.startswith("## Summary") or line.startswith("## Vulnerability"):
            in_section = True
        if line.startswith("## Timeline") or line.startswith("## Methodology"):
            in_section = False
            continue
        if in_section:
            summary_lines.append(line)
        if len(summary_lines) >= max_lines:
            summary_lines.append("...")
            break

    return "\n".join(summary_lines).strip() if summary_lines else content[:800]


def get_tp_findings(analysis_path):
    """분석 결과에서 TP 건 추출"""
    try:
        with open(analysis_path) as f:
            data = json.load(f)
    except:
        return []

    return [
        t for t in data.get("redos_triage", [])
        if t.get("verdict") == "TP" and t.get("severity") in ("CRITICAL", "HIGH")
    ]


def build_github_file_url(repo_url, file_path, line=None):
    """GitHub 파일 링크 생성"""
    # repo_url: https://github.com/angular/angular
    # file_path: src/core/regex.ts:42
    parts = file_path.split(":")
    fpath = parts[0]
    url = f"{repo_url}/blob/main/{fpath}"
    if len(parts) > 1 and parts[1].isdigit():
        url += f"#L{parts[1]}"
    return url


def build_report_github_url(report_path, branch):
    """리포트 파일의 GitHub 링크 생성"""
    rel_path = os.path.relpath(report_path, BASE_DIR)
    return f"https://github.com/{GITHUB_REPO}/blob/{branch}/{rel_path}"


def send_discord(webhook_url, embeds):
    """Discord 웹훅으로 embed 메시지 전송"""
    payload = json.dumps({"embeds": embeds}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        print("[discord] 알림 전송 완료")
    except Exception as e:
        print(f"[discord] 전송 실패: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="ReDoS 발견 Discord 알림")
    parser.add_argument("--report", required=True, help="리포트 파일 경로")
    parser.add_argument("--project", required=True, help="프로젝트 이름")
    parser.add_argument("--repo-url", required=True, help="대상 레포 GitHub URL")
    parser.add_argument("--analysis", default="", help="LLM 분석 결과 JSON")
    parser.add_argument("--branch", default="main", help="리포트가 push된 브랜치")
    args = parser.parse_args()

    webhook_url = get_webhook_url()
    if not webhook_url or webhook_url == "YOUR_DISCORD_WEBHOOK_URL":
        print("[discord] 웹훅 미설정 — 스킵")
        return

    # 리포트 요약
    summary = read_report_summary(args.report)

    # TP findings에서 GitHub 링크 생성
    tp_findings = get_tp_findings(args.analysis) if args.analysis else []

    # 리포트 GitHub 링크
    report_url = build_report_github_url(args.report, args.branch)

    # Discord embed 구성
    fields = []

    # 취약 파일별 GitHub 링크
    for tp in tp_findings[:5]:
        file_path = tp.get("file", "?")
        severity = tp.get("severity", "?")
        vuln_type = tp.get("vuln_type", "?")
        gh_link = build_github_file_url(args.repo_url, file_path)

        fields.append({
            "name": f":warning: [{severity}] {vuln_type}",
            "value": f"[`{file_path}`]({gh_link})\n`{tp.get('pattern', '?')[:60]}`",
            "inline": False,
        })

    if len(tp_findings) > 5:
        fields.append({
            "name": "",
            "value": f"... 외 {len(tp_findings) - 5}건",
            "inline": False,
        })

    # 리포트 링크
    fields.append({
        "name": ":page_facing_up: Report",
        "value": f"[전체 리포트 보기]({report_url})",
        "inline": False,
    })

    # severity에 따른 색상
    color = 0xFF0000  # red (CRITICAL)
    if tp_findings and all(t.get("severity") == "HIGH" for t in tp_findings):
        color = 0xFF8C00  # orange (HIGH)

    embed = {
        "title": f":bug: ReDoS Found: {args.project}",
        "description": f"**{len(tp_findings)}건의 ReDoS 취약점 발견** (CWE-1333)\n대상: [{args.project}]({args.repo_url})",
        "color": color,
        "fields": fields,
        "footer": {"text": "autoBounty ReDoS Scanner"},
    }

    send_discord(webhook_url, [embed])


if __name__ == "__main__":
    main()
