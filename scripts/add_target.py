#!/usr/bin/env python3
"""
타겟 추가 헬퍼

사용법:
  python3 add_target.py idor --domain api.example.com --program https://hackerone.com/example
  python3 add_target.py oss  --repo https://github.com/org/project --name myproject --lang python
  python3 add_target.py web3 --repo https://github.com/org/protocol --name myprotocol
"""
import json, os, argparse

BASE = os.path.expanduser("~/bounty-autopilot/data")

def add_idor(args):
    path = f"{BASE}/targets_idor.json"
    targets = json.load(open(path)) if os.path.exists(path) else []
    targets.append({
        "name": args.domain.split(".")[0],
        "domain": args.domain,
        "program_url": args.program or "",
        "scope": [f"*.{args.domain}", args.domain],
        "out_of_scope": [],
        "auth": {"user_a_token": "ENV:TOKEN_A", "user_b_token": "ENV:TOKEN_B"},
        "notes": ""
    })
    with open(path, "w") as f:
        json.dump(targets, f, indent=2)
    print(f"✓ IDOR 타겟 추가: {args.domain} (총 {len(targets)}개)")
    print(f"  ⚠️  인증 토큰 설정 필요: 환경변수 TOKEN_A, TOKEN_B")

def add_oss(args):
    path = f"{BASE}/targets_oss.json"
    targets = json.load(open(path)) if os.path.exists(path) else []
    targets.append({
        "name": args.name or args.repo.split("/")[-1],
        "repo_url": args.repo,
        "language": args.lang or "unknown",
        "security_policy": "",
        "notes": ""
    })
    with open(path, "w") as f:
        json.dump(targets, f, indent=2)
    print(f"✓ OSS 타겟 추가: {args.repo} (총 {len(targets)}개)")

def add_web3(args):
    path = f"{BASE}/targets_web3.json"
    targets = json.load(open(path)) if os.path.exists(path) else []
    targets.append({
        "name": args.name or args.repo.split("/")[-1],
        "repo_url": args.repo,
        "platform": args.platform or "immunefi",
        "notes": ""
    })
    with open(path, "w") as f:
        json.dump(targets, f, indent=2)
    print(f"✓ Web3 타겟 추가: {args.repo} (총 {len(targets)}개)")

parser = argparse.ArgumentParser()
sub = parser.add_subparsers(dest="track")

p1 = sub.add_parser("idor")
p1.add_argument("--domain", required=True)
p1.add_argument("--program")

p2 = sub.add_parser("oss")
p2.add_argument("--repo", required=True)
p2.add_argument("--name")
p2.add_argument("--lang")

p3 = sub.add_parser("web3")
p3.add_argument("--repo", required=True)
p3.add_argument("--name")
p3.add_argument("--platform", default="immunefi")

args = parser.parse_args()
if args.track == "idor": add_idor(args)
elif args.track == "oss": add_oss(args)
elif args.track == "web3": add_web3(args)
else: parser.print_help()
