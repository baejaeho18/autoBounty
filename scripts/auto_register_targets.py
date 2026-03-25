#!/usr/bin/env python3
"""
discover_targets.sh 결과를 파싱해서 선별 기준 충족 타겟을 자동 등록
"""
import json, os, re, sys, glob

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(SCRIPT_DIR)
DATA = os.path.join(BASE, "data")

# ── 선별 기준 (USER-GUIDE 3.2절) ──────────────────────────────
IDOR_MIN_BOUNTY = 50
OSS_STARS_MIN   = 1000
OSS_STARS_MAX   = 50000
WEB3_MIN_BOUNTY = 100

# ── 타겟 파일 로드 헬퍼 ───────────────────────────────────────
def load_targets(track):
    path = os.path.join(DATA, f"targets_{track}.json")
    if os.path.exists(path):
        return json.load(open(path))
    return []

def save_targets(track, targets):
    path = os.path.join(DATA, f"targets_{track}.json")
    with open(path, "w") as f:
        json.dump(targets, f, indent=2, ensure_ascii=False)

def already_registered(targets, key, value):
    """중복 등록 방지"""
    return any(t.get(key, "").lower() == value.lower() for t in targets)

# ── 바운티 금액 파싱 ($100, $10,000, $10K 등) ─────────────────
def parse_usd(s):
    if not s:
        return 0
    s = str(s).replace(",", "")
    m = re.search(r'\$?([\d.]+)\s*[Kk]', s)
    if m:
        return int(float(m.group(1)) * 1000)
    m = re.search(r'\$?([\d]+)', s)
    if m:
        return int(m.group(1))
    return 0

# ── discovered JSON 파싱 (여러 JSON 블록이 이어붙여진 형식) ────
def parse_discovered_file(path):
    with open(path) as f:
        raw = f.read()

    # JSON 블록 추출 (중첩 중괄호 매칭)
    blocks = []
    depth = 0
    start = None
    for i, ch in enumerate(raw):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    blocks.append(json.loads(raw[start:i+1]))
                except json.JSONDecodeError:
                    pass
                start = None
    return blocks

# ── 자동 등록 ─────────────────────────────────────────────────
def register_idor(programs):
    targets = load_targets("idor")
    added = []
    for p in programs:
        domain = p.get("domain", "")
        bounty_raw = p.get("bounty_range", "") or p.get("bounty_max", "")
        api_in_scope = p.get("api_in_scope", True)
        program_url = p.get("url", "")

        if not domain:
            continue
        if not api_in_scope:
            continue

        # 최소 바운티 파싱 (범위에서 최솟값 추출)
        min_val = parse_usd(bounty_raw.split("~")[0] if "~" in bounty_raw else bounty_raw)
        if min_val < IDOR_MIN_BOUNTY:
            continue
        if already_registered(targets, "domain", domain):
            continue

        targets.append({
            "name": p.get("name", domain.split(".")[0]),
            "domain": domain,
            "program_url": program_url,
            "scope": [f"*.{domain}", domain],
            "out_of_scope": [],
            "auth": {"user_a_token": "ENV:TOKEN_A", "user_b_token": "ENV:TOKEN_B"},
            "notes": p.get("notes", "")
        })
        added.append(domain)

    if added:
        save_targets("idor", targets)
        for d in added:
            print(f"  ✓ [IDOR] {d} 등록")
            print(f"    ⚠️  계정 2개 생성 + TOKEN_A/TOKEN_B 환경변수 설정 필요")
    return len(added)

def register_oss(projects):
    targets = load_targets("oss")
    added = []
    for p in projects:
        repo = p.get("repo_url", "")
        stars = p.get("stars", 0) or 0
        lang = p.get("language", "")
        has_security = p.get("security_policy", False)
        score = p.get("attack_surface_score", "MEDIUM")

        if not repo:
            continue
        if not (OSS_STARS_MIN <= stars <= OSS_STARS_MAX):
            continue
        if not has_security:
            continue
        if score == "LOW":
            continue
        if already_registered(targets, "repo_url", repo):
            continue

        name = p.get("name", repo.rstrip("/").split("/")[-1])
        targets.append({
            "name": name,
            "repo_url": repo,
            "language": lang,
            "security_policy": "",
            "notes": p.get("notes", "")
        })
        added.append(name)

    if added:
        save_targets("oss", targets)
        for n in added:
            print(f"  ✓ [OSS] {n} 등록")
    return len(added)

def register_web3(programs):
    targets = load_targets("web3")
    added = []
    for p in programs:
        repo = p.get("repo_url", "")
        bounty_raw = p.get("bounty_critical", "")
        audit_count = p.get("audit_count", 99)

        if not repo:
            continue
        if parse_usd(bounty_raw) < WEB3_MIN_BOUNTY:
            continue
        if audit_count > 1:
            continue
        if already_registered(targets, "repo_url", repo):
            continue

        name = p.get("name", repo.rstrip("/").split("/")[-1])
        targets.append({
            "name": name,
            "repo_url": repo,
            "platform": "immunefi",
            "notes": p.get("notes", "")
        })
        added.append(name)

    if added:
        save_targets("web3", targets)
        for n in added:
            print(f"  ✓ [Web3] {n} 등록")
    return len(added)

# ── 메인 ─────────────────────────────────────────────────────
def main():
    # 오늘 날짜 또는 최신 파일 사용
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        files = sorted(glob.glob(os.path.join(DATA, "discovered_*.json")), reverse=True)
        if not files:
            print("탐색 결과 파일 없음")
            sys.exit(0)
        path = files[0]

    print(f"[AUTO-REGISTER] {os.path.basename(path)} 분석 중...")
    blocks = parse_discovered_file(path)

    if not blocks:
        print("  파싱 가능한 JSON 블록 없음")
        sys.exit(0)

    total = 0
    for block in blocks:
        # IDOR: programs 배열, platform이 hackerone/bugcrowd
        programs_idor = [
            p for p in block.get("programs", [])
            if p.get("platform", "") in ("hackerone", "bugcrowd", "")
            and p.get("api_in_scope", True)
        ]
        if programs_idor:
            total += register_idor(programs_idor)

        # Web3: programs 배열, platform이 immunefi
        programs_web3 = [
            p for p in block.get("programs", [])
            if p.get("platform", "") == "immunefi"
        ]
        if programs_web3:
            total += register_web3(programs_web3)

        # OSS: projects 배열
        if "projects" in block:
            total += register_oss(block["projects"])

    if total == 0:
        print("  신규 등록 타겟 없음 (이미 등록됐거나 기준 미달)")
    else:
        print(f"[AUTO-REGISTER] 완료 — {total}개 신규 등록")

if __name__ == "__main__":
    main()
