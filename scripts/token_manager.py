#!/usr/bin/env python3
"""
IDOR 타겟 토큰 관리자
- 토큰 저장/로드 (파일 기반, 환경변수 대체)
- JWT 만료 감지 + 자동 갱신 (refresh token 또는 credential 기반)
- Playwright 헤드리스 브라우저로 토큰 추출 자동화

사용법:
  # 초기 설정 (1회): 브라우저로 로그인하여 토큰 자동 추출
  python3 token_manager.py extract --domain api.example.com --login-url https://example.com/login

  # 토큰 상태 확인
  python3 token_manager.py status

  # 만료된 토큰 자동 갱신
  python3 token_manager.py refresh --domain api.example.com

  # 전체 토큰 갱신 (cron용)
  python3 token_manager.py refresh-all
"""
import json, os, sys, time, base64, argparse
from datetime import datetime, timezone

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(SCRIPT_DIR)
TOKEN_STORE = os.path.join(BASE, "data", ".tokens.json")
TARGETS_FILE = os.path.join(BASE, "data", "targets_idor.json")


def load_tokens():
    if os.path.exists(TOKEN_STORE):
        with open(TOKEN_STORE) as f:
            return json.load(f)
    return {}


def save_tokens(tokens):
    with open(TOKEN_STORE, "w") as f:
        json.dump(tokens, f, indent=2)
    os.chmod(TOKEN_STORE, 0o600)  # owner-only read/write


def decode_jwt_payload(token):
    """JWT 페이로드 디코딩 (서명 검증 없이 만료 시간만 확인)"""
    try:
        token_str = token.replace("Bearer ", "").strip()
        parts = token_str.split(".")
        if len(parts) != 3:
            return None
        # base64url 디코딩
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)  # padding
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None


def get_token_expiry(token):
    """JWT 토큰 만료 시간 반환 (Unix timestamp). 비JWT면 None."""
    payload = decode_jwt_payload(token)
    if payload and "exp" in payload:
        return payload["exp"]
    return None


def is_token_expired(token, buffer_minutes=30):
    """토큰이 만료되었거나 buffer_minutes 내 만료 예정이면 True"""
    exp = get_token_expiry(token)
    if exp is None:
        return False  # 비JWT 토큰은 만료 체크 불가 → 유효하다고 가정
    now = time.time()
    return now >= (exp - buffer_minutes * 60)


def token_expiry_str(token):
    """만료 시간을 사람이 읽을 수 있는 문자열로"""
    exp = get_token_expiry(token)
    if exp is None:
        return "알 수 없음 (비JWT)"
    dt = datetime.fromtimestamp(exp, tz=timezone.utc)
    remaining = exp - time.time()
    if remaining <= 0:
        return f"만료됨 ({dt.strftime('%Y-%m-%d %H:%M UTC')})"
    hours = remaining / 3600
    if hours < 1:
        return f"{remaining/60:.0f}분 남음"
    elif hours < 24:
        return f"{hours:.1f}시간 남음"
    else:
        return f"{hours/24:.1f}일 남음"


# ─── 토큰 추출: Playwright 헤드리스 브라우저 ───

def extract_tokens(domain, login_url, headless=True):
    """
    Playwright로 로그인 페이지를 열어 사용자가 로그인하면
    Authorization 헤더에서 토큰을 자동 캡처합니다.

    headless=False: 브라우저 창이 뜨고 직접 로그인 (초회)
    headless=True: 저장된 cookie/session으로 자동 로그인 (갱신)
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("❌ Playwright 미설치. 설치:")
        print("   pip3 install playwright && playwright install chromium")
        return None

    tokens = load_tokens()
    domain_data = tokens.get(domain, {})
    storage_path = os.path.join(BASE, "data", f".browser_state_{domain.replace('.', '_')}.json")

    captured_tokens = []

    def capture_request(request):
        auth = request.headers.get("authorization", "")
        if auth and auth.startswith("Bearer ") and len(auth) > 20:
            if auth not in [t["token"] for t in captured_tokens]:
                captured_tokens.append({
                    "token": auth,
                    "url": request.url,
                    "timestamp": time.time()
                })
                print(f"  🔑 토큰 캡처됨: {auth[:30]}... ({request.url[:50]})")

    with sync_playwright() as p:
        browser_args = {"headless": headless}

        # 저장된 브라우저 상태가 있으면 로드
        context_args = {}
        if os.path.exists(storage_path):
            context_args["storage_state"] = storage_path

        browser = p.chromium.launch(**browser_args)
        context = browser.new_context(**context_args)
        page = context.new_page()

        # 모든 요청에서 Authorization 헤더 캡처
        page.on("request", capture_request)

        print(f"\n  🌐 브라우저 열기: {login_url}")
        if not headless:
            print("  ⏳ 계정 A로 로그인하세요. 로그인 후 페이지를 탐색하면 토큰이 캡처됩니다.")
            print("  ✋ 완료되면 터미널에서 Enter를 누르세요.")

        page.goto(login_url, wait_until="networkidle", timeout=60000)

        if not headless:
            input("\n  [계정 A 로그인 완료 후 Enter] ")

        # 페이지 탐색으로 API 요청 유도
        page.wait_for_timeout(3000)

        token_a = captured_tokens[-1]["token"] if captured_tokens else None

        if token_a:
            # 브라우저 상태 저장 (쿠키, 세션)
            context.storage_state(path=storage_path)
            os.chmod(storage_path, 0o600)

            # refresh token 찾기 (localStorage/cookie)
            refresh_token = page.evaluate("""() => {
                // localStorage에서 refresh token 검색
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    if (key.toLowerCase().includes('refresh')) {
                        return localStorage.getItem(key);
                    }
                }
                return null;
            }""")

            domain_data["token_a"] = token_a
            domain_data["token_a_captured_at"] = time.time()
            if refresh_token:
                domain_data["refresh_token_a"] = refresh_token
                print(f"  🔄 Refresh token도 캡처됨")

        # 계정 B
        if not headless:
            captured_tokens.clear()
            print("\n  이제 계정 B로 로그인하세요.")
            print("  (시크릿 탭이나 다른 프로필 사용을 권장)")

            # 새 컨텍스트 (계정 B는 별도 세션)
            context2 = browser.new_context()
            page2 = context2.new_page()
            page2.on("request", capture_request)
            page2.goto(login_url, wait_until="networkidle", timeout=60000)

            input("\n  [계정 B 로그인 완료 후 Enter] ")
            page2.wait_for_timeout(3000)

            token_b = captured_tokens[-1]["token"] if captured_tokens else None
            if token_b:
                domain_data["token_b"] = token_b
                domain_data["token_b_captured_at"] = time.time()

                refresh_token_b = page2.evaluate("""() => {
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        if (key.toLowerCase().includes('refresh')) {
                            return localStorage.getItem(key);
                        }
                    }
                    return null;
                }""")
                if refresh_token_b:
                    domain_data["refresh_token_b"] = refresh_token_b

            context2.close()

        browser.close()

    if token_a:
        domain_data["login_url"] = login_url
        domain_data["last_refresh"] = time.time()
        tokens[domain] = domain_data
        save_tokens(tokens)
        print(f"\n  ✅ 토큰 저장 완료: {TOKEN_STORE}")
        return domain_data
    else:
        print("\n  ❌ 토큰 캡처 실패 — 로그인 후 API 요청이 발생하지 않았습니다.")
        return None


def refresh_token_for_domain(domain):
    """저장된 브라우저 상태로 헤드리스 재로그인하여 토큰 갱신"""
    tokens = load_tokens()
    domain_data = tokens.get(domain, {})
    login_url = domain_data.get("login_url")

    if not login_url:
        print(f"  ⚠ {domain}: login_url 없음 — 먼저 extract 실행 필요")
        return False

    storage_path = os.path.join(BASE, "data", f".browser_state_{domain.replace('.', '_')}.json")
    if not os.path.exists(storage_path):
        print(f"  ⚠ {domain}: 브라우저 상태 없음 — 먼저 extract 실행 필요")
        return False

    print(f"  🔄 {domain}: 헤드리스 토큰 갱신 중...")
    result = extract_tokens(domain, login_url, headless=True)
    if result and result.get("token_a"):
        print(f"  ✅ {domain}: 토큰 갱신 완료")
        return True
    else:
        print(f"  ❌ {domain}: 자동 갱신 실패 — 수동 extract 필요 (세션 만료)")
        return False


# ─── 토큰 → 환경변수/파이프라인 연동 ───

def get_tokens_for_domain(domain):
    """파이프라인에서 호출: domain의 유효한 토큰 반환. 만료 시 자동 갱신 시도."""
    tokens = load_tokens()
    domain_data = tokens.get(domain, {})

    token_a = domain_data.get("token_a", "")
    token_b = domain_data.get("token_b", "")

    # 만료 체크 + 자동 갱신
    if token_a and is_token_expired(token_a):
        print(f"  ⚠ {domain}: token_a 만료 — 자동 갱신 시도")
        if refresh_token_for_domain(domain):
            tokens = load_tokens()
            domain_data = tokens.get(domain, {})
            token_a = domain_data.get("token_a", "")
            token_b = domain_data.get("token_b", "")
        else:
            print(f"  ❌ 자동 갱신 실패 — 이 타겟 스킵")
            return None, None

    return token_a, token_b


# ─── CLI ───

def cmd_status(args):
    """모든 도메인의 토큰 상태 출력"""
    tokens = load_tokens()
    if not tokens:
        print("  저장된 토큰 없음. 먼저 extract 실행:")
        print("  python3 token_manager.py extract --domain api.example.com --login-url https://example.com/login")
        return

    print(f"\n  {'도메인':<30} {'Token A':<20} {'Token B':<20}")
    print(f"  {'─'*70}")
    for domain, data in tokens.items():
        ta = data.get("token_a", "")
        tb = data.get("token_b", "")
        ta_status = token_expiry_str(ta) if ta else "미설정"
        tb_status = token_expiry_str(tb) if tb else "미설정"
        print(f"  {domain:<30} {ta_status:<20} {tb_status:<20}")
    print()


def cmd_extract(args):
    """브라우저로 토큰 추출"""
    extract_tokens(args.domain, args.login_url, headless=False)


def cmd_refresh(args):
    """특정 도메인 토큰 갱신"""
    refresh_token_for_domain(args.domain)


def cmd_refresh_all(args):
    """만료 임박한 모든 토큰 갱신"""
    tokens = load_tokens()
    refreshed = 0
    failed = 0
    for domain, data in tokens.items():
        token_a = data.get("token_a", "")
        if token_a and is_token_expired(token_a, buffer_minutes=60):
            if refresh_token_for_domain(domain):
                refreshed += 1
            else:
                failed += 1
    print(f"\n  갱신 완료: {refreshed}건, 실패: {failed}건")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDOR 토큰 관리자")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("status", help="토큰 상태 확인")

    p_extract = sub.add_parser("extract", help="브라우저로 토큰 추출")
    p_extract.add_argument("--domain", required=True)
    p_extract.add_argument("--login-url", required=True)

    p_refresh = sub.add_parser("refresh", help="토큰 갱신")
    p_refresh.add_argument("--domain", required=True)

    sub.add_parser("refresh-all", help="만료 임박 토큰 전체 갱신")

    args = parser.parse_args()
    if args.cmd == "status":
        cmd_status(args)
    elif args.cmd == "extract":
        cmd_extract(args)
    elif args.cmd == "refresh":
        cmd_refresh(args)
    elif args.cmd == "refresh-all":
        cmd_refresh_all(args)
    else:
        parser.print_help()
