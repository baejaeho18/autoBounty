# autoBounty User Guide

## 목차

- [1. 개요](#1-개요)
- [2. 초기 셋업 (1회)](#2-초기-셋업-1회)
- [3. 타겟 등록](#3-타겟-등록)
- [4. 파이프라인 실행](#4-파이프라인-실행)
- [5. 결과 확인 및 검토](#5-결과-확인-및-검토)
- [6. 재현 확인 및 스크린샷 (수동)](#6-재현-확인-및-스크린샷-수동)
- [7. 플랫폼 제출 (수동)](#7-플랫폼-제출-수동)
- [8. CLI 명령어 레퍼런스](#8-cli-명령어-레퍼런스)
- [9. 루틴 요약](#9-루틴-요약)

---

## 1. 개요

autoBounty는 버그 바운티 자동화 파이프라인입니다. 3개 트랙을 병렬로 운영합니다.

| 트랙 | 대상 | 찾는 취약점 | 제출 플랫폼 |
|------|------|------------|------------|
| Track 1 (IDOR) | SaaS API 엔드포인트 | 인가 우회 (IDOR) | HackerOne / Bugcrowd |
| Track 2 (OSS) | GitHub 오픈소스 웹앱 | SQLi, XSS, SSTI, Auth Bypass, RCE 등 | 프로젝트 Security 채널 |
| Track 3 (Web3) | Solidity 스마트 컨트랙트 | Reentrancy, Access Control, Flash Loan 등 | Immunefi |

### 자동 vs 수동 경계

| 단계 | 자동? | 비고 |
|------|-------|------|
| 타겟 후보 탐색 | ✅ 자동 | 매주 월 08:00, WebSearch로 HackerOne/Immunefi/GitHub 검색 |
| 타겟 자동 등록 | ✅ 자동 | 선별 기준 충족 시 즉시 `targets_*.json`에 등록 |
| 서브도메인/엔드포인트 수집 | ✅ 자동 | subfinder, httpx, katana |
| 취약점 분석 (SAST, LLM) | ✅ 자동 | semgrep, slither, claude |
| IDOR 검증 (요청 + body 비교) | ✅ 자동 | User A/B 토큰으로 응답 비교 |
| 리포트 생성 | ✅ 자동 | Markdown 리포트 자동 작성 |
| Discord 알림 | ✅ 자동 | HIGH/CRITICAL 발견 시 즉시 알림 |
| JWT 토큰 갱신 | ✅ 자동 | 매일 05:00, 만료 30분 전 자동 갱신 |
| **계정 2개 생성** | ❌ 수동 | CAPTCHA·이메일 인증 등으로 자동화 불가 |
| **최초 토큰 추출** | 🔶 반자동 | `./bounty token-extract` → 브라우저 뜸, 로그인만 하면 됨 |
| **재현 확인 + 스크린샷** | ❌ 수동 | 제출 증거용 스크린샷 |
| **플랫폼 제출** | ❌ 수동 | HackerOne/Immunefi 웹사이트에서 직접 제출 |

---

## 2. 초기 셋업 (1회)

### 2.1 설치 실행

```bash
bash setup.sh
```

setup.sh가 수행하는 작업:
- 디렉토리 구조 생성 (`data/track1~3`, `logs/`)
- 도구 자동 설치 (Go 1.22, subfinder, httpx, katana, semgrep, slither, playwright)
- cron 등록:
  - 매일 05:00 — IDOR 토큰 자동 갱신 (`token_manager.py refresh-all`)
  - 매일 06:00 — 파이프라인 실행 (`orchestrator.sh`)
  - 매주 월 08:00 — 타겟 자동 탐색 + 등록 (`discover_targets.sh`)
  - 매월 1일 09:00 — 프롬프트 자동 튜닝 (`tune_prompts.sh`)
- 첫 실행 시 타겟 후보 즉시 탐색 (백그라운드)

### 2.2 Claude 로그인 (1회)

Claude Max 구독($100/월 또는 $200/월)을 사용합니다.
`claude -p` 명령어가 Max 크레딧으로 실행됩니다.

```bash
# Max 구독 계정으로 로그인 (1회만)
claude login

# 확인
claude -p "hello"
```

> **로그인은 1회만 하면 됩니다.** 인증 토큰이 `~/.claude/`에 저장되어
> 이후 cron 자동 실행도 로그인 없이 동작합니다.
>
> **주의:** `ANTHROPIC_API_KEY` 환경변수가 있으면 API 종량제로 과금됩니다.
> Max를 사용하려면 반드시 제거하세요:
> ```bash
> unset ANTHROPIC_API_KEY
> # ~/.bashrc에서도 해당 줄 삭제
> ```
>
> **$200/월 플랜 권장** — 5배 사용량으로 다수 타겟 자동 스캔에 적합합니다.

### 2.3 Discord Webhook 설정

1. Discord 서버에서 채널 우클릭 → 채널 편집
2. 연동 → 웹후크 → 새 웹후크 → URL 복사
3. `config.json` 수정:

```bash
vi config.json
# "discord_webhook": "https://discord.com/api/webhooks/..." 으로 변경
```

### 2.4 플랫폼 가입

**HackerOne** (Track 1, 2):
1. https://hackerone.com/users/sign_up 접속
2. 이메일/비밀번호로 가입
3. 프로필에 간단한 소개 작성 (신뢰도 향상)

**Immunefi** (Track 3):
1. https://immunefi.com 접속
2. MetaMask 등 지갑 연결로 가입

---

## 3. 타겟 등록

### 3.1 타겟 자동 탐색 + 자동 등록

매주 월요일 08:00에 자동 실행됩니다. 수동으로 즉시 실행하려면:

```bash
bash scripts/discover_targets.sh
```

실행 흐름:
1. WebSearch로 HackerOne/Bugcrowd/Immunefi/GitHub에서 조건 충족 프로그램 탐색
2. 결과를 `data/discovered_YYYY-MM-DD.json`에 저장
3. **선별 기준을 충족하는 타겟을 자동으로 `targets_*.json`에 등록**

탐색 결과 확인:

```bash
cat data/discovered_$(date +%Y-%m-%d).json
```

### 3.2 타겟 선별 기준 (자동 등록 필터)

**IDOR 타겟:**
- Bounty 최소 $50 이상
- API 도메인이 Scope에 포함
- 무료 회원가입 가능한 SaaS

**OSS 타겟:**
- GitHub Stars 1,000~50,000
- 최근 3개월 내 커밋 활발
- `SECURITY.md` 파일 존재
- 인증/인가 로직이 있는 웹앱 (Django, Express, Rails 등)
- attack_surface_score가 MEDIUM 이상

**Web3 타겟:**
- Critical 바운티 $100 이상
- GitHub에 Solidity 코드 공개
- 감사(audit) 이력 1회 이하

### 3.3 수동 타겟 추가 (선택)

자동 탐색 외에 직접 추가할 수도 있습니다:

```bash
# Track 1: IDOR
./bounty add-idor api.example.com https://hackerone.com/example

# Track 2: OSS
./bounty add-oss https://github.com/org/project project python

# Track 3: Web3
./bounty add-web3 https://github.com/org/protocol protocol
```

### 3.4 IDOR 타겟 필수 작업 — 계정 생성 + 최초 토큰 추출

> **이 작업만 수동입니다.** 이후 토큰 갱신은 매일 05:00 자동으로 처리됩니다.

IDOR 테스트는 "User A의 데이터를 User B가 접근할 수 있는지" 확인하므로 계정 2개가 필요합니다.

---

#### Step 1: 타겟 서비스에 계정 2개 직접 생성

브라우저로 해당 서비스에 접속해서 계정을 2개 만드세요.

- 계정 A: `testuser_a@gmail.com`
- 계정 B: `testuser_b@gmail.com`

> 이메일 인증, CAPTCHA, SMS 인증 등은 직접 처리해야 합니다.
> Gmail의 `+` 별칭(`testuser+a@gmail.com`)을 사용하면 같은 받은편지함으로 수신 가능합니다.

---

#### Step 2: 최초 토큰 추출 (반자동 — 로그인만 하면 됨)

```bash
./bounty token-extract api.example.com https://example.com/login
```

실행하면:
1. Chromium 브라우저가 자동으로 열립니다
2. 로그인 페이지에서 **계정 A로 로그인**하세요
3. 로그인 완료 후 Authorization 헤더가 자동 캡처됩니다
4. 계정 B도 동일하게 안내에 따라 진행합니다
5. 토큰이 `data/.tokens.json`에 암호화 저장됩니다

> **이후 토큰 갱신은 자동입니다.** JWT 만료 30분 전에 헤드리스 브라우저가 자동으로 갱신합니다.
> 갱신 실패 시 Discord로 알림이 옵니다.

토큰 상태 확인:

```bash
./bounty token
```

출력 예시:
```
  api.example.com
    User A: 유효 (만료까지 18시간)
    User B: 유효 (만료까지 17시간)
```

---

## 4. 파이프라인 실행

### 4.1 즉시 실행

```bash
./bounty run
```

백그라운드에서 3개 트랙이 병렬 실행됩니다.

### 4.2 자동 실행 (cron)

매일 06:00에 자동 실행됩니다.

```bash
# cron 등록 확인
crontab -l
```

### 4.3 실행 로그 확인

```bash
./bounty log              # 오늘 로그
./bounty log 2026-03-25   # 특정 날짜 로그
```

---

## 5. 결과 확인 및 검토

### 5.1 대시보드

```bash
./bounty status
```

출력 예시:
```
═══════════════════════════════════════
  🎯 Bounty Autopilot Dashboard
═══════════════════════════════════════
  상태: ○ 대기 중
  마지막 실행: 2026-03-25

  📊 누적 통계
  ─────────────────────────────────────
  ⏳ 검증 대기      3건  ← 확인 필요!
  ✅ 검증 완료      1건  ← 제출하세요!
  📨 제출 완료      4건
  💰 바운티 수령    2건
  ❌ FP 제거        1건
  ─────────────────────────────────────
  총 11건 | FP율 9%

  🎯 등록된 타겟
  ─────────────────────────────────────
  idor: 7개
  oss: 6개
  web3: 3개
```

### 5.2 대기 건 목록

```bash
./bounty list
```

출력 예시:
```
⏳ 검증 대기: 3건

  #    심각도       트랙    타겟                유형                          날짜
  ───  ────────  ──────  ──────────────────  ───────────────────────────  ──────────
  0    CRITICAL  idor    api.example.com     IDOR in /api/users/{id}      2026-03-25
  1    HIGH      oss     django-app          SQL Injection in search       2026-03-25
  2    HIGH      web3    defi-protocol       Reentrancy in withdraw()      2026-03-25
```

`#` 컬럼의 숫자가 **N**입니다.

### 5.3 상세 보기

```bash
./bounty show 0
```

리포트 전문, 자동 검증 결과, curl 재현 예시 등이 출력됩니다.

**IDOR의 경우 자동 검증 결과가 포함됩니다:**
```
자동 검증: CONFIRMED
  - User A: 200 OK (312 bytes)
  - User B: 200 OK (312 bytes) ← 동일한 body 반환
  - 증거: data/track1/evidence/example.com_idor_verify_2026-03-25.json
```

---

## 6. 재현 확인 및 스크린샷 (수동)

> **이 섹션은 수동 작업입니다.** 플랫폼 제출 시 재현 증거가 필요합니다.

자동 검증이 `CONFIRMED`여도, 플랫폼 제출에는 사람이 직접 확인한 스크린샷이 필요합니다.

### 6.1 IDOR 재현 확인

`./bounty show N`의 리포트에 curl 예시가 포함되어 있습니다:

```bash
# Step 1: User A 토큰으로 정상 요청 → 200 OK 확인
curl -v -H "Authorization: $TOKEN_A" \
  https://api.target.com/api/v1/users/123/profile

# Step 2: User B 토큰으로 같은 요청 → IDOR 확인
curl -v -H "Authorization: $TOKEN_B" \
  https://api.target.com/api/v1/users/123/profile
```

**판정:**
- 둘 다 200 OK + 같은 데이터 반환 → IDOR 확정 → `./bounty verify N`
- Step 2가 401/403 → 정상 차단됨 → `./bounty reject N`

### 6.2 Burp Suite로 정밀 재현 (권장)

1. **Burp Suite Community Edition** 실행
2. Proxy → Intercept → Open Browser
3. 계정 A로 로그인 → 페이지 탐색
4. HTTP History에서 API 요청 우클릭 → **Send to Repeater**
5. Repeater에서 `Authorization` 헤더를 계정 B 토큰으로 교체 → **Send**
6. 응답 확인

### 6.3 스크린샷 촬영

제출에 필요한 스크린샷 3장:

| # | 내용 |
|---|------|
| 1 | User A 토큰으로 요청 → 200 OK + 데이터 반환 |
| 2 | User B 토큰으로 같은 요청 → 200 OK + 같은 데이터 (IDOR 증거) |
| 3 | 두 요청의 Authorization 헤더가 다름을 보여주는 화면 |

**스크린샷 단축키:**
- Linux: `flameshot gui` 또는 `gnome-screenshot -a`
- Mac: `Cmd + Shift + 4`
- Windows: `Win + Shift + S`

**또는 curl 출력을 텍스트로 저장 (스크린샷 대체 가능):**

```bash
curl -v -H "Authorization: $TOKEN_A" \
  https://api.target.com/api/v1/users/123/profile \
  2>&1 | tee evidence_user_a.txt

curl -v -H "Authorization: $TOKEN_B" \
  https://api.target.com/api/v1/users/123/profile \
  2>&1 | tee evidence_user_b.txt
```

### 6.4 OSS/Web3 트랙 재현

**OSS (Track 2):**
- 리포트에 PoC 코드와 재현 절차가 포함됨
- 로컬에서 프로젝트 clone → 취약 코드 직접 확인
- 가능하면 Docker로 로컬 실행 후 exploit 시도

**Web3 (Track 3):**
- 리포트에 Foundry 테스트 코드가 포함됨

```bash
cd data/track3/repos/protocol-name
forge test --match-test testExploit -vvvv \
  --fork-url https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY
```

---

## 7. 플랫폼 제출 (수동)

### 7.1 HackerOne 제출 (Track 1, 2)

1. `./bounty show N`으로 리포트 확인
2. 해당 프로그램 페이지 → **Submit Report**
3. 항목 입력:
   - **Title**: 리포트 제목
   - **Vulnerability Type**: 드롭다운 선택 (예: Insecure Direct Object Reference)
   - **Severity**: 리포트의 CVSS 점수로 설정
   - **Description**: 리포트 본문 복사/붙여넣기
   - **Impact**: 리포트의 impact 섹션 복사
   - **Steps to Reproduce**: 리포트의 재현 절차 복사
   - **Attachments**: 스크린샷 파일 첨부
4. **Submit Report**

제출 완료 후:
```bash
./bounty submit N
```

### 7.2 Immunefi 제출 (Track 3)

1. `./bounty show N`으로 리포트 확인
2. https://immunefi.com → 해당 프로젝트 → **Submit Bug Report**
3. 항목 입력:
   - **Severity**: Critical / High
   - **Description**: 리포트 본문 복사
   - **Proof of Concept**: Foundry 테스트 코드 + 실행 결과 첨부
   - **Impact**: 리포트의 `estimated_impact_usd` 값
4. 제출

제출 완료 후:
```bash
./bounty submit N
```

### 7.3 바운티 수령 기록

```bash
./bounty paid N
```

---

## 8. CLI 명령어 레퍼런스

### 파이프라인

| 명령어 | 설명 |
|--------|------|
| `./bounty run` | 파이프라인 즉시 실행 |
| `./bounty status` | 대시보드 |
| `./bounty log [DATE]` | 실행 로그 |

### 발견 건 관리

| 명령어 | 설명 |
|--------|------|
| `./bounty list` | 검증 대기 건 목록 |
| `./bounty show N` | N번 건 상세 + 리포트 전문 |
| `./bounty verify N` | 재현 성공 → 검증 완료 |
| `./bounty reject N` | 거짓양성 → 제거 |
| `./bounty submit N` | 플랫폼 제출 완료 기록 |
| `./bounty paid N` | 바운티 수령 기록 |

### 타겟 관리

| 명령어 | 설명 |
|--------|------|
| `./bounty add` | 타겟 추가 가이드 |
| `./bounty add-idor [domain] [url]` | IDOR 타겟 수동 추가 |
| `./bounty add-oss [repo] [name] [lang]` | OSS 타겟 수동 추가 |
| `./bounty add-web3 [repo] [name]` | Web3 타겟 수동 추가 |

### 토큰 관리 (IDOR)

| 명령어 | 설명 |
|--------|------|
| `./bounty token` | 전체 토큰 상태 (만료 시간 포함) |
| `./bounty token-extract [domain] [login_url]` | 브라우저로 최초 토큰 추출 |
| `./bounty token-refresh [domain]` | 특정 도메인 토큰 수동 갱신 |
| `./bounty token-refresh` | 전체 토큰 갱신 |

### 발견 건 상태 흐름

```
pending_review → verified → submitted → paid
      ↓
   rejected
```

---

## 9. 루틴 요약

### 매일 (~5분)

Discord 알림 확인 → 새 발견 건이 있으면:

```bash
./bounty list
./bounty show 0

# 리포트 검토 후 판정
./bounty verify 0    # 자동 검증 결과 동의 + 재현 확인
./bounty reject 0    # 거짓양성

# 검증된 건: 스크린샷 촬영 → 플랫폼 제출
./bounty submit 0

# 바운티 수령 시
./bounty paid 0
```

### IDOR 신규 타겟 추가 시 (1회성)

자동 등록된 IDOR 타겟은 토큰이 없어서 테스트가 안 됩니다.
Discord 알림 또는 `./bounty status`에서 토큰 미설정 타겟을 확인하고:

```bash
# 1. 해당 서비스에 계정 2개 직접 생성 (브라우저에서 수동)

# 2. 토큰 추출 (브라우저 뜨면 로그인만 하면 됨)
./bounty token-extract api.example.com https://example.com/login

# 3. 확인
./bounty token
```

### 매주 (자동, 확인만)

월요일 08:00에 자동으로 타겟 탐색 + 등록이 실행됩니다.

```bash
# 새로 등록된 타겟 확인
./bounty status

# IDOR 신규 타겟이 있으면 위 '신규 타겟 추가' 절차 실행
./bounty token
```

### 매월

```bash
./bounty status      # 성과 리뷰
./bounty token       # 토큰 상태 확인 (자동 갱신 실패 여부)
```

- 성과가 낮은 타겟은 `data/targets_*.json`에서 직접 제거
- 새 기준으로 타겟 재탐색: `bash scripts/discover_targets.sh`
