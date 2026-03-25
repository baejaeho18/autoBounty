# autoBounty User Guide

## 목차

- [1. 개요](#1-개요)
- [2. 초기 셋업 (1회)](#2-초기-셋업-1회)
- [3. 타겟 등록](#3-타겟-등록)
- [4. 파이프라인 실행](#4-파이프라인-실행)
- [5. 결과 확인 및 검토](#5-결과-확인-및-검토)
- [6. 수동 재현 및 스크린샷](#6-수동-재현-및-스크린샷)
- [7. 플랫폼 제출](#7-플랫폼-제출)
- [8. CLI 명령어 레퍼런스](#8-cli-명령어-레퍼런스)
- [9. 일일 루틴 요약](#9-일일-루틴-요약)

---

## 1. 개요

autoBounty는 버그 바운티 자동화 파이프라인입니다. 3개 트랙을 병렬로 운영합니다.

| 트랙 | 대상 | 찾는 취약점 | 제출 플랫폼 |
|------|------|------------|------------|
| Track 1 (IDOR) | SaaS API 엔드포인트 | 인가 우회 (IDOR) | HackerOne |
| Track 2 (OSS) | GitHub 오픈소스 웹앱 | SQLi, XSS, SSTI, Auth Bypass, RCE 등 | 프로젝트 Security 채널 |
| Track 3 (Web3) | Solidity 스마트 컨트랙트 | Reentrancy, Access Control, Flash Loan 등 | Immunefi |

### 자동 vs 수동 경계

```
[자동] 스캔 → 분석 → IDOR 자동검증 → 리포트 생성 → Discord 알림
[수동] 타겟 등록 / 재현 확인 / 스크린샷 / 플랫폼 제출
```

---

## 2. 초기 셋업 (1회)

### 2.1 설치 실행

```bash
bash setup.sh
```

setup.sh가 수행하는 작업:
- 디렉토리 구조 생성 (`data/track1~3`, `logs/`)
- 도구 설치 확인 (claude, subfinder, httpx, katana, semgrep, slither)
- cron 등록:
  - 매일 06:00 — 파이프라인 실행 (`orchestrator.sh`)
  - 매주 월 08:00 — 타겟 자동 탐색 (`discover_targets.sh`)
  - 매월 1일 09:00 — 프롬프트 자동 튜닝 (`tune_prompts.sh`)

### 2.2 Claude 로그인 (Claude Max)

Claude API 키 대신 **Claude Max 구독** ($100/월 또는 $200/월)을 사용합니다.
`claude -p` 명령어가 Max 크레딧으로 실행됩니다.

```bash
# Claude Code CLI 설치
npm install -g @anthropic-ai/claude-code

# Max 구독 계정으로 로그인 (1회만 하면 됨)
claude login

# 확인
claude -p "hello"
```

> **로그인은 1회만 하면 됩니다.** 인증 토큰이 `~/.claude/`에 저장되어
> 이후 `claude -p` 호출 및 cron 자동 실행 모두 로그인 없이 동작합니다.
>
> **주의:** `ANTHROPIC_API_KEY` 환경변수가 설정되어 있으면 API 종량제로 과금됩니다.
> Max를 사용하려면 반드시 제거하세요:
> ```bash
> unset ANTHROPIC_API_KEY
> # ~/.bashrc에서도 해당 줄이 있으면 삭제
> ```
>
> **$200/월 플랜 권장** — 5배 사용량 제한으로, 다수 타겟 자동 스캔에 적합합니다.

### 2.3 Discord Webhook 설정

**Discord Webhook 만드는 방법:**
1. Discord 서버에서 채널 우클릭 → 채널 편집
2. 연동 → 웹후크 → 새 웹후크
3. 웹후크 URL 복사
4. `config.json`을 열어 `YOUR_DISCORD_WEBHOOK_URL`을 복사한 URL로 교체:

```bash
# config.json 수정
vi config.json
# "discord_webhook": "https://discord.com/api/webhooks/..." 으로 변경
```

### 2.3 플랫폼 가입

**HackerOne** (Track 1, 2):
1. https://hackerone.com/users/sign_up 접속
2. 이메일/비밀번호로 가입
3. 프로필에 간단한 소개 작성 (신뢰도 향상)

**Immunefi** (Track 3):
1. https://immunefi.com 접속
2. MetaMask 등 지갑 연결로 가입

### 2.4 도구 설치 확인

```bash
# 각 도구가 설치되어 있는지 확인
which subfinder httpx katana semgrep slither claude
```

미설치 도구가 있어도 해당 트랙이 graceful하게 스킵됩니다.
필요한 트랙만 `config.json`에서 `"enabled": true`로 설정하세요.

---

## 3. 타겟 등록

### 3.1 타겟 자동 탐색 (추천 목록 생성)

```bash
# 수동 실행 (또는 매주 월 08:00 cron 자동)
bash scripts/discover_targets.sh
```

결과 파일 확인:

```bash
cat data/discovered_$(date +%Y-%m-%d).json
```

출력 예시:
```json
[
  {
    "type": "idor",
    "name": "example-saas",
    "domain": "api.example.com",
    "program_url": "https://hackerone.com/example",
    "bounty_range": "$100 - $5,000"
  },
  {
    "type": "oss",
    "name": "cool-project",
    "repo": "https://github.com/org/cool-project",
    "language": "python",
    "stars": 3200
  }
]
```

이 목록은 **추천일 뿐**, 자동 등록되지 않습니다. 아래 기준으로 직접 선별하세요.

### 3.2 좋은 타겟 선별 기준

**IDOR 타겟:**
- Bounty 최소 $100 이상
- API 도메인이 Scope에 포함
- 무료 회원가입 가능한 SaaS
- 중소 규모 (직원 50~500명) — 대형 회사는 경쟁 극심

**OSS 타겟:**
- GitHub Stars 1,000~15,000
- 최근 3개월 내 커밋 활발
- `SECURITY.md` 파일 존재
- 인증/인가 로직이 있는 웹앱 (Django, Express, Rails 등)

**Web3 타겟:**
- Critical 바운티 $10K 이상
- GitHub에 Solidity 코드 공개
- 감사(audit) 이력 1회 이하

### 3.3 타겟 등록 명령어

```bash
# Track 1: IDOR
./bounty add-idor api.example.com https://hackerone.com/example

# Track 2: OSS
./bounty add-oss https://github.com/org/project project python

# Track 3: Web3
./bounty add-web3 https://github.com/org/protocol protocol
```

### 3.4 IDOR 타겟 추가 작업 — 계정 2개 생성 및 토큰 등록

IDOR 테스트는 "User A의 데이터를 User B가 접근할 수 있는지" 확인하므로 계정 2개가 필요합니다.

**Step 1: 타겟 서비스에 계정 2개 생성**

- 계정 A: `testuser_a@gmail.com`
- 계정 B: `testuser_b@gmail.com`

**Step 2: 인증 토큰 추출**

1. 계정 A로 로그인
2. 브라우저에서 F12 (개발자 도구) 열기
3. **Network** 탭 클릭
4. 페이지 이동 (API 요청 발생시킴)
5. API 요청 클릭 (예: `/api/me`, `/api/user`) → **Headers** 탭
6. `Authorization: Bearer eyJhbGci...` 값 전체 복사

```
┌─ Network 탭 ──────────────────────────────────┐
│ Name          Status  Type                     │
│ /api/me       200     fetch   ← 이 요청 클릭   │
│                                                │
│ ▼ Request Headers                              │
│   Authorization: Bearer eyJhbGci...            │
│                   ↑ 이 전체 값을 복사           │
└────────────────────────────────────────────────┘
```

7. 계정 B로도 동일하게 반복

**Step 3: 환경변수 등록**

```bash
echo 'export TARGET1_TOKEN_A="Bearer eyJhbGci..."' >> ~/.bashrc
echo 'export TARGET1_TOKEN_B="Bearer eyJhbGci..."' >> ~/.bashrc
source ~/.bashrc

# 등록 확인
echo $TARGET1_TOKEN_A
echo $TARGET1_TOKEN_B
```

> JWT 토큰은 보통 1~24시간 후 만료됩니다.
> 만료 시 다시 로그인하여 새 토큰으로 교체하세요.
> 장기 API 키를 제공하는 서비스면 그것을 사용하세요.

---

## 4. 파이프라인 실행

### 4.1 즉시 실행

```bash
./bounty run
```

백그라운드에서 3개 트랙이 병렬 실행됩니다. PID가 표시됩니다.

### 4.2 자동 실행 (cron)

setup.sh에서 등록한 cron이 매일 06:00에 자동 실행합니다.

```bash
# cron 등록 확인
crontab -l
```

### 4.3 실행 로그 확인

```bash
# 오늘 로그
./bounty log

# 특정 날짜 로그
./bounty log 2026-03-25
```

---

## 5. 결과 확인 및 검토

### 5.1 대시보드

```bash
./bounty status
```

출력 예시:
```
상태: 유휴 (마지막 실행: 2026-03-25 06:00)

등록 타겟: IDOR 3 | OSS 5 | Web3 2
누적 발견: 총 12 | 대기 3 | 검증 2 | 제출 4 | 보상 2 | 제외 1
```

### 5.2 대기 건 목록

```bash
./bounty list
```

출력 예시:
```
⏳ 검증 대기: 3건

  #    심각도       트랙    타겟                유형                        날짜
  ───  ────────  ──────  ──────────────────  ─────────────────────────    ──────────
  0    CRITICAL  idor    api.example.com     IDOR in /api/users/{id}      2026-03-25
  1    HIGH      oss     django-app          SQL Injection in search      2026-03-25
  2    HIGH      web3    defi-protocol       Reentrancy in withdraw()     2026-03-25
```

여기서 `#` 컬럼의 숫자가 **N**입니다. 이후 명령어에서 이 번호를 사용합니다.

### 5.3 상세 보기

```bash
./bounty show 0
```

리포트 전문, 재현 방법, curl 예시 등이 출력됩니다.
리포트 파일 직접 확인:

```bash
cat data/track1/reports/example.com_2026-03-25_report.md
```

---

## 6. 수동 재현 및 스크린샷

> 스크린샷 자동 촬영 기능은 없습니다. 수동으로 촬영해야 합니다.

### 6.1 curl로 간단 재현 (IDOR)

`./bounty show N`의 리포트에 curl 예시가 포함되어 있습니다:

```bash
# Step 1: User A 토큰으로 정상 요청 → 200 OK 확인
curl -v -H "Authorization: $TARGET1_TOKEN_A" \
  https://api.target.com/api/v1/users/123/profile

# Step 2: User B 토큰으로 같은 요청 → IDOR 확인
curl -v -H "Authorization: $TARGET1_TOKEN_B" \
  https://api.target.com/api/v1/users/123/profile
```

**판정 기준:**
- 둘 다 200 OK + 같은 데이터 반환 → IDOR 확정 → `./bounty verify N`
- Step 2가 401/403 → 정상 차단됨 (거짓양성) → `./bounty reject N`

### 6.2 Burp Suite로 정밀 재현

1. **Burp Suite Community Edition** 실행
2. Proxy → Intercept → Open Browser
3. 계정 A로 로그인 → 페이지 탐색
4. **HTTP History**에서 API 요청 우클릭 → **Send to Repeater**
5. Repeater에서 `Authorization` 헤더를 계정 B 토큰으로 교체
6. **Send** → 응답 확인

### 6.3 스크린샷 촬영 방법

버그 바운티 리포트에는 재현 증거 스크린샷이 필요합니다.
아래 절차로 촬영하세요.

#### 방법 1: 브라우저 개발자 도구 (간단한 경우)

1. F12 → Network 탭 열기
2. 취약한 API 요청 실행
3. 요청 클릭 → Response 탭에서 데이터 확인
4. **스크린샷 단축키:**
   - Windows: `Win + Shift + S` (영역 선택)
   - Mac: `Cmd + Shift + 4` (영역 선택)
   - Linux: `gnome-screenshot -a` 또는 `flameshot gui`

**필요한 스크린샷 목록:**
- (1) User A 토큰으로 요청 → 200 OK + 데이터 반환
- (2) User B 토큰으로 같은 요청 → 200 OK + 같은 데이터 (IDOR 증거)
- (3) 두 요청의 Authorization 헤더가 다름을 보여주는 화면

#### 방법 2: Burp Suite (권장)

1. Repeater 탭에서 Request/Response 모두 보이게 설정
2. **User A 요청 + 응답** 화면 스크린샷
3. Authorization 헤더를 User B로 교체
4. **User B 요청 + 응답** 화면 스크린샷

> Burp Suite에서 우클릭 → "Copy to clipboard" 로 요청/응답 텍스트를 복사할 수도 있습니다.

#### 방법 3: curl 출력 저장 (텍스트 증거)

```bash
# 요청 + 응답 헤더 + 본문을 파일로 저장
curl -v -H "Authorization: $TARGET1_TOKEN_A" \
  https://api.target.com/api/v1/users/123/profile \
  2>&1 | tee evidence_user_a.txt

curl -v -H "Authorization: $TARGET1_TOKEN_B" \
  https://api.target.com/api/v1/users/123/profile \
  2>&1 | tee evidence_user_b.txt
```

이 텍스트 파일을 리포트에 첨부하거나, 터미널 화면을 스크린샷으로 촬영합니다.

#### 방법 4: 터미널 녹화 (asciinema)

```bash
# 설치
pip install asciinema

# 녹화 시작
asciinema rec evidence.cast

# ... curl 명령어 실행 ...

# 녹화 종료: Ctrl+D 또는 exit
```

녹화 파일 링크를 리포트에 첨부할 수 있습니다.

### 6.4 OSS/Web3 트랙 재현

**OSS (Track 2):**
- 리포트에 PoC 코드나 재현 절차가 포함됨
- 로컬에서 해당 프로젝트를 clone → 취약 코드 직접 확인
- 가능하면 Docker로 로컬 실행 후 exploit 시도

**Web3 (Track 3):**
- 리포트에 Foundry 테스트 코드가 포함됨
- 실행 방법:
```bash
cd data/track3/repos/protocol-name
forge test --match-test testExploit -vvvv --fork-url https://eth-mainnet.alchemyapi.io/v2/YOUR_KEY
```

---

## 7. 플랫폼 제출

### 7.1 HackerOne 제출 (Track 1, 2)

1. `./bounty show N`으로 리포트 내용 확인
2. HackerOne에서 해당 프로그램 페이지 접속
3. **Submit Report** 클릭
4. 항목 입력:
   - **Title**: 리포트 제목 (예: "IDOR allows user B to access user A's profile via /api/users/{id}")
   - **Vulnerability Type**: 드롭다운에서 선택 (예: Insecure Direct Object Reference)
   - **Severity**: 리포트에 CVSS 점수 포함되어 있음 → 해당 점수로 설정
   - **Description**: 리포트 본문 복사/붙여넣기
   - **Impact**: 리포트의 impact 섹션 복사
   - **Steps to Reproduce**: 리포트의 재현 절차 복사
   - **Attachments**: 스크린샷 파일 첨부
5. **Submit Report** 클릭

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
   - **Impact**: 예상 피해액 (리포트에 `estimated_impact_usd` 포함)
4. 제출

제출 완료 후:
```bash
./bounty submit N
```

### 7.3 바운티 수령 기록

플랫폼에서 바운티 지급이 확인되면:

```bash
./bounty paid N
```

---

## 8. CLI 명령어 레퍼런스

| 명령어 | 설명 | 예시 |
|--------|------|------|
| `./bounty run` | 파이프라인 즉시 실행 | `./bounty run` |
| `./bounty status` | 대시보드 | `./bounty status` |
| `./bounty log [DATE]` | 실행 로그 | `./bounty log 2026-03-25` |
| `./bounty list` | 검증 대기 건 목록 | `./bounty list` |
| `./bounty show N` | N번 건 상세 + 리포트 | `./bounty show 0` |
| `./bounty verify N` | 재현 성공 → 검증 완료 | `./bounty verify 0` |
| `./bounty reject N` | 거짓양성 → 제거 | `./bounty reject 0` |
| `./bounty submit N` | 플랫폼 제출 완료 기록 | `./bounty submit 0` |
| `./bounty paid N` | 바운티 수령 기록 | `./bounty paid 0` |
| `./bounty add` | 타겟 추가 가이드 | `./bounty add` |
| `./bounty add-idor` | IDOR 타겟 추가 | `./bounty add-idor api.ex.com https://hackerone.com/ex` |
| `./bounty add-oss` | OSS 타겟 추가 | `./bounty add-oss https://github.com/o/p proj python` |
| `./bounty add-web3` | Web3 타겟 추가 | `./bounty add-web3 https://github.com/o/p proto` |
| `./bounty help` | 도움말 | `./bounty help` |

### 발견 건 상태 흐름

```
pending_review → verified → submitted → paid
      ↓
   rejected
```

---

## 9. 일일 루틴 요약

### 매일 (~10분)

```bash
# 1. 상태 확인 (또는 Discord 알림 확인)
./bounty status

# 2. 새 발견 건이 있으면
./bounty list
./bounty show 0

# 3. curl/Burp로 재현 시도 + 스크린샷 촬영

# 4. 판정
./bounty verify 0    # 재현 성공
./bounty reject 0    # 거짓양성

# 5. 검증된 건 플랫폼 제출
#    → HackerOne/Immunefi에 리포트 복붙 + 스크린샷 첨부
./bounty submit 0

# 6. 바운티 수령 시
./bounty paid 0
```

### 매주 (~20분)

```bash
# 새 타겟 추천 확인
cat data/discovered_$(date +%Y-%m-%d).json

# 좋은 타겟 등록
./bounty add-idor ...
./bounty add-oss ...

# IDOR 타겟이면: 계정 생성 + 토큰 등록
```

### 매월

- 토큰 만료 확인 및 갱신
- `./bounty status`로 성과 리뷰
- 성과가 낮은 타겟 제거, 새 타겟 추가
