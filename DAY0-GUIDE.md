# Day 0: 오늘 바로 실행하는 가이드

## 지금부터 2시간 안에 3개 트랙 전부 가동시키는 절차

---

## Step 1: 도구 설치 (20분)

```bash
# Claude Code (필수 — 이미 있으면 스킵)
npm install -g @anthropic-ai/claude-code

# Go 도구 일괄 (recon용)
# Go가 없으면: https://go.dev/dl/ 에서 먼저 설치
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Python 도구
pip3 install semgrep pip-audit slither-analyzer

# Foundry (Web3용)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Burp Suite Community — 수동 다운로드
# https://portswigger.net/burp/communitydownload
```

## Step 2: Autopilot 설치 (2분)

```bash
cd ~
tar xzf bounty-autopilot.tar.gz   # 다운받은 파일
cd bounty-autopilot
bash setup.sh
```

## Step 3: 플랫폼 가입 (10분)

| 순서 | 플랫폼 | 가입 | 소요 |
|------|--------|------|------|
| 1 | HackerOne | hackerone.com/users/sign_up | 3분 |
| 2 | Bugcrowd | bugcrowd.com/user/sign_up | 3분 |
| 3 | Immunefi | immunefi.com (지갑 연결) | 4분 |

## Step 4: 타겟 등록 — 이게 핵심 (30분)

### Track 1: IDOR 타겟 선정법

HackerOne에서 다음 순서로 필터링:

1. hackerone.com/bug-bounty-programs 접속
2. 필터: "Bounty" + "API" 검색
3. 정렬: "Newest" (최신 등록순)
4. 다음 조건 체크:
   - ✅ 바운티 최소 $100+
   - ✅ API (*.api.example.com) 가 스코프에 포함
   - ✅ 무료 회원가입 가능한 SaaS
   - ✅ Managed 프로그램 (응답 보장)
   - ❌ Google, Meta 등 대형 → 패스 (경쟁 극심)

좋은 타겟 카테고리:
- 핀테크 SaaS (결제, 인보이스, 급여)
- 프로젝트 관리 도구
- CRM / 마케팅 자동화
- 헬스테크 플랫폼
- EdTech 플랫폼

```bash
# 타겟을 찾았으면 등록
python3 scripts/add_target.py idor \
  --domain api.target1.com \
  --program https://hackerone.com/target1

python3 scripts/add_target.py idor \
  --domain api.target2.com \
  --program https://hackerone.com/target2

python3 scripts/add_target.py idor \
  --domain api.target3.com \
  --program https://hackerone.com/target3
```

⚠️ 각 타겟에 테스트 계정 2개를 만들어서 토큰을 환경변수에 저장:
```bash
export TARGET1_TOKEN_A="Bearer eyJ..."
export TARGET1_TOKEN_B="Bearer eyJ..."
```

### Track 2: OSS 타겟 선정법

GitHub에서 찾는 공식:

```
# GitHub 검색 쿼리 (브라우저에서)
stars:1000..10000 language:python topic:web pushed:>2025-09-01

# 또는 Claude Code에서:
claude -p "GitHub에서 Stars 1000~10000, Python 웹앱,
최근 6개월 내 커밋 활발하고, SECURITY.md가 있는
프로젝트 10개를 찾아서 이름과 URL을 알려줘"
```

좋은 OSS 타겟 패턴:
- Django/Flask 기반 SaaS (인증 복잡)
- Node.js Express API 서버
- Ruby on Rails 앱
- 셀프 호스팅 가능한 오픈소스 (Gitea, Outline, Chatwoot 등)

```bash
python3 scripts/add_target.py oss \
  --repo https://github.com/org/project1 \
  --name project1 --lang python

python3 scripts/add_target.py oss \
  --repo https://github.com/org/project2 \
  --name project2 --lang javascript

python3 scripts/add_target.py oss \
  --repo https://github.com/org/project3 \
  --name project3 --lang ruby
```

### Track 3: Web3 타겟 선정법

Immunefi에서 필터링:

1. immunefi.com/bug-bounty 접속
2. 필터: "Web/App" + "Smart Contract"
3. 정렬: 최신순
4. 조건:
   - ✅ Critical 바운티 $10K+
   - ✅ GitHub에 코드 공개
   - ✅ 감사 이력 1회 이하 (취약점 남아있을 확률 ↑)
   - ✅ TVL $1M+ (너무 작으면 보상 불확실)

```bash
python3 scripts/add_target.py web3 \
  --repo https://github.com/org/protocol1 \
  --name protocol1

python3 scripts/add_target.py web3 \
  --repo https://github.com/org/protocol2 \
  --name protocol2
```

## Step 5: 첫 실행 (30분)

```bash
# 전체 파이프라인 수동 실행
cd ~/bounty-autopilot
bash scripts/orchestrator.sh

# 실시간 로그 확인 (다른 터미널에서)
tail -f logs/$(date +%Y-%m-%d)-orchestrator.log
tail -f logs/$(date +%Y-%m-%d)-track1.log
tail -f logs/$(date +%Y-%m-%d)-track2.log
tail -f logs/$(date +%Y-%m-%d)-track3.log
```

## Step 6: 결과 확인 + 첫 리뷰 (20분)

```bash
# 대기 건 목록
python3 scripts/review.py

# 상세 보기
python3 scripts/review.py --show 0

# 리포트 전문 확인
cat data/track1/reports/*.md
cat data/track2/reports/*.md
cat data/track3/reports/*.md

# 통계
python3 scripts/review.py --stats
```

## Step 7: Discord 알림 설정 (선택, 5분)

1. Discord 서버에서 채널 설정 → 연동 → 웹후크 → 새 웹후크
2. URL 복사

```bash
# config.json 편집
nano ~/bounty-autopilot/config.json
# "discord_webhook": "YOUR_DISCORD_WEBHOOK_URL" 부분에 URL 붙여넣기
```

이제 매일 아침 Discord로 알림이 옵니다.

---

## 이후 일상 루틴 (하루 10~20분)

### 아침 (알림 확인)
- Discord 알림 확인
- `python3 review.py` 로 새 발견 확인

### 발견 건이 있을 때
1. `python3 review.py --show N` 으로 리포트 읽기
2. Burp Suite로 직접 재현 시도
   - 성공 → `python3 review.py --verify N`
   - 실패 → `python3 review.py --reject N`
3. 검증된 건: HackerOne/Immunefi에 리포트 제출
   - `python3 review.py --submit N`
4. 바운티 수령 시:
   - `python3 review.py --paid N`

### 주 1회 (15분)
- 새 타겟 추가 (HackerOne 신규 프로그램 확인)
- `python3 review.py --stats` 로 성과 확인
- 로그 확인: `ls -la logs/`

---

## 스케일링 전략

### 1개월 후
- 타겟 수: 3개 → 10개로 확대
- false positive 패턴 학습 → 프롬프트 개선
- 첫 바운티 수령 목표

### 3개월 후
- 타겟 수: 10개 → 30개
- 커스텀 Semgrep 룰 축적
- HackerOne 프로필 + reputation 쌓임 → private 프로그램 초대

### 6개월 후
- VPS에서 24/7 실행 (DigitalOcean $12/월)
- 타겟 50개+
- Web3 전문화 (바운티 금액 ↑)
- 월 수익 안정화

---

## 비용 정리

| 항목 | 비용 | 비고 |
|------|------|------|
| Claude Code Pro | 월 $20 | claude -p 사용량 포함 |
| VPS (선택) | 월 $12 | 24/7 자동화 시 |
| Burp Suite Community | 무료 | 수동 검증용 |
| 기타 도구 | 전부 무료 | subfinder, httpx 등 |
| **총** | **월 $20~32** | |

첫 IDOR 바운티 하나 ($100~500)로 1년치 비용 커버.
