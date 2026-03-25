# Bounty Autopilot

Claude Code 기반 버그 바운티 완전 자동화 시스템.
타겟을 등록하면 매일 자동으로 정찰 → 분석 → 리포트 초안까지 돌아갑니다.

## 자동 vs 수동 경계

```
┌─────────────────────────────────────────────┐
│              완전 자동 (cron)                 │
│                                             │
│  정찰 (subfinder → httpx → katana)          │
│  변경 감지 (서브도메인/엔드포인트 diff)       │
│  코드 스캔 (/security-review, semgrep)       │
│  스마트 컨트랙트 스캔 (slither)              │
│  Claude 심층 분석 (claude -p)                │
│  IDOR 후보 추출                              │
│  리포트 초안 생성                            │
│  findings.json 중복 제거 저장                │
│  Discord 알림                               │
│                                             │
├─────────────── 여기까지 자동 ─────────────────┤
│                                             │
│  ⏳ python3 review.py  ← 이것만 사람이 함    │
│                                             │
│  1. 리포트 확인 (--show N)                   │
│  2. 수동 검증: Burp Suite로 재현             │
│  3. 상태 업데이트 (--verify/--reject N)       │
│  4. HackerOne/Immunefi에 제출               │
│  5. 상태 업데이트 (--submit/--paid N)         │
│                                             │
└─────────────────────────────────────────────┘
```

## 빠른 시작

```bash
# 1. 설치 (1분)
bash setup.sh

# 2. 타겟 등록
python3 scripts/add_target.py idor --domain api.target.com --program https://hackerone.com/target
python3 scripts/add_target.py oss  --repo https://github.com/org/project --lang python
python3 scripts/add_target.py web3 --repo https://github.com/org/protocol

# 3. 수동 테스트 실행 (처음 한 번)
bash scripts/orchestrator.sh

# 4. 결과 확인
python3 scripts/review.py
python3 scripts/review.py --show 0
python3 scripts/review.py --stats

# 이후 매일 06:00에 자동 실행됨 (cron)
```

## 실행 스케줄

3개 트랙 모두 **매일** 실행됩니다. Track 2/3은 git diff로 변경이 감지된 레포만 분석하므로 불필요한 비용이 발생하지 않습니다.

| Track | 실행 주기 | 스킵 조건 |
|-------|----------|-----------|
| Track 1 (IDOR) | 매일 | 엔드포인트 없으면 스킵 |
| Track 2 (OSS) | 매일 | git pull 후 변경 없으면 스킵 |
| Track 3 (Web3) | 매일 | git pull 후 변경 없으면 스킵 |

config.json의 `enabled: false`로 개별 트랙 비활성화 가능.

## 디렉토리 구조

```
~/bounty-autopilot/
├── config.json              # 전체 설정
├── setup.sh                 # 원커맨드 설치
├── scripts/
│   ├── orchestrator.sh      # cron 진입점
│   ├── track1_idor.sh       # IDOR 파이프라인
│   ├── track2_oss.sh        # OSS 감사 파이프라인
│   ├── track3_web3.sh       # Web3 감사 파이프라인
│   ├── add_finding.py       # 발견사항 DB 추가
│   ├── aggregate_notify.py  # 취합 + Discord 알림
│   ├── add_target.py        # 타겟 추가 헬퍼
│   └── review.py            # 수동 검토 CLI ← 유일한 수동 작업
├── data/
│   ├── findings.json        # 중앙 발견사항 DB
│   ├── targets_idor.json    # Track 1 타겟
│   ├── targets_oss.json     # Track 2 타겟
│   ├── targets_web3.json    # Track 3 타겟
│   ├── track1/              # 정찰, 분석, 리포트
│   ├── track2/              # 레포, 스캔, 분석, 리포트
│   └── track3/              # 레포, 스캔, 분석, 리포트
└── logs/                    # 일별 실행 로그
```

## 비용 추정

- Claude Code API: 타겟당 약 $0.5~2 / 실행 (변경 없는 레포는 $0)
- 10개 타겟 × 매일 = 월 $150~600 (실제로는 변경 감지 스킵으로 더 적음)
- 첫 바운티 하나면 충분히 커버됨

## 주요 개선 사항

- 모든 트랙 매일 실행 (변경 감지 기반 자동 스킵으로 비용 절약)
- Claude JSON 출력 안정화 (extract_json.py 후처리)
- Track 1 IDOR 자동 검증 (인증 토큰 2개로 실제 curl 테스트)
- 중복 실행 방지 (lock file)
- config.json 기반 rate limit 적용
- 경로 자동 감지 (어디에 설치해도 동작)

## 주의사항

- 반드시 허가된 버그 바운티 스코프 내에서만 테스트
- 각 프로그램의 Rules of Engagement을 반드시 준수
- False positive rate가 높으므로 (78~86%) 수동 검증 필수
- 리포트 제출 전 반드시 직접 재현 확인
