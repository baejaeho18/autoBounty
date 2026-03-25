# ReDoS Vulnerability Scanner

Google OSS VRP 대상 레포지토리에서 ReDoS(Regular Expression Denial of Service) 취약점을 자동으로 탐지하는 시스템.

## 파이프라인

```
═══ Pass 1: 정적 분석 (LLM 불필요, 전체 실행) ═══

  레포 목록 가져오기 (Google Bug Hunters)
          ↓
    65개 레포 Clone/Pull
          ↓
    정적 ReDoS 분석 (redos_scanner.py)
    - 중첩 수량자: (a+)+
    - 겹치는 대안: (\d|\w)+
    - Star height ≥ 2: (.*)*
    - 경험적 백트래킹 검증
          ↓
    CRITICAL/HIGH 발견 레포 → LLM 대기열에 등록

═══ Pass 2: LLM 정밀 분석 (토큰 소진 시 대기 후 재시도) ═══

    LLM 정밀 분석 (TP/FP 판별)
    - 외부 입력 도달 여부 추적
    - RE2 사용 여부 확인
    - 입력 길이 제한 확인
          ↓
    ❌ 토큰 소진? → 리셋 시간까지 대기 → 재시도
    ✅ 성공? → 리포트 생성 → commit & push → Discord 알림
          ↓
    ⏳ 수동 검증 (review.py)
```

## 빠른 시작

```bash
# 1. 레포 목록 가져오기 + 전체 파이프라인 실행
bash scripts/track4_redos.sh

# 2. 진행 상황 확인 (스캔 중에도 실행 가능)
python3 scripts/status.py              # 전체 진행률
python3 scripts/status.py --detail     # 프로젝트별 현황 테이블
python3 scripts/status.py --findings   # 발견사항 + 리포트 위치 + 검증 방법
python3 scripts/status.py -p angular_angular  # 특정 프로젝트 상세

# 3. 발견사항 검토
python3 scripts/review.py             # 대기 중인 건 목록
python3 scripts/review.py --show 0    # 상세 보기
python3 scripts/review.py --verify 0  # 수동 검증 완료 처리
python3 scripts/review.py --stats     # 전체 통계

# 매일 자동 실행 (cron)
bash scripts/orchestrator.sh
```

## 토큰 소진 대응

LLM (Claude) 질의 중 토큰 한도에 도달하면:
1. 정적 분석은 이미 전부 완료된 상태 (Pass 1)
2. 현재까지 완료된 LLM 분석 결과는 보존
3. 토큰 리셋 시간(기본 60분)까지 자동 대기
4. 리셋 후 미완료 프로젝트부터 자동 재시도 (최대 5회)

환경변수로 조정 가능:
```bash
TOKEN_RESET_WAIT_MIN=60  # 리셋 대기 시간 (분)
MAX_LLM_RETRIES=5        # 최대 재시도 횟수
```

## Discord 알림

취약점 발견 시 Discord로 실시간 알림이 전송됩니다:
- 리포트 요약 (프로젝트명, 심각도, 발견 건수)
- 취약한 파일의 GitHub 링크 (라인 번호 포함)
- 리포트 전문 GitHub 링크

설정: `config.json` → `general.notification.discord_webhook`

## 자동화 흐름

리포트가 생성되면 자동으로:
1. `data/track4/reports/` 에 저장
2. git commit & push → GitHub에 리포트 업로드
3. Discord 웹훅으로 요약 + GitHub 링크 전송
4. `findings.json`에 발견사항 등록 → `review.py`로 검토 가능

## 지원 언어

| 언어 | 추출 패턴 |
|------|----------|
| Python | `re.compile()`, `re.match()`, `re.search()` 등 |
| JavaScript/TypeScript | `new RegExp()`, `/pattern/flags` |
| Java | `Pattern.compile()`, `.matches()` |
| Go | `regexp.Compile()`, `regexp.MustCompile()` |
| PHP | `preg_match()`, `preg_replace()` |
| Ruby | `Regexp.new()`, `/pattern/` |
| Dart | `RegExp()` |
| Rust | `Regex::new()` |
| C++ | `std::regex()`, `RE2()` |

## 대상 레포지토리

[Google Bug Hunters OSS VRP](https://github.com/google/bughunters/tree/main/oss-repository-tier)에서 자동 수집.
총 65개 GitHub 레포 (TIER_OT0 26개, TIER_OT1 40개).

## 디렉토리 구조

```
autoBounty/
├── config.json                 # 설정 (Discord 웹훅 포함)
├── scripts/
│   ├── orchestrator.sh         # cron 진입점
│   ├── track4_redos.sh         # ReDoS 파이프라인 (스캔→리포트→push→알림)
│   ├── fetch_oss_repos.py      # 레포 목록 수집
│   ├── redos_scanner.py        # ReDoS 정적 분석 엔진
│   ├── notify_discord.py       # Discord 웹훅 알림 (리포트 요약 + GitHub 링크)
│   ├── status.py               # 진행 상황 모니터
│   ├── extract_json.py         # Claude JSON 출력 파서
│   ├── add_finding.py          # 발견사항 DB 추가
│   ├── aggregate_notify.py     # 일일 결과 취합 + 알림
│   └── review.py               # 수동 검토 CLI
├── data/
│   ├── targets_oss.json        # 대상 레포 목록
│   ├── findings.json           # 발견사항 DB
│   └── track4/
│       ├── repos/              # 클론된 레포 (.gitignore)
│       ├── scans/              # 정적 분석 결과 (.gitignore)
│       ├── analysis/           # LLM 분석 결과 (.gitignore)
│       └── reports/            # 리포트 (git 추적됨, push됨)
└── logs/                       # 실행 로그
```

## 주의사항

- 반드시 허가된 버그 바운티 스코프 내에서만 테스트
- Google OSS VRP 프로그램 규칙 준수
- False positive가 있으므로 수동 검증 필수
- 리포트 제출 전 반드시 직접 재현 확인
