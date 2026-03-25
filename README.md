# ReDoS Vulnerability Scanner

Google OSS VRP 대상 레포지토리에서 ReDoS(Regular Expression Denial of Service) 취약점을 자동으로 탐지하는 시스템.

## 파이프라인

```
레포 목록 가져오기 (Google Bug Hunters)
        ↓
  각 레포 Clone/Pull
        ↓
  정적 ReDoS 분석 (redos_scanner.py)
  - 중첩 수량자: (a+)+
  - 겹치는 대안: (\d|\w)+
  - Star height ≥ 2: (.*)*
  - 경험적 백트래킹 검증
        ↓
  LLM 정밀 분석 (TP/FP 판별)
  - 외부 입력 도달 여부 추적
  - RE2 사용 여부 확인
  - 입력 길이 제한 확인
        ↓
  리포트 생성 (CWE-1333)
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
├── config.json                 # 설정
├── scripts/
│   ├── orchestrator.sh         # cron 진입점
│   ├── track4_redos.sh         # ReDoS 파이프라인
│   ├── fetch_oss_repos.py      # 레포 목록 수집
│   ├── redos_scanner.py        # ReDoS 정적 분석 엔진
│   ├── extract_json.py         # Claude JSON 출력 파서
│   ├── add_finding.py          # 발견사항 DB 추가
│   ├── aggregate_notify.py     # 결과 취합 + 알림
│   └── review.py               # 수동 검토 CLI
├── data/
│   ├── targets_oss.json        # 대상 레포 목록
│   ├── findings.json           # 발견사항 DB
│   └── track4/                 # 스캔 결과
│       ├── repos/              # 클론된 레포
│       ├── scans/              # 정적 분석 결과
│       ├── analysis/           # LLM 분석 결과
│       └── reports/            # 리포트
└── logs/                       # 실행 로그
```

## 주의사항

- 반드시 허가된 버그 바운티 스코프 내에서만 테스트
- Google OSS VRP 프로그램 규칙 준수
- False positive가 있으므로 수동 검증 필수
- 리포트 제출 전 반드시 직접 재현 확인
