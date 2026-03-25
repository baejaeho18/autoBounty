#!/usr/bin/env bash
# ============================================================
# Track 2: 오픈소스 코드 감사 자동 파이프라인
# 매일 실행 — Clone/Pull → 변경 감지 → SAST → LLM 정밀 분석 → 리포트
# (변경 없는 레포는 자동 스킵)
#
# 방법론 참고:
#   - ch4n3: SAST로 후보 축소 → LLM에 실제 코드 전달 → 정밀 판별
#   - Toss: diff 기반 변경 코드에 집중 → 주변 컨텍스트 포함 → LLM 분석
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="$(dirname "$SCRIPT_DIR")"
TRACK_DIR="$BASE/data/track2"
TARGETS="$BASE/data/targets_oss.json"
CONFIG="$BASE/config.json"
EXTRACT_JSON="$BASE/scripts/extract_json.py"
DATE=$(date +%Y-%m-%d)

mkdir -p "$TRACK_DIR"/{repos,scans,analysis,reports}

log() { echo "[T2 $(date '+%H:%M:%S')] $1"; }

# 타겟 수 확인
TARGET_COUNT=$(python3 -c "
import json
with open('$TARGETS') as f:
    print(len(json.load(f)))
" 2>/dev/null || echo "0")

if [[ "$TARGET_COUNT" == "0" ]]; then
  log "등록된 OSS 타겟 없음 — 종료"
  exit 0
fi

# ─── 타겟 읽기 ───
python3 -c "
import json
with open('$TARGETS') as f:
    targets = json.load(f)
for t in targets:
    print(f\"{t['repo_url']}|{t['name']}|{t.get('language','unknown')}\")
" | while IFS='|' read -r REPO_URL NAME LANG; do

  log "=== $NAME ($LANG) 감사 시작 ==="
  REPO_DIR="$TRACK_DIR/repos/$NAME"
  IS_NEW_CLONE=false
  CHANGED_FILES_PATH="$TRACK_DIR/scans/${NAME}_changed_${DATE}.txt"

  # ──────────────────────────────────────
  # Phase 1: Clone 또는 Pull — 변경 감지
  # ──────────────────────────────────────
  if [[ -d "$REPO_DIR/.git" ]]; then
    log "Phase 1: git pull (기존 레포)"
    PREV_HASH=$(git -C "$REPO_DIR" rev-parse HEAD)
    git -C "$REPO_DIR" pull --quiet 2>/dev/null || {
      log "WARN: git pull 실패 ($NAME)"
      continue
    }
    NEW_HASH=$(git -C "$REPO_DIR" rev-parse HEAD)

    if [[ "$PREV_HASH" == "$NEW_HASH" ]]; then
      log "변경 없음 — $NAME 스킵"
      continue
    fi

    # 변경된 파일 목록
    git -C "$REPO_DIR" diff --name-only "$PREV_HASH" "$NEW_HASH" > "$CHANGED_FILES_PATH"
    CHANGED_COUNT=$(wc -l < "$CHANGED_FILES_PATH")
    log "${CHANGED_COUNT}개 파일 변경 감지"

    # 변경 diff 저장 (Toss 방식: diff 기반 분석)
    git -C "$REPO_DIR" diff "$PREV_HASH" "$NEW_HASH" -- \
      '*.py' '*.js' '*.ts' '*.rb' '*.php' '*.go' '*.java' \
      > "$TRACK_DIR/scans/${NAME}_diff_${DATE}.patch" 2>/dev/null || true
  else
    log "Phase 1: git clone (신규)"
    if ! git clone --depth 100 "$REPO_URL" "$REPO_DIR" 2>/dev/null; then
      log "ERROR: git clone 실패 ($NAME) — 스킵"
      continue
    fi
    IS_NEW_CLONE=true
  fi

  # ──────────────────────────────────────
  # Phase 2: SAST 스캔 (1차 필터) — Semgrep + 의존성
  # ──────────────────────────────────────
  SEMGREP_FILE="$TRACK_DIR/scans/${NAME}_semgrep_${DATE}.json"

  log "Phase 2a: Semgrep 스캔"
  if command -v semgrep &>/dev/null; then
    if semgrep scan --config auto --json \
      -o "$SEMGREP_FILE" \
      "$REPO_DIR" 2>/dev/null; then
      SEMGREP_COUNT=$(python3 -c "
import json
try:
    with open('$SEMGREP_FILE') as f:
        print(len(json.load(f).get('results', [])))
except: print(0)
" 2>/dev/null || echo "0")
      log "Semgrep: ${SEMGREP_COUNT}건 발견"
    else
      log "WARN: Semgrep 스캔 실패"
    fi
  else
    log "WARN: semgrep 미설치 — 스킵"
  fi

  log "Phase 2b: 의존성 CVE 스캔"
  if [[ -f "$REPO_DIR/requirements.txt" ]] && command -v pip-audit &>/dev/null; then
    pip-audit -r "$REPO_DIR/requirements.txt" --format json \
      -o "$TRACK_DIR/scans/${NAME}_deps_${DATE}.json" 2>/dev/null || \
      log "WARN: pip-audit 실패"
  elif [[ -f "$REPO_DIR/package.json" ]]; then
    (cd "$REPO_DIR" && npm audit --json > "$TRACK_DIR/scans/${NAME}_deps_${DATE}.json" 2>/dev/null) || \
      log "WARN: npm audit 실패"
  fi

  # ──────────────────────────────────────
  # Phase 3: SAST 결과 + 실제 코드 → LLM 정밀 판별
  # (ch4n3 방식: Semgrep 결과에 코드 붙여서 TP/FP 판별)
  # ──────────────────────────────────────
  log "Phase 3: SAST → LLM 정밀 분석 (코드 컨텍스트 포함)"

  # Semgrep 결과에서 코드 조각 포함한 상세 정보 추출
  SEMGREP_WITH_CODE=""
  if [[ -f "$SEMGREP_FILE" ]]; then
    SEMGREP_WITH_CODE=$(python3 - "$SEMGREP_FILE" "$REPO_DIR" <<'PYEOF'
import json, sys, os

semgrep_file = sys.argv[1]
repo_dir = sys.argv[2]

try:
    with open(semgrep_file) as f:
        data = json.load(f)
except:
    print("Semgrep 결과 없음")
    sys.exit(0)

results = data.get("results", [])
if not results:
    print("Semgrep 결과 0건")
    sys.exit(0)

output_parts = []
for r in results[:20]:  # 상위 20건만
    sev = r.get("extra", {}).get("severity", "?")
    msg = r.get("extra", {}).get("message", "")
    rule_id = r.get("check_id", "?")
    path = r.get("path", "?")
    start_line = r.get("start", {}).get("line", 0)
    end_line = r.get("end", {}).get("line", 0)

    # 실제 코드 조각 읽기 (전후 5줄 컨텍스트)
    code_snippet = ""
    full_path = path if os.path.isabs(path) else os.path.join(repo_dir, path)
    try:
        with open(full_path) as f:
            lines = f.readlines()
        ctx_start = max(0, start_line - 6)
        ctx_end = min(len(lines), end_line + 5)
        for i in range(ctx_start, ctx_end):
            marker = ">>>" if start_line - 1 <= i <= end_line - 1 else "   "
            code_snippet += f"{marker} {i+1:4d}| {lines[i].rstrip()}\n"
    except:
        code_snippet = "(코드 읽기 실패)"

    output_parts.append(
        f"### [{sev}] {rule_id}\n"
        f"File: {path}:{start_line}-{end_line}\n"
        f"Message: {msg}\n"
        f"```\n{code_snippet}```\n"
    )

print("\n".join(output_parts))
PYEOF
    )
  fi

  SAST_ANALYSIS_FILE="$TRACK_DIR/analysis/${NAME}_sast_${DATE}.json"

  ALLOWED_TOOLS="Read,Grep,Glob,Bash(ls:*),Bash(head:*),Bash(wc:*),Bash(find:*)"

  if [[ -n "$SEMGREP_WITH_CODE" ]] && [[ "$SEMGREP_WITH_CODE" != "Semgrep 결과 0건" ]] && [[ "$SEMGREP_WITH_CODE" != "Semgrep 결과 없음" ]]; then
    log "Phase 3a: Semgrep 결과 TP/FP 판별 (LLM + 코드 직접 읽기)"

    # Semgrep 결과 요약만 프롬프트에 포함, 실제 코드는 Claude가 직접 읽음
    SEMGREP_SUMMARY=$(python3 - "$SEMGREP_FILE" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except:
    print("Semgrep 결과 없음"); sys.exit(0)
results = data.get("results", [])
if not results:
    print("Semgrep 결과 0건"); sys.exit(0)
for r in results[:20]:
    sev = r.get("extra", {}).get("severity", "?")
    rule = r.get("check_id", "?")
    path = r.get("path", "?")
    start = r.get("start", {}).get("line", 0)
    end = r.get("end", {}).get("line", 0)
    msg = r.get("extra", {}).get("message", "")[:100]
    print(f"- [{sev}] {rule} → {path}:{start}-{end} | {msg}")
PYEOF
    )

    claude -p "
당신은 시니어 보안 연구원입니다. $NAME ($LANG) 프로젝트의 보안 감사를 수행합니다.

프로젝트 경로: $REPO_DIR

## Semgrep SAST 스캔 결과 요약:
$SEMGREP_SUMMARY

**지시사항:**
1. 위 Semgrep 결과의 각 파일을 Read 도구로 직접 열어서 전체 코드를 확인하세요
2. 취약점 주변 코드뿐 아니라, import문, 미들웨어, 인증 로직도 확인하세요
3. 함수 호출 체인을 따라가며 외부 입력이 실제로 취약 함수에 도달하는지 추적하세요
4. Grep으로 관련 함수/변수가 다른 파일에서 어떻게 사용되는지 검색하세요

**판별 기준:**
- 프레임워크 기본 보호 (Django CSRF, Rails strong params 등)로 막히면 FP
- 입력이 이미 검증/이스케이프되어 있으면 FP
- 내부 전용 코드이고 외부 입력이 닿지 않으면 FP
- 실제 외부 입력이 검증 없이 위험 함수에 도달하면 TP

최종 결과를 반드시 아래 JSON 형식으로만 출력하세요:
{
  \"project\": \"$NAME\",
  \"date\": \"$DATE\",
  \"sast_triage\": [
    {
      \"rule_id\": \"Semgrep 룰 ID\",
      \"file\": \"파일:라인\",
      \"verdict\": \"TP 또는 FP\",
      \"confidence\": \"HIGH/MEDIUM/LOW\",
      \"severity\": \"CRITICAL/HIGH/MEDIUM/LOW\",
      \"reasoning\": \"판별 근거 (어떤 파일의 어떤 코드를 확인했는지 포함)\",
      \"attack_scenario\": \"TP일 때만: 구체적 공격 시나리오\",
      \"poc\": \"TP일 때만: PoC 코드/curl\"
    }
  ]
}
" --allowedTools "$ALLOWED_TOOLS" 2>/dev/null | python3 "$EXTRACT_JSON" > "$SAST_ANALYSIS_FILE"
  fi

  # ──────────────────────────────────────
  # Phase 4: Diff 기반 변경 코드 분석
  # (Toss 방식: 변경된 코드에 집중, 주변 컨텍스트 포함)
  # ──────────────────────────────────────
  DIFF_ANALYSIS_FILE="$TRACK_DIR/analysis/${NAME}_diff_${DATE}.json"
  DIFF_FILE="$TRACK_DIR/scans/${NAME}_diff_${DATE}.patch"

  if [[ "$IS_NEW_CLONE" == "false" ]] && [[ -f "$DIFF_FILE" ]] && [[ -s "$DIFF_FILE" ]]; then
    log "Phase 4: Diff 기반 변경 코드 보안 분석"

    # 변경된 파일 목록만 추출 (코드는 Claude가 직접 읽음)
    CHANGED_LIST=$(cat "$CHANGED_FILES_PATH" | head -50)

    claude -p "
당신은 시니어 보안 연구원입니다. $NAME ($LANG) 프로젝트에 새 코드가 커밋되었습니다.

프로젝트 경로: $REPO_DIR
변경 diff 파일: $DIFF_FILE

## 변경된 파일 목록:
$CHANGED_LIST

**지시사항:**
1. Read 도구로 diff 파일($DIFF_FILE)을 읽어서 변경 내용을 파악하세요
2. 보안 관련 변경이 있는 파일은 Read로 전체 파일을 읽어 컨텍스트를 확인하세요
3. Grep으로 인증/인가 미들웨어, 입력 검증 로직을 검색하세요
   - 예: Grep으로 'auth', 'middleware', 'permission', 'sanitize' 등 검색
4. 변경된 함수가 호출되는 다른 파일도 추적하세요

**분석 포커스:**
1. 새로 추가된 엔드포인트에 인증/인가 누락
2. 새 입력 처리 코드에서 검증 누락 (SQLi, XSS, SSTI, 커맨드 인젝션)
3. 기존 보안 로직이 변경되면서 우회 가능해진 경우
4. 새 파일 업로드/다운로드 로직의 검증 부재
5. 시크릿/키 하드코딩

중요: 변경 전에도 있던 기존 문제는 제외. 이번 변경으로 새로 도입된 것만.

최종 결과를 반드시 아래 JSON 형식으로만 출력하세요:
{
  \"project\": \"$NAME\",
  \"date\": \"$DATE\",
  \"diff_findings\": [
    {
      \"type\": \"취약점 유형\",
      \"severity\": \"CRITICAL/HIGH/MEDIUM/LOW\",
      \"file\": \"파일:라인\",
      \"introduced_in\": \"어떤 변경에서 도입됐는지\",
      \"description\": \"상세 설명 (어떤 파일의 어떤 코드를 확인했는지 포함)\",
      \"vulnerable_code\": \"취약한 코드 라인 (실제 코드에서 인용)\",
      \"poc_scenario\": \"PoC 시나리오\",
      \"fix_suggestion\": \"수정 제안\"
    }
  ]
}
" --allowedTools "$ALLOWED_TOOLS" 2>/dev/null | python3 "$EXTRACT_JSON" > "$DIFF_ANALYSIS_FILE"

  elif [[ "$IS_NEW_CLONE" == "true" ]]; then
    log "Phase 4: 신규 레포 — 전체 보안 관련 코드 분석 (LLM 직접 탐색)"

    claude -p "
당신은 시니어 보안 연구원입니다. $NAME ($LANG) 프로젝트를 처음 감사합니다.

프로젝트 경로: $REPO_DIR

**지시사항:**
1. Glob으로 프로젝트 구조를 파악하세요 (소스 파일 목록)
2. Grep으로 보안 민감 패턴을 검색하세요:
   - 라우트/엔드포인트 정의: 'route', '@app.', 'router', 'urlpatterns'
   - 인증: 'auth', 'login', 'session', 'token', 'jwt'
   - 위험 함수: 'exec', 'eval', 'system', 'subprocess', 'raw(', 'serialize'
   - DB: 'query', 'execute', 'cursor', 'raw_sql', 'format('
   - 파일: 'upload', 'download', 'open(', 'write('
3. 발견된 보안 민감 파일을 Read로 전체 읽어서 분석하세요
4. 인증 미들웨어 설정 파일도 확인하세요
5. 함수 호출 체인을 따라가며 외부 입력이 위험 함수에 도달하는지 추적하세요

**분석 포커스:**
1. 인증 미들웨어 없이 노출된 엔드포인트 (CRITICAL)
2. 수평/수직 권한 상승 가능 지점 (HIGH)
3. SQL 인젝션, 커맨드 인젝션, SSTI 경로 (HIGH)
4. 레이스 컨디션 가능 지점 (MEDIUM)
5. 파일 업로드/다운로드 검증 우회 (MEDIUM)

중요: 실제 exploit 가능한 취약점만. 프레임워크 기본 보호로 막히는 건 제외.

최종 결과를 반드시 아래 JSON 형식으로만 출력하세요:
{
  \"project\": \"$NAME\",
  \"date\": \"$DATE\",
  \"diff_findings\": [
    {
      \"type\": \"취약점 유형\",
      \"severity\": \"CRITICAL/HIGH/MEDIUM/LOW\",
      \"file\": \"파일:라인\",
      \"introduced_in\": \"initial audit\",
      \"description\": \"상세 설명 (어떤 파일의 어떤 코드를 확인했는지 포함)\",
      \"vulnerable_code\": \"취약한 코드 라인 (실제 코드에서 인용)\",
      \"poc_scenario\": \"PoC 시나리오\",
      \"fix_suggestion\": \"수정 제안\"
    }
  ]
}
" --allowedTools "$ALLOWED_TOOLS" 2>/dev/null | python3 "$EXTRACT_JSON" > "$DIFF_ANALYSIS_FILE"
  fi

  # ──────────────────────────────────────
  # Phase 5: 결과 통합 + 리포트
  # ──────────────────────────────────────
  log "Phase 5: 결과 통합 + 리포트"

  # SAST TP + Diff findings 합치기
  COMBINED_FILE="$TRACK_DIR/analysis/${NAME}_${DATE}.json"

  python3 - "$SAST_ANALYSIS_FILE" "$DIFF_ANALYSIS_FILE" "$NAME" "$DATE" "$COMBINED_FILE" <<'PYEOF'
import json, sys, os

sast_file, diff_file, name, date, output_file = sys.argv[1:6]

findings = []

# SAST TP 결과
if os.path.exists(sast_file):
    try:
        with open(sast_file) as f:
            sast = json.load(f)
        for item in sast.get("sast_triage", []):
            if item.get("verdict") == "TP" and item.get("confidence") in ("HIGH", "MEDIUM"):
                findings.append({
                    "source": "sast_triage",
                    "type": item.get("rule_id", "unknown"),
                    "severity": item.get("severity", "MEDIUM"),
                    "file": item.get("file", "?"),
                    "description": item.get("reasoning", "") + " | " + item.get("attack_scenario", ""),
                    "poc_scenario": item.get("poc", ""),
                    "fix_suggestion": ""
                })
    except:
        pass

# Diff 분석 결과
if os.path.exists(diff_file):
    try:
        with open(diff_file) as f:
            diff_data = json.load(f)
        for item in diff_data.get("diff_findings", []):
            findings.append({
                "source": "diff_analysis",
                "type": item.get("type", "unknown"),
                "severity": item.get("severity", "MEDIUM"),
                "file": item.get("file", "?"),
                "description": item.get("description", ""),
                "poc_scenario": item.get("poc_scenario", ""),
                "fix_suggestion": item.get("fix_suggestion", ""),
                "vulnerable_code": item.get("vulnerable_code", ""),
                "introduced_in": item.get("introduced_in", "")
            })
    except:
        pass

combined = {"project": name, "date": date, "findings": findings}
with open(output_file, "w") as f:
    json.dump(combined, f, indent=2, ensure_ascii=False)
print(f"통합: {len(findings)}건 (SAST TP + Diff)")
PYEOF

  CRIT_HIGH=$(python3 -c "
import json
try:
    with open('$COMBINED_FILE') as f:
        data = json.load(f)
    findings = [f for f in data.get('findings', []) if f.get('severity') in ('CRITICAL', 'HIGH')]
    print(len(findings))
except: print(0)
" 2>/dev/null || echo "0")

  if [[ "$CRIT_HIGH" -gt 0 ]]; then
    log "!! CRITICAL/HIGH $CRIT_HIGH건 — 리포트 초안 생성"

    ANALYSIS=$(cat "$COMBINED_FILE")
    REPORT_FILE="$TRACK_DIR/reports/${NAME}_${DATE}_report.md"

    claude -p "
아래 보안 감사 결과를 바탕으로 Responsible Disclosure 리포트를 작성하세요.
SAST 도구 결과의 LLM 정밀 분석과 코드 변경 diff 분석을 종합한 결과입니다.

$ANALYSIS

형식:
# Security Vulnerability Report: $NAME
## Summary
## Methodology
- SAST scanning (Semgrep) → LLM triage (TP/FP classification)
- Git diff analysis → security-focused code review
## Vulnerability Details (각 HIGH/CRITICAL 건에 대해)
### [제목]
- Source: [sast_triage / diff_analysis]
- Type: [CWE-XXX]
- Severity: [CVSS 3.1 점수]
- File: [파일:라인]
- Description:
- Vulnerable Code:
- Steps to Reproduce:
- Impact:
- Suggested Fix:
## Timeline
- Discovered: $DATE
- Vendor notification: [TBD - 수동]
- Public disclosure: 90 days after vendor notification
" > "$REPORT_FILE" 2>/dev/null

    if [[ -s "$REPORT_FILE" ]]; then
      python3 "$BASE/scripts/add_finding.py" \
        --track "oss" \
        --domain "$NAME" \
        --file "$COMBINED_FILE" \
        --report "$REPORT_FILE"
      log "리포트 저장: $REPORT_FILE"
    else
      log "WARN: 리포트 생성 실패"
    fi
  else
    log "CRITICAL/HIGH 건 없음 — 리포트 스킵"
  fi

  log "=== $NAME 완료 ==="
done

log "Track 2 파이프라인 완료"
