# 00. 앱 전체 보안 점검 (Student_JWT)

> 대상: Student_JWT (Spring Boot 3.4.5 / Thymeleaf 세션 + REST JWT)
> 목적: 강의용 취약점 데모 대상 식별·우선순위화 및 진행 관리
> 점검일: 2026-09-29 · 갱신일: 2026-10-02
> **이 브랜치(`feature/deserialization-demo`) 기준 진행 상태**로 표기한다(완료 ✅ / 예정 ⏳).

각 항목은 **OWASP Top 10 2025** 카테고리와 매핑하며, 주제별로 **취약/안전 코드 + 실습 문서(md·docx)**로 다룬다. 개념 요약은 `OWASP_Top10_2025_한글요약`(md·docx) 참고.

---

## 🔴 HIGH — 우선 조치

### 1. 접근 제어 미흡 / IDOR — `/api/users` — OWASP #1 ✅ 완료
- **근거**: `UserRestController`, `UserServiceController`에 메서드 인가(`@PreAuthorize`)가 없음. `SecurityConfig`는 `/api/**`에 "인증만" 요구.
- **영향**: 임의의 `ROLE_USER`가 다른 사용자의 User를 조회·수정·삭제 가능 (`PATCH`/`DELETE /api/users/{id}`).
- **대비**: `StudentController`는 쓰기 작업에 `@PreAuthorize("hasAuthority('ROLE_ADMIN')")` 적용 → 일관성 붕괴.
- **핵심**: 인증(누구인가) ≠ 인가(무엇을 할 수 있나).
- **브랜치/문서**: `feature/access-control-demo` · `02_Insecure_DOR.md/.docx`

### 2. CSRF(세션 체인) + 상태변경 GET — OWASP #1(넓게) ✅ 완료
- **근거**: 폼 로그인 체인의 CSRF가 꺼져 있었고, `UserController`에 `@GetMapping("/delete/{id}")`(GET 삭제)가 있었음.
- **영향**: 세션+쿠키 기반 Thymeleaf 폼이 CSRF에 노출. GET 삭제는 `<img src>` 한 줄로 트리거.
- **조치**: 세션 체인 CSRF 활성화(기본값), 삭제를 POST(+`_csrf`)로. 재현용으로 취약 GET 삭제를 별도 유지해 `<img>` 공격을 시연.
- **브랜치/문서**: `feature/csrf-demo` · `05_CSRF.md/.docx` (`csrf_attack.html` 포함)

### 3. SQL Injection — `/api/vuln/**` — OWASP #5(인젝션) ✅ 완료
- **근거**: 교육용 취약 엔드포인트에서 문자열 결합 쿼리(JdbcTemplate) 및 JPA 네이티브 쿼리 사용 → UNION 인젝션으로 타 테이블 정보 탈취 가능.
- **조치**: 파라미터 바인딩(PreparedStatement / `:param`) 안전 버전과 대비 시연.
- **브랜치/문서**: `feature/sqli-demo` · `01_SQL_Injection.md/.docx`

---

## 🟡 MEDIUM

### 4. 로깅·경보 실패 / 예외 처리 미흡 — OWASP #9, #10 ✅ 완료
- **#9**: 인증 실패(401)·접근 거부(403)·비밀번호 변경 등 감사 대상 이벤트에 `[AUDIT]` 로그(출처 IP 포함) 부재 → 추가.
- **#10**: 예외 시 내부 메시지/스택트레이스가 외부로 노출될 수 있음 → 500을 일반 메시지+`traceId`로 fail-closed 처리, catch-all이 표준 MVC 예외(405/404 등)를 삼키지 않도록 교정.
- **브랜치/문서**: `feature/logging-hardening` · `04_Logging_Hardening.md/.docx`

### 5. JWT 보안 — OWASP #7(인증), #4(암호) ✅ 완료 (1·2단계)
- 기본 `jwt.secret`이 소스(`application.properties`)에 하드코딩(환경변수 override는 있음) → **유출 시 admin 토큰 위조 가능**(검증됨).
- 토큰 subject 가 **email(PII)** 이라 탈취 토큰을 디코딩하는 것만으로 계정 식별자가 노출됨(1단계).
- 토큰 무효화(로그아웃)·Refresh Token 부재 → 탈취 토큰이 만료까지 유효(1단계).
- 참고: `alg:none`·서명 변조는 jjwt 0.12 `verifyWith()`로 이미 차단됨(검증됨).
- **조치(1단계)**: 기동 시 약한/기본 secret 감지 → **fail-closed**(`jwt.allow-insecure-secret=false`). 강한 secret은 env 관리.
- **조치(2단계)**: 토큰 subject 를 email → **uuid** 로 변경(PII 제거). 무효화는 **Refresh 토큰**(서버 저장 + 회전)으로 구현하고, 그 효과로 access 만료를 900초(15분)로 단축(1단계는 refresh 가 없어 3600초 유지).
- **브랜치/문서**:
  - 1단계(secret 하드닝) `feature/jwt-security-demo` · `06_JWT_Security.md` (`jwt_forge.py` 포함)
  - 2단계(uuid + Refresh, 1단계에서 분기) `feature/jwt-advanced-demo` · `06_JWT_Security.md`

### 6. Mass Assignment / 엔티티 직접 바인딩·반환 — OWASP #6(설계) ⏳ 예정
- `UserRestController`가 `@RequestBody User` 직접 바인딩, `getUserById`가 User 엔티티 직접 반환.
- 현재 `User` 엔티티엔 password/role이 없어(자격증명은 별도 `UserInfo`) 영향은 제한적이나, 패턴 자체가 위험(다른 엔티티 적용 시 권한 상승) → DTO 분리 권장.

### 7. 약한 비밀번호 & 소스 노출 — OWASP #7
- 시드 계정 비밀번호 `pwd1`/`pwd2`가 `UserInfoInsertRunner`에 평문 하드코딩, 비밀번호 정책 없음 (저장은 BCrypt 해시).

### 8. XSS (Stored) — OWASP #5(인젝션) ✅ 완료
- **근거**: 안전한 `index.html`(`th:text`, 자동 이스케이프)은 원래부터 있었지만, 그 반례(취약 버전)가 없어 "왜 안전한지"를 실제로 보여줄 수 없었다.
- **영향**: `User.name`에 길이·특수문자 제한이 없어 `<script>...</script>` 저장이 가능. 세션 쿠키는 `HttpOnly`라 고전적 탈취는 막히지만, 같은 출처에서 실행되는 스크립트는 피해자 권한으로 즉시 행동(및 CSRF 토큰 탈취)할 수 있다.
- **조치**: CSRF 데모와 동일한 패턴으로 **안전(`/users/index`, `th:text`) · 취약(`/users/index-vuln`, `th:utext`) 핸들러를 나란히** 둬서, 같은 데이터가 렌더링 방식에 따라 이스케이프되는지 실측 비교(검증됨).
- **브랜치/문서**: `feature/xss-demo` · `07_XSS.md/.docx`

### 9. 역직렬화 무결성 실패 (Insecure Deserialization) — OWASP #8(무결성) ✅ 완료
- **근거**: 서버가 클라이언트에게 Java 직렬화된 `Voucher`(쿠폰) 객체를 Base64 로 내려주고, 결제 확인 시 그 토큰을 그대로 돌려받아 역직렬화한다.
- **영향**: `int` 필드(`discountPercent`)는 직렬화 스트림에 고정 4바이트로 들어가므로, Base64 디코딩 후 그 4바이트만 바꿔치기하면 할인율을 조작할 수 있다. 서버가 역직렬화된 값을 재검증 없이 신뢰하면 **전액 할인(공짜 결제)** 까지 가능(검증됨). RCE 가젯체인은 다루지 않음(이 앱엔 해당 라이브러리가 없어 안전하게 재현 불가) — "역직렬화된 필드를 재검증 없이 신뢰"하는 더 보편적인 문제에 집중.
- **조치**: 같은 패턴으로 **취약(`/apply`, 토큰 값 그대로 신뢰) · 안전(`/apply-safe`, `code`로 서버 정책 재조회)** 엔드포인트를 나란히 둬서 바이트 변조 공격과 방어를 실측 비교.
- **브랜치/문서**: `feature/deserialization-demo` · `08_Insecure_Deserialization.md/.docx` (`voucher_tamper.py` 포함)

---

## 🟢 LOW / 확인·양호

- **`/api/users` 경로 중복** — `UserRestController`·`UserServiceController` 모두 `/api/users` → 혼란·유지보수 위험, 정리 권장.
- **CORS** — `allowCredentials=true` + `allowedHeaders="*"` → 운영 시 범위 축소 권장 (origin은 명시되어 양호).
- **`/api/vuln/**` permitAll** — SQLi 교육용(의도됨), 운영 배포 금지.

---

## 공급망 보안 (개념)
- 코드 취약점과 별개로 **의존성/공급망 위험**(알려진 CVE, SBOM)도 다룬다 — OWASP #3 신설(Software Supply Chain Failures).
- **문서**: `03_Supply_Chain_SBOM.md` (개념·SBOM/CycloneDX, 데모 코드 없음)

---

## 진행 현황 (이 브랜치 기준)

| 항목 | OWASP | 브랜치 | 문서 | 상태 |
|---|---|---|---|---|
| SQL Injection | #5 | `feature/sqli-demo` | `01_SQL_Injection` | ✅ 완료 |
| 접근 제어/IDOR | #1 | `feature/access-control-demo` | `02_Insecure_DOR` | ✅ 완료 |
| 로깅·경보 / 예외 처리 | #9, #10 | `feature/logging-hardening` | `04_Logging_Hardening` | ✅ 완료 |
| CSRF (+GET 삭제) | #1 | `feature/csrf-demo` | `05_CSRF` | ✅ 완료 |
| JWT 보안 (1단계: secret 하드닝) | #7, #4 | `feature/jwt-security-demo` | `06_JWT_Security` | ✅ 완료 |
| JWT 보안 (2단계: uuid + Refresh) | #7, #4 | `feature/jwt-advanced-demo` | `06_JWT_Security` | ✅ 완료 |
| XSS (Stored) | #5 | `feature/xss-demo` | `07_XSS` | ✅ 완료 |
| 역직렬화 무결성 실패 | #8 | `feature/deserialization-demo` | `08_Insecure_Deserialization` | ✅ 완료 |
| 공급망/SBOM(개념) | #3 | — | `03_Supply_Chain_SBOM` | ✅ 문서 |
| OWASP Top 10 2025 요약 | 전체 | — | `OWASP_Top10_2025_한글요약` | ✅ 문서 |
| Mass Assignment / 민감정보 노출 | #6 | (예정) | — | ⏳ 예정 |

> 취약점은 브랜치별로 누적되며(`sqli-demo → access-control-demo → logging-hardening → csrf-demo → jwt-security-demo → jwt-advanced-demo → xss-demo → deserialization-demo`), 각 브랜치의 이 문서는 그 시점까지의 완료 상태만 표시한다. `jwt-advanced-demo`는 `jwt-security-demo`(1단계)에서 분기한 2단계로, 같은 JWT 주제의 심화 단계다. `xss-demo`는 `jwt-advanced-demo`에서, `deserialization-demo`는 `xss-demo`에서 분기했다. 모든 취약점 정리 후 `main`에 최종 병합 예정.
