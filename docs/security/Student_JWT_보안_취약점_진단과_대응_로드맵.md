# SpringBoot 백엔드보안 개요

> 대상: Student_JWT (Spring Boot 3.4.5 / Thymeleaf 세션 + REST JWT)
> 기준 브랜치: **`main`** (어떤 보안 조치도 아직 적용되지 않은 베이스라인)
> 목적: `main`에 실재하는 취약점을 한눈에 정리하고, 각 취약점을 어떤 브랜치에서 어떤 공격·방어 시나리오로 다루는지 안내한다.

---

## 0. 이 문서를 읽는 법

`main`은 교육용으로 **일부러 아무 보안 조치도 적용하지 않은 상태**로 유지된다. 실제 조치(취약 코드 → 공격 → 보안 코드 → 재공격 막기)는 `feature/*-demo` 브랜치에 하나씩 누적되어 있다.

```
sqli-demo → access-control-demo → logging-hardening → csrf-demo
→ jwt-security-demo → jwt-advanced-demo → xss-demo
→ deserialization-demo → security-misconfig-demo
```

각 브랜치는 **이전 브랜치를 모두 포함**하므로, 체인 뒤로 갈수록 더 많은 주제가 "조치된" 상태로 누적된다. 하나씩 순서대로 `git checkout`하면서 같은 공격이 막히는 과정을 직접 확인하면 된다. 브랜치별 상세 실습은 각 문서(`01_SQL_Injection.md` ~ `09_Security_Misconfiguration.md`)를 참고.

---

## 1. OWASP Top 10 2025 전체 지도

| # | 카테고리 | 한 줄 설명 | Student_JWT 데모 |
|---|---|---|---|
| 1 | 접근 제어 실패 (Broken Access Control) | id 등을 바꿔 남의 것에 접근. SSRF가 2025년에 이 항목으로 흡수됨 | ✅ IDOR, CSRF(넓게) |
| 2 | 보안 설정 오류 (Security Misconfiguration) | 기본값·불필요 기능·오류 노출 등 설정 실수. **2021년 5위 → 2025년 2위로 상승** | ✅ Actuator 노출 |
| 3 | 소프트웨어 공급망 실패 (Supply Chain Failures) — **2025 신규** | 외부 라이브러리·빌드 도구 오염이 그대로 전파 | 🟡 개념만 (`03_Supply_Chain_SBOM.md`, 코드 데모 없음) |
| 4 | 암호화 실패 (Cryptographic Failures) | 민감정보 암호화 미흡. 2021년 2위 → 2025년 4위로 하락 | 🟡 부분 — BCrypt 비밀번호 저장, JWT secret 하드닝 |
| 5 | 인젝션 (Injection) | 입력값이 "명령"으로 실행됨 (SQL·XSS 등 통합). 2021년 3위 → 2025년 5위로 하락 | ✅ SQL Injection, XSS |
| 6 | 안전하지 않은 설계 (Insecure Design) | 구현 버그가 아니라 설계 자체의 결함 | ❌ Small (Mass Assignment 패턴) |
| 7 | 인증 실패 (Authentication Failures) | 신원 확인 실패로 계정 탈취 (2021년 "식별 및 인증 실패"에서 개명) | ✅ JWT 보안 |
| 8 | 무결성 실패 (Integrity Failures) | 검증 없이 코드·데이터가 변조됨 | ✅ 역직렬화 무결성 |
| 9 | 로깅·경보 실패 (Logging & Alerting Failures) | 공격의 기록·감지·대응 실패 (2021년 "보안 로깅·모니터링 실패"에서 개명) | ✅ 감사 로깅 |
| 10 | 예외 상황 처리 미흡 (Mishandling of Exceptional Conditions) — **2025 신규** | 오류 상황에서 안전하지 않게 무너짐 | ✅ fail-closed 예외 처리 |

> 2025년판의 핵심 변화: 신규 2개(#3, #10), SSRF가 #1에 흡수, "보안 설정 오류"가 5→2위로 급상승, "암호화 실패"는 2→4위로 하락. 전체 10개 중 **7개는 이미 데모 완료**, 1개는 부분 대응, 2개는 Small 상태다. 상세는 `OWASP_Top10_2025_한글요약.md` 참고.

---

## 2. `main`에 현재 존재하는 취약점 (전수 정리)

> 아래는 모두 **아직 `main`에 적용된 조치가 없는** 현재 상태 기준이다.

### 🔴 HIGH

**① 접근 제어 실패 / IDOR — `/api/users/**`**
`UserRestController`·`UserServiceController`에 메서드 인가(`@PreAuthorize`)가 전혀 없다. `SecurityConfig`는 `/api/**`에 "인증만" 요구하므로, 로그인한 어떤 `ROLE_USER`든 다른 사용자의 정보를 `GET`/`PATCH`/`DELETE`할 수 있다. 같은 앱의 `StudentController`는 쓰기 작업에 `@PreAuthorize`를 적용해 뒀는데, 이 둘의 불일치 자체가 "접근 제어는 전역 정책이 아니라 리소스마다 챙겨야 한다"는 교훈이다.

**② CSRF + 상태변경 GET**
폼 로그인(세션) 체인의 CSRF 보호가 꺼져 있다(`csrf.disable()`). 게다가 `UserController`에 `@GetMapping("/delete/{id}")`처럼 **GET으로 상태를 바꾸는** 엔드포인트가 남아 있어, `<img>` 태그 한 줄로도 삭제가 트리거된다.

**③ SQL Injection — `/api/vuln/sqli/**`**
교육용 취약 엔드포인트가 JdbcTemplate과 JPA 네이티브 쿼리 양쪽 모두에서 문자열 결합으로 쿼리를 만든다(`"...WHERE name LIKE '%" + name + "%'"`). JPA도 메서드 이름 기반 Query Method는 안전하지만, 네이티브 쿼리를 문자열로 조합해 생성하는 메서드는 위험하다.

### 🟡 MEDIUM

**④ 로깅·경보 실패**
로그인 성공/실패, 401/403 같은 감사(audit) 대상 이벤트에 대한 로그가 없다. 사고가 나도 "언제·누가·어디서" 시도했는지 추적할 수 없다.

**⑤ 예외 처리 미흡**
500 에러 발생 시 `e.getMessage()`가 응답 본문에 그대로 노출된다. SQL 구조, 내부 클래스명 같은 정보가 공격자에게 새 나간다.

**⑥ JWT 보안**
`jwt.secret`이 `application.properties`에 평문 하드코딩되어 있다(환경변수 override는 가능하지만 강제되지 않음). 토큰의 subject가 **email(개인정보)** 이라 탈취한 토큰을 디코딩만 해도 계정이 식별된다. 로그아웃·Refresh Token 메커니즘이 없어 한 번 탈취된 토큰은 만료(60분)까지 계속 유효하다.

**⑦ XSS (Stored)**
`User.name`에 길이·특수문자 제한이 없고, 취약 화면(`index-vuln.html`)이 `th:utext`(이스케이프 없음)로 렌더링한다. 회원가입 이름에 스크립트를 저장하면 그 화면을 보는 모든 사용자(관리자 포함)에게 실행된다.

**⑧ 역직렬화 무결성 실패**
앱에는 결제 시 할인 쿠폰을 적용하는 기능이 있는데, 서버가 쿠폰(`Voucher`) 객체를 Java 직렬화 후 Base64로 클라이언트에 내려주고, 결제 확인 시 그 값을 재검증 없이 그대로 신뢰한다. `int` 필드는 직렬화 스트림에 고정 4바이트로 박히므로, 그 바이트만 바꿔치기하면 할인율을 조작할 수 있다.

**⑨ 보안 설정 오류 (잠재적)**
`SecurityConfig`에 `/actuator/**` 전용 규칙이 없어 `anyRequest().permitAll()`로 빠진다. 지금은 Actuator 노출 범위가 기본값(`health`만)이라 드러나지 않지만, 누군가 디버깅 편의로 `management.endpoints.web.exposure.include=*`를 추가하는 순간 — 흔히 일어나는 실수다 — `/actuator/env`로 **모든 설정값(jwt.secret 포함)이 평문으로** 열린다.

### ⚪ Small (LOW 또는 예정)

**⑩ Mass Assignment / 엔티티 직접 바인딩**
`UserRestController`가 `@RequestBody User`를 직접 바인딩하고, 엔티티를 그대로 응답에도 반환한다. 지금은 `User` 엔티티에 password/role이 없어 영향이 제한적이지만, 패턴 자체가 위험해서(다른 엔티티에 적용되는 순간 권한 상승으로 이어짐) 데모 브랜치가 아직 없다.

**⑪ 약한 비밀번호 & 소스 노출**
시드 계정 비밀번호 `pwd1`/`pwd2`가 `UserInfoInsertRunner`에 평문 하드코딩되어 있고, 비밀번호 정책도 없다. (단, DB에 **저장**되는 값은 BCrypt 해시라 이 항목과는 별개로 안전하다 — "소스 코드에 하드코딩된 초기값"과 "DB 저장"은 다른 문제다.)

**공급망 보안 (개념만)**
코드 취약점과는 별개로 의존성/공급망 위험(알려진 CVE, SBOM)도 OWASP #3(2025 신설)에 해당한다. `03_Supply_Chain_SBOM.md`에 개념만 정리되어 있고 코드 데모는 없다.

---

## 3. 순서대로 봐야 할 브랜치 가이드

항목별 구체적인 공격·방어 시나리오는 각 브랜치의 `01_SQL_Injection.md` ~ `09_Security_Misconfiguration.md` 문서에 이미 단계별로 정리되어 있다. 여기서는 어떤 순서로 브랜치를 체크아웃하며 살펴보면 되는지만 정리한다.

1. **`feature/sqli-demo`** — SQL Injection (OWASP #5). 문자열 결합 쿼리의 위험과 파라미터 바인딩 방어를 다룬다. → `01_SQL_Injection.md`
2. **`feature/access-control-demo`** — 접근 제어 실패 / IDOR (OWASP #1). 소유권 검사 없는 조회의 위험과 객체 수준 인가를 다룬다. → `02_Insecure_DOR.md`
3. **`feature/logging-hardening`** — 로깅·경보 실패 + 예외 처리 (OWASP #9, #10). 감사 로깅과 fail-closed 예외 처리를 다룬다. → `04_Logging_Hardening.md`
4. **`feature/csrf-demo`** — CSRF + 상태변경 GET (OWASP #1, 넓게). 세션 기반 요청 위조와 CSRF 토큰 방어를 다룬다. → `05_CSRF.md`
5. **`feature/jwt-security-demo`(1단계)** — JWT secret 하드닝 (OWASP #7, #4). secret 하드코딩 위조 공격과 fail-closed 방어를 다룬다. → `06_JWT_Security.md`
6. **`feature/jwt-advanced-demo`(2단계)** — JWT PII 제거 + Refresh 토큰 (OWASP #7, #4). subject uuid화와 Refresh 토큰 회전을 다룬다. → `06_JWT_Security.md`
7. **`feature/xss-demo`** — XSS 저장형 (OWASP #5). 이스케이프 여부에 따른 실행 차이를 다룬다. → `07_XSS.md`
8. **`feature/deserialization-demo`** — 역직렬화 무결성 실패 (OWASP #8). 바이트 변조 공격과 서명 검증 방어를 다룬다. → `08_Insecure_Deserialization.md`
9. **`feature/security-misconfig-demo`** — 보안 설정 오류 (OWASP #2). Actuator 노출 범위 축소와 인증 가드를 다룬다. → `09_Security_Misconfiguration.md`

---

## 4. 요약 표

| 순서 | 취약점 | OWASP | 대응 브랜치 | 상태 |
|---|---|---|---|---|
| 1 | SQL Injection | #5 | `feature/sqli-demo` | 브랜치에서 조치 가능 |
| 2 | 접근 제어 실패 / IDOR | #1 | `feature/access-control-demo` | 브랜치에서 조치 가능 |
| 3 | CSRF + GET 삭제 | #1(넓게) | `feature/csrf-demo` | 브랜치에서 조치 가능 |
| 4 | JWT 보안 (secret/PII/무효화) | #7, #4 | `feature/jwt-security-demo` → `jwt-advanced-demo` | 브랜치에서 조치 가능 |
| 5 | XSS (Stored) | #5 | `feature/xss-demo` | 브랜치에서 조치 가능 |
| 6 | 역직렬화 무결성 실패 | #8 | `feature/deserialization-demo` | 브랜치에서 조치 가능 |
| 7 | 로깅·경보 실패 + 예외 처리 | #9, #10 | `feature/logging-hardening` | 브랜치에서 조치 가능 |
| 8 | 보안 설정 오류 (Actuator) | #2 | `feature/security-misconfig-demo` | 브랜치에서 조치 가능 |
| 9 | Mass Assignment | #6 | (예정, 브랜치 없음) | ⏳ Small |
| 10 | 약한 비밀번호 & 소스 노출 | #7 | (예정, 브랜치 없음) | ⏳ Small |
| — | 공급망/SBOM | #3 | — | 🟡 개념 문서만 (`03_Supply_Chain_SBOM.md`) |

---

## 5. 관련 문서
- `00_App_Security_Review.md` — 브랜치 기준 진행 현황 추적 (각 feature 브랜치에 존재)
- `OWASP_Top10_2025_한글요약.md` — OWASP Top 10 2025 전체 설명과 매핑표
- `01_SQL_Injection.md` ~ `09_Security_Misconfiguration.md` — 항목별 상세 실습 문서 (각 feature 브랜치에 존재)
