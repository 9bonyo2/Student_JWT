# 00. 앱 전체 보안 점검 (Student_JWT)

> 대상: Student_JWT (Spring Boot 3.4.5 / Thymeleaf 세션 + REST JWT)
> 목적: 강의용 취약점 데모 대상 식별 및 우선순위화
> 점검일: 2026-09-29

각 항목은 교재 장(章)과 매핑되어 있으며, 이후 브랜치별 데모로 다룬다.

---

## 🔴 HIGH — 우선 조치 권장

### 1. 접근 제어 미흡 / IDOR — `/api/users` (교재 10장) ← 진행 중
- **근거**: `UserRestController`, `UserServiceController`에 메서드 인가(`@PreAuthorize`)가 없음. `SecurityConfig`는 `/api/**`에 "인증만" 요구.
- **영향**: 아무 `ROLE_USER`나 다른 사용자의 User를 조회·수정·삭제 가능
  - `PATCH /api/users/{id}`, `DELETE /api/users/{id}` → 남의 계정 변경/삭제
- **대비**: `StudentController`는 쓰기 작업에 `@PreAuthorize("hasAuthority('ROLE_ADMIN')")` 적용 → 일관성 붕괴
- **데모 브랜치**: `feature/access-control-demo`

### 2. CSRF 비활성화(세션 체인) + 상태변경 GET (교재 13장)
- **근거**: `SecurityConfig`의 폼 로그인 체인에도 `.csrf(csrf -> csrf.disable())`. `UserController`에 `@GetMapping("/delete/{id}")`(GET으로 삭제).
- **영향**: 세션+쿠키 기반 Thymeleaf 폼이 CSRF에 노출. GET 삭제는 `<img src>`만으로 공격 가능.

---

## 🟡 MEDIUM

### 3. JWT 보안 (교재 9장-B)
- 기본 `jwt.secret`이 소스(`application.properties`)에 하드코딩(환경변수 override는 있음) → 유출 시 토큰 위조
- 토큰 무효화(로그아웃)·Refresh Token 부재 → 탈취 토큰이 만료까지 유효
- 참고: `alg:none`은 jjwt 0.12 `verifyWith()`로 이미 차단됨(개념 설명용)

### 4. Mass Assignment / 엔티티 직접 바인딩·반환 (교재 12·15-B장)
- `UserRestController.updateUser(@RequestBody User ...)`가 엔티티 직접 바인딩, `getUserById`가 User 엔티티 직접 반환
- 현재 `User` 엔티티엔 password/role이 없어(자격증명은 별도 `UserInfo`) 영향은 제한적이나, 패턴 자체가 위험(다른 엔티티 적용 시 권한 상승)

### 5. 약한 비밀번호 & 소스 노출 (교재 9장)
- 시드 계정 비밀번호 `pwd1`/`pwd2`가 `UserInfoInsertRunner`에 평문 하드코딩, 비밀번호 정책 없음 (BCrypt 해시 저장은 됨)

---

## 🟢 LOW / 확인·양호

- **`/api/users` 두 컨트롤러 경로 중복** — `UserRestController`·`UserServiceController` 모두 `/api/users` → 혼란·유지보수 위험, 정리 권장
- **CORS** — `allowCredentials=true` + `allowedHeaders="*"` → 운영 시 범위 축소 권장 (origin은 명시되어 양호)
- **XSS** — 현재 템플릿에 `th:utext` 없음 → 양호(데모하려면 별도 추가 필요)
- **`/api/vuln/**` permitAll** — SQLi 교육용(의도됨), 운영 배포 금지

---

## 진행 순서

| 순서 | 항목 | 브랜치 | 상태 |
|---|---|---|---|
| 1 | 접근 제어/IDOR (`/api/users`) | `feature/access-control-demo` | 진행 중 |
| 2 | CSRF (세션 체인 + GET 삭제) | (예정) `feature/csrf-demo` | 대기 |
| 3 | JWT 보안 | (예정) `feature/jwt-security-demo` | 대기 |
| 4 | Mass Assignment / 민감정보 노출 | (예정) | 대기 |
