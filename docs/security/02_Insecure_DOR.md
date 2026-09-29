# 02. Insecure DOR (IDOR) / 접근 제어 실습

> 브랜치: `feature/access-control-demo`
> 대상 코드: `com.basic.myspringboot.vuln.idor` 패키지 (교육용, 격리됨)
> 관련 교재: 10장 Insecure DOR

---

## 1. 개념 요약과 학습 목표

**IDOR(Insecure Direct Object Reference)** 는 **로그인은 되어 있지만**, 요청한 리소스가 "내 것인지"를 서버가 검사하지 않아, 경로변수 `{id}` 만 바꾸면 **남의 데이터에 접근**되는 취약점이다. (넓게는 Broken Access Control)

- **인증(Authentication)** = "너 누구야?" (로그인)
- **인가/접근제어(Authorization)** = "이걸 볼 권한이 있어?" (소유권·역할)
- IDOR은 **인증은 통과했지만 인가(소유권 검사)가 빠진** 경우다.

**학습 목표**
- SQLi와 달리, 로그인한 정상 사용자가 **URL의 `{id}` 만 바꿔** 남의 정보를 보는 과정을 이해한다.
- 방어는 **객체 수준 인가(본인/관리자 확인)** 임을 코드로 확인한다.

---

## 2. 취약점이 생기는 지점

`IdorDemoService`:

```java
// 🔴 취약 : 소유권 검사가 없다. 로그인만 되어 있으면 임의의 {id} 조회 가능
public ProfileResponse getProfileVulnerable(Long id) {
    UserInfo target = findOrThrow(id);   // 요청자와 무관하게 그냥 조회
    return ProfileResponse.from(target);
}

// 🟢 안전 : 본인 또는 관리자만 허용
public ProfileResponse getProfileSecure(Long id, UserInfoUserDetails me) {
    boolean isAdmin = me.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    boolean isOwner = id.equals(me.getUserInfo().getId());
    if (!isAdmin && !isOwner) {
        throw new AccessDeniedException("본인 또는 관리자만 조회할 수 있습니다"); // 403
    }
    return ProfileResponse.from(findOrThrow(id));
}
```

> **핵심**: 취약 코드는 "누가 요청했는지"를 보지 않는다. 안전 코드는 **요청자(`me`)와 대상(`id`)을 대조**한다.

---

## 3. 엔드포인트

| 용도 | 메서드 | URL | 인증 |
|---|---|---|---|
| 🔴 취약 조회 | GET | `/api/idor/profiles/{id}` | 필요 |
| 🟢 안전 조회 | GET | `/api/idor/profiles-safe/{id}` | 필요 |

> 이 경로는 `/api/**` 규칙에 따라 **JWT 인증이 필요**하다. (IDOR은 "로그인 후 남의 것 접근"이라 인증이 전제되어야 의미가 있다.)

시드 계정: `admin@aa.com`(id=1, ROLE_ADMIN) / `user@aa.com`(id=2, ROLE_USER)

---

## 4. 실습 단계

### 4-1. 일반 사용자로 로그인해 토큰 획득

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/userinfos/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@aa.com","password":"pwd2"}' \
  | sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p')
```

### 4-2. 🔴 IDOR: 남(admin, id=1)의 프로필 조회

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/idor/profiles/1
```
결과 — 일반 사용자인데 **admin 정보가 그대로 노출**된다:
```json
{"id":1,"name":"adminboot","email":"admin@aa.com","roles":"ROLE_ADMIN,ROLE_USER"}
```
→ `{id}` 를 2, 3... 으로 바꾸면 전체 사용자를 열람할 수 있다(IDOR).

### 4-3. 🟢 안전: 남의 것 조회 시도 → 403

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/idor/profiles-safe/1
```
```json
{"statusCode":403,"message":"본인 또는 관리자만 조회할 수 있습니다", ...}
```

### 4-4. 🟢 안전: 본인(id=2) 조회 → 200

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/idor/profiles-safe/2
```
```json
{"id":2,"name":"userboot","email":"user@aa.com","roles":"ROLE_USER"}
```

---

## 5. 실제 앱과의 연결 (중요)

이 데모는 실제 앱의 취약점과 동일한 구조다. **`/api/users`** 의 `UserRestController`·`UserServiceController` 에는 메서드 인가가 없어, 아무 `ROLE_USER` 나 다음을 할 수 있다:

- `GET /api/users/{id}` — 남의 정보 조회
- `PATCH /api/users/{id}` — 남의 정보 수정
- `DELETE /api/users/{id}` — 남의 계정 삭제

반면 `StudentController` 는 쓰기 작업에 `@PreAuthorize("hasAuthority('ROLE_ADMIN')")` 를 적용해 보호한다. → 접근 제어의 **일관성**이 중요하다.

---

## 6. 방어 정리

| 방법 | 설명 |
|---|---|
| **객체 수준 인가** | 요청자와 리소스 소유자를 대조(본인/관리자만 허용) — 가장 근본적 |
| **함수 수준 인가** | `@PreAuthorize`, `@Secured` 로 역할 검사. 예: `@PreAuthorize("hasRole('ADMIN') or #id == principal.userInfo.id")` |
| 기본 거부(Deny by default) | 명시적으로 허용하지 않은 접근은 막는다 |
| 예측 불가 식별자 | 순차 증가 ID 대신 UUID 등으로 열거(enumeration) 난이도를 높인다(보조) |
| 최소 노출 | 응답 DTO로 필요한 필드만 반환(비밀번호 등 제외) |

> 근본 방어는 **"인증 != 인가"** 를 분리해 생각하고, 리소스마다 소유권/역할을 검사하는 것이다.
