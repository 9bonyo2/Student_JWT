# 06. JWT 보안 실습 — 2단계 (uuid + Refresh)

> OWASP Top 10 2025 **#7 인증 실패**, **#4 암호화 실패**
> 브랜치: `feature/jwt-advanced-demo` (**2단계**, `feature/jwt-security-demo`(1단계)에서 분기)
> 대상 코드: `com.basic.myspringboot.security.jwt` + `security.models`(UserInfo·RefreshToken) + `security.service`
>
> **단계 안내**: **1단계(`feature/jwt-security-demo`)** 는 secret 하드닝까지이고 토큰 subject 가 email 이라 **공격이 성공**한다. **이 2단계**는 ① subject 를 **uuid** 로 바꿔 email 위조를 막고(PII 제거), ② **Refresh 토큰**(서버 저장 + 회전)을 추가한다.
>
> **이 문서는 2단계에서 달라진 부분만 다룬다.** JWT 개념, 서명 검증(`verifyWith`), `alg:none`·서명 변조 차단, secret 외부화·기동 시 fail-closed 하드닝 등 **1단계와 공통인 내용은 중복 기술하지 않는다** → `feature/jwt-security-demo` 의 `06_JWT_Security.md` 참고.

---

## 1. 2단계에서 바뀐 것 (요약)

JWT 의 안전은 거의 전부 **secret(서명 키) 관리**에 달려 있다. 아래 4가지 중 **1단계는 #1**, **이 2단계는 #3·#4** 를 다룬다.

| # | 취약점 | 위험 | 방어 | 적용 단계 |
|---|---|---|---|---|
| 1 | secret 약함/공개(소스 하드코딩) | 유출 시 누구나 admin 토큰 위조 | env 분리 + 기동 시 약한 secret 거부(fail-closed) | 1단계 |
| 2 | `alg:none`·서명 변조 | 서명 우회 | `verifyWith()` 로 서명 필수 검증 | 기존 코드(변경 없음) |
| 3 | payload 노출(base64) → **email 등 PII 유출** | 탈취 토큰 디코딩만으로 계정 식별자 확보 | 토큰 subject 를 **email→uuid**(불투명)로, 필터는 uuid 로 조회 | **2단계** ✅ |
| 4 | 탈취 토큰 장기 유효 | 로그아웃·탈취 후에도 만료까지 유효 | **짧은 access + Refresh**(서버 저장·회전·폐기) | **2단계** ✅ |

> HS256 은 같은 secret 으로 서명·검증한다. secret 유출 = 위조 가능이라는 **1단계의 전제는 2단계에도 그대로 남아 있다.** 2단계가 막는 것은 "secret 을 안다고 해서 아무 계정이나 바로 위조할 수 있는가"라는 **공격 범위**의 문제다 — 아래 2장에서 바로 비교한다.

---

## 2. 공격 실습 — 1단계 공격이 2단계에서 왜 무력화되는가 ⭐

> 취약 상태 = `application.properties` 의 기본 secret + `jwt.allow-insecure-secret=true` (secret 유출은 1단계와 동일하게 가정)

1단계의 공격 전제는 단순했다: **"비밀번호 없이, secret + 대상 이메일만 알면 그 계정의 토큰을 영구히 찍어낼 수 있다."** `admin@aa.com` 처럼 **흔히 쓰이는/추측 가능한 이메일**이면 공격자는 그 계정의 토큰을 단 한 번도 본 적 없이도 위조에 성공했다(1단계 문서 §2 참고 — `sub=admin@aa.com` 위조 → `/me` → **200**).

이 2단계 코드(subject=uuid)에 **같은 공격을 그대로** 시도하면:

```bash
B=http://localhost:8080
FT=$(python docs/security/jwt_forge.py admin@aa.com)   # 1단계와 동일한 방식: email 을 sub 에 서명
curl -s -w "\n%{http_code}\n" "$B/api/userinfos/me" -H "Authorization: Bearer $FT"
```

| 단계 | 공격 방식 | 결과 |
|---|---|---|
| 1단계 | `sub=admin@aa.com` 위조 → `/me` | **200** ✅ 공격 성공 (email 로 사용자 조회) |
| 2단계 | **동일한** `sub=admin@aa.com` 위조 → `/me` | **401** ✅ 공격 무력화 (uuid 로 사용자 조회 → 매칭되는 사용자 없음) |

→ secret 이 유출된 사실 자체는 2단계에서도 달라지지 않는다(위조 서명 자체는 여전히 유효하다). 하지만 **토큰에 담긴 값이 더 이상 email 이 아니므로**, 서버는 "그런 uuid 를 가진 사용자가 없다"고 판단해 인증을 거부한다. "이메일을 안다"는 공격자의 유일한 무기가 2단계에서는 쓸모없어진 것 — 이것이 1단계 공격이 2단계에서 무력화되는 핵심이다.

> `jwt_forge.py` 자체의 동작 원리(서명 생성 방식)는 1단계 문서 참고.
> 참고 — `alg:none`·서명 변조·payload base64 노출 같은 공통 공격/개념은 1단계 문서(§3-2, §3-3)에서 이미 다뤘고 이 코드에서도 동일하게 차단된다(변경 없음).

---

## 3. 방어 ① — 토큰 subject 를 email → uuid 로 (PII 제거 + 공격 범위 축소)

> **PII(Personally Identifiable Information, 개인 식별 정보)란?** 특정 개인을 **직접**(이름·주민번호·email·전화번호) 또는 **간접**(생년월일·주소·IP)으로 알아볼 수 있는 정보. **JWT payload 는 암호화가 아니라 base64** 라 누구나 읽을 수 있으므로, 토큰·로그·URL 처럼 노출되기 쉬운 곳에는 **PII 를 넣지 않는 것**이 원칙이다.

payload 는 공개(base64)이므로 **email 같은 PII 를 넣지 않는다.** 로그인에 쓰는 email 대신 **의미 없는 불투명 식별자(`UserInfo.uuid`)** 를 토큰 subject 로 담고, 필터는 그 uuid 로 사용자를 조회한다. 이 변경의 보안 효과는 **PII 비노출**뿐 아니라, 바로 앞 §2 에서 본 것처럼 **"이메일만 알면 위조 가능"이라는 공격 경로를 끊는 것**이다 — uuid 는 어떤 API 응답으로도 클라이언트에 반환되지 않기 때문에, 공격자 입장에서는 "짐작"도 "조회"도 불가능한 값이 된다.

#### 수정 요약 — 한눈에 보기 (7곳)

| 파일 | 구분 | 한 일 |
|---|---|---|
| `UserInfo` | 수정 | `uuid` 컬럼 추가 + `@PrePersist` 로 저장 직전 자동 생성(시드·회원가입 공통) |
| `UserInfoRepository` | 추가 | `findByUuid(uuid)` — uuid 로 사용자 조회 |
| `UserInfoUserDetails` | 수정 | `getUuid()` 추가. `getUsername()`=email 은 유지(기존 코드 보호) |
| `UserInfoUserDetailsService` | 추가 | `loadUserByUuid(uuid)` — JWT 필터 전용(폼 로그인은 email) |
| `JwtService` | 수정 | `generateToken(uuid)`, `extractUsername`→`extractSubject`, `validateToken(token, uuid)` |
| `JwtAuthenticationFilter` | 수정 | email 조회 → **uuid 조회**로 변경 |
| `UserInfoController` | 수정 | 로그인 성공 시 토큰 subject = **uuid** |

> **`@PrePersist` 란?** JPA(Java Persistence API)의 엔티티 생명주기 콜백 애노테이션으로, 해당 엔티티가 DB 에 **처음 저장(INSERT)되기 직전**에 자동 호출된다. `UserInfo` 에 이 콜백으로 uuid 를 채워 넣으면, 회원가입 API 를 통해서든 초기 시드 데이터를 통해서든 — **생성 경로와 무관하게** — 저장되는 모든 사용자 레코드가 빠짐없이 고유 uuid 를 갖게 된다.

#### 핵심 로직 Before → After
> 엔티티·레포·서비스는 **새로 추가된 코드**라 Before 가 없다. 동작이 바뀐 핵심은 아래 2곳이다.

**① 발급 (`UserInfoController`)**
```java
// Before
String token = jwtService.generateToken(userDetails.getUsername());  // subject = email(PII)
// After
String token = jwtService.generateToken(userDetails.getUuid());      // subject = uuid(불투명)
```
**② 검증 (`JwtAuthenticationFilter`)**
```java
// Before
String username = jwtService.extractUsername(token);
UserDetails ud = userDetailsService.loadUserByUsername(username);    // email 로 조회
// After
String uuid = jwtService.extractSubject(token);
UserInfoUserDetails ud = userDetailsService.loadUserByUuid(uuid);    // uuid 로 조회
```

**검증 결과** (test 프로파일, 검증됨):

| 항목 | 결과 |
|---|---|
| 로그인 토큰의 payload | `{"sub":"<uuid>","iat":..,"exp":..}` → **email 없음** ✅ |
| 정상 토큰으로 `/me` | **200** ✅ (uuid 조회로 정상 인증) |
| 1단계 방식 위조(subject=email, secret 서명) | **401** ✅ (uuid 아님 → 사용자 없음) |
| 탈취 경험 없는 계정의 uuid 를 추측해 위조 | (추측 불가능하므로 시도 자체가 무의미) |
| 랜덤 uuid 위조(secret 서명) | **401** ✅ (그런 사용자 없음) |

> 주의: 이는 **payload 최소화**이지 암호화가 아니다. uuid 역시 base64 로 보이므로, 민감정보는 여전히 넣지 않는다. 그리고 uuid 화는 **secret 유출 자체를 막지는 못한다** — "유출된 secret 으로 임의 계정을 위조"하는 **공격 범위**를 좁히는 방어이지, secret 하드닝(1단계)을 대체하지 않는다.

---

## 4. 방어 ② — Refresh 토큰 (서버 저장 + 회전) 🆕 2단계 핵심 구현

### 4-1. 문제: JWT 는 stateless 라 "끌 수" 없다

JWT access 토큰은 서버가 상태를 기억하지 않는 **stateless** 방식이다. 서명만 맞으면 만료 전까지 항상 유효하다고 판단하므로, 다음 상황에서 **서버가 손을 쓸 방법이 없었다(1단계)**:
- 사용자가 **로그아웃**해도, 그 토큰은 만료 시각까지 여전히 유효하다(클라이언트가 버렸을 뿐).
- 토큰이 **탈취**되어도, 만료 전까지는 공격자도 정상 사용자처럼 인증된다.
- 비밀번호를 바꾸거나 계정에 이상이 감지돼도, 이미 발급된 토큰을 **강제로 무효화할 수 없다.**

1단계는 이 문제를 "access 만료를 60분으로 유지"하는 선에서 남겨뒀다 — 탈취되면 최대 60분간 무방비다.

### 4-2. 해결: access 는 짧게, Refresh 로 갱신 + 서버가 통제

- **access**: 평소 API 호출마다 쓰는 단기 JWT. **900초(15분)** 로 단축.
- **refresh**: access 가 만료됐을 때 새 access 를 받기 위한 자격. **JWT 가 아니라 서버 DB 에 저장한 무작위 불투명 문자열**이다 → 서버가 "들고" 있으므로 **조회·폐기·교체**가 가능해진다. 이것이 stateless 한 access 토큰에는 없던 **상태(state)를 서버 쪽에 되살리는 지점**이다.

**동작 흐름**
1. 로그인 → `accessToken`(15분) + `refreshToken`(DB 저장) 함께 발급
2. access 로 평소처럼 API 호출
3. access 만료(15분 경과) → 클라이언트가 `POST /api/userinfos/refresh` 에 refresh 제출
4. 서버가 DB 에서 refresh 유효성 확인 → **새 access + 새 refresh** 발급, **기존 refresh 는 즉시 폐기**(1회용 **회전**)
5. 사용자가 로그아웃 → `POST /api/userinfos/logout` → 서버가 **해당 refresh 를 DB 에서 삭제**(그 순간부터 재사용 불가)

```java
// 회전(RefreshTokenService.rotate): 유효하면 폐기 후 새 토큰 발급
RefreshToken rt = repository.findByToken(presented)
        .orElseThrow(() -> new BadCredentialsException("유효하지 않은 refresh"));
if (rt.getExpiresAt().isBefore(Instant.now())) { repository.delete(rt); throw ...만료; }
repository.delete(rt);          // 1회용 → 즉시 폐기
return issue(rt.getUserUuid()); // 새 refresh 발급(회전)
```

> **참고 — refresh 토큰 수명은 보통 얼마로 두나?** 일반적인 웹 서비스는 **1~4주**(이 앱은 **14일**, `jwt.refresh-expire-seconds`) 정도를 많이 쓰고, 금융 등 고보안 서비스는 **몇 시간~며칠**로 더 짧게, 모바일 앱은 **30~90일** 이상으로 더 길게 두기도 한다. 다만 이 앱의 `rotate()`는 갱신할 때마다 `issue()`를 다시 호출해 만료 시각을 **"지금부터 14일"로 매번 리셋**한다 — 즉 고정 만료가 아니라 **활동 기반(sliding) 만료**다. 사용자가 14일 안에 한 번이라도 쓰면 세션은 사실상 끊기지 않고 계속 연장된다(탈취된 토큰도 공격자가 계속 쓰면 마찬가지로 연장되지만, 회전+재사용 탐지가 이를 어느 정도 상쇄한다). 더 엄격하게 제한하려면 활동과 무관하게 N일 후 무조건 재로그인시키는 **절대 만료**를 sliding 위에 추가로 둘 수 있다(이 앱에는 없음).

### 4-3. 이 구조로 얻는 것 — 구체적 이점

| 이점 | 설명 |
|---|---|
| **탈취 피해 시간 최소화** | access 가 15분짜리라 탈취돼도 **최대 15분**이면 자동으로 무력화된다(1단계는 60분간 무방비). access 를 이렇게 짧게 잡을 수 있는 것 자체가 Refresh 도입의 효과다 — Refresh 없이 access 만 15분이면 사용자가 15분마다 재로그인해야 한다. |
| **로그아웃이 실제로 "끄는" 동작이 된다** | stateless JWT 는 로그아웃해도 토큰이 만료까지 살아있었다(1단계). Refresh 는 서버 DB 에 있으므로 로그아웃 시 **즉시 삭제** → 그 세션은 더 이상 갱신될 수 없다(남은 access 수명만큼만 유효, 최대 15분). |
| **탈취·재사용 탐지의 기반(회전)** | refresh 는 **1회용**이라 쓰는 즉시 폐기되고 새 값으로 교체된다. 만약 공격자가 탈취한 **옛 refresh** 로 갱신을 시도하면 이미 폐기된 값이라 **401**이 난다 — 이 "이미 쓴 토큰이 또 온다"는 신호는 운영에서 **도난 탐지 트리거**로 쓸 수 있다(예: 해당 사용자의 모든 세션 강제 로그아웃). |
| **사용자 경험은 그대로, 보안만 강화** | access 가 짧아져도 Refresh 가 자동으로 갱신해주므로 **사용자는 체감상 로그인 상태가 유지**된다 — "보안 강화 = 불편해진다"는 트레이드오프를 Refresh 가 흡수한다. |
| **향후 세션·기기 관리의 토대** | 서버가 refresh 를 DB 로 들고 있으므로, 이후 "내 모든 기기에서 로그아웃", "의심 기기 강제 로그아웃", "활성 세션 목록 조회" 같은 기능을 **이 테이블 위에 그대로 확장**할 수 있다(이번 2단계 범위에는 없음).

**탈취 시나리오로 보는 Before/After**

| | 1단계 (Refresh 없음) | 2단계 (access 15분 + Refresh) |
|---|---|---|
| 토큰 탈취 후 공격자가 쓸 수 있는 시간 | **최대 60분**(만료까지), 로그아웃해도 무효화 불가 | **최대 15분**(access 만료까지) |
| 사용자가 로그아웃하면? | 탈취된 토큰은 여전히 유효(서버가 모름) | 로그아웃 시 refresh 폐기 → 다음 갱신부터 전면 차단 |
| 탈취된 토큰이 재사용되면? | 서버는 구분할 방법이 없음 | 폐기된 refresh 재사용 시 **401** → 이상 신호로 탐지 가능 |

### 4-4. 추가/변경 코드 (한눈에)

| 파일 | 구분 | 한 일 |
|---|---|---|
| `RefreshToken` | 추가 | 엔티티(token·userUuid·expiresAt). DB 저장 |
| `RefreshTokenRepository` | 추가 | `findByToken` |
| `RefreshTokenService` | 추가 | `issue`(발급)·`rotate`(회전)·`revoke`(폐기) |
| `AuthResponse` / `RefreshRequest` | 수정/추가 | 응답에 `refreshToken` 추가 / 요청 DTO |
| `UserInfoController` | 수정 | 로그인에 refresh 발급 + `/refresh`·`/logout` |
| `SecurityConfig` | 수정 | `/refresh`·`/logout` permitAll |
| `application.properties` | 수정 | `jwt.refresh-expire-seconds` |

**검증 결과** (test 프로파일, 검증됨):

| 단계 | 결과 |
|---|---|
| 로그인 | `accessToken`(JWT) + `refreshToken`(불투명 64자) 발급 ✅ |
| `POST /refresh`(유효 refresh) | 새 access + **새 refresh**(회전, 값 바뀜) ✅ |
| 예전 refresh 재사용 | **401** ✅ (1회용 → 폐기됨, 재사용 탐지 신호) |
| `POST /logout` 후 그 refresh 로 `/refresh` | **401** ✅ (서버에서 폐기) |

### 4-5. 한계와 운영 보강 포인트

refresh 서버 저장은 **JWT 의 stateless 장점을 일부 포기**하는 트레이드오프다(DB 조회가 늘어남). 대신 **무효화(로그아웃·회전·탈취 대응)** 라는, stateless 만으로는 불가능했던 능력을 얻는다. 운영 환경에서는 추가로:
- refresh **원문 대신 해시**를 DB 에 저장(DB 유출 시에도 바로 재사용 불가)
- **재사용 탐지 시 해당 사용자의 모든 refresh 를 일괄 폐기**(§4-3 표의 탐지를 실제 대응으로 연결)
- refresh 발급 기기/IP 를 함께 기록해 이상 패턴 모니터링에 활용
- (보안과 무관한 운영 팁) `expiresAt`(`Instant`, UTC)을 DB 에서 직접 조회하면 로컬 시각보다 이르게 보일 수 있다 — `spring.jpa.properties.hibernate.jdbc.time_zone=Asia/Seoul` 로 KST 기준 표기되도록 맞춰둔다(`application-prod.properties`)

### 4-6. API 요청 한눈에 보기

Refresh 토큰 적용 후 실제 인증 흐름에서 호출하는 API 요청을 정리하면 다음과 같다. (Base URL: `http://localhost:8080`)

**① 로그인 — `POST /api/userinfos/login`**
```
POST http://localhost:8080/api/userinfos/login
Content-Type: application/json

{
  "email": "admin@aa.com",
  "password": "pwd1"
}
```
→ 응답: `accessToken`, `refreshToken`, `tokenType`("Bearer"), `expiresIn`(초), `email`, `name`, `roles`

**② 토큰 갱신 — `POST /api/userinfos/refresh`**
```
POST http://localhost:8080/api/userinfos/refresh
Content-Type: application/json

{
  "refreshToken": "<로그인 응답으로 받은 refreshToken>"
}
```
→ 응답: 새 `accessToken` + 새 `refreshToken`(1회용 **회전**, 값이 바뀜)

**③ 로그아웃 — `POST /api/userinfos/logout`**
```
POST http://localhost:8080/api/userinfos/logout
Content-Type: application/json

{
  "refreshToken": "<폐기할 refreshToken>"
}
```
→ 응답: **204 No Content** (서버가 해당 refresh 를 DB 에서 삭제)

**참고) 인증이 필요한 일반 API 호출 — `GET /api/userinfos/me`**
```
GET http://localhost:8080/api/userinfos/me
Authorization: Bearer <accessToken>
```
→ JSON 본문 없이, accessToken 만 `Authorization` 헤더에 담아 호출한다.

---

## 5. 방어 정리

| 위험 | 방어 | 단계 |
|---|---|---|
| secret 유출 → 위조 | 강한 secret env 관리, 소스에 두지 않기, 기동 시 약한 secret 거부(fail-closed), 로테이션 | 1단계 |
| `alg:none`·서명 변조 | `verifyWith()` 로 서명 필수 검증(이미 적용) | 기존 |
| payload 노출 → 공격 범위 확대 | subject 를 email→**uuid**(불투명)로 교체 → "이메일만 알면 위조" 경로 차단 | **2단계** |
| 탈취 토큰 장기 유효·로그아웃 무력화 | **짧은 access(15분) + Refresh**(서버 저장·회전·로그아웃 폐기) | **2단계** |
| 전송 중 탈취 | **HTTPS/TLS** 필수(평문 금지) | 공통 |

---

## 6. 자주 묻는 질문 (FAQ)

> secret 외부화, fail-closed, 약한 secret 의 기준, git 노출 등 **1단계 공통 FAQ(Q1~Q4, Q7)는 1단계 문서 참고**. 아래는 2단계(uuid·Refresh)에 특화된 질문만 다룬다.

**Q1. PII 가 무엇인가요?**
**개인 식별 정보(Personally Identifiable Information)** — 이름·주민번호·email·전화번호처럼 개인을 알아볼 수 있는 정보다. JWT payload 는 암호화가 아니라 base64 라 누구나 읽으므로 **PII 를 넣지 않는다.** 그래서 이 앱은 토큰 subject 를 **email → uuid**(불투명 식별자)로 바꿨다(§3 참고).

**Q2. access 와 refresh 토큰의 차이는?**
**access** 는 API 호출마다 `Authorization` 헤더로 보내는 **단기 JWT**(권한 증표)다. 자주 노출되므로 **짧게** 둔다. **refresh** 는 access 가 만료됐을 때 **새 access 를 받기 위한 장기 자격**으로, 평소엔 보관만 하고 `/refresh` 호출 때만 쓴다. 이 앱의 refresh 는 **JWT 가 아니라 서버 DB 에 저장한 무작위 값**이라 **폐기(로그아웃)·회전**이 가능하다. 요약: **access=짧고 자주, refresh=길고 가끔·서버가 통제**.

---

## 7. 관련 문서
- **이전 단계**: `feature/jwt-security-demo` (**1단계** — secret 하드닝, email subject라 공격 성공 시연, JWT 개념·`alg:none`·fail-closed FAQ 포함)
- OWASP Top 10 2025 #7 인증, #4 암호화 하드닝 체크리스트
- 접근 제어: `02_Insecure_DOR` (인증 ≠ 인가 — 위조로 인증돼도 인가는 별개)
- 프론트: 토큰 저장 위치(sessionStorage/localStorage)와 XSS 연계는 프론트 보안편에서 다룸
