# 06. JWT 보안 실습 — 2단계 (uuid + Refresh)

> OWASP Top 10 2025 **#7 인증 실패**, **#4 암호화 실패**
> 브랜치: `feature/jwt-advanced-demo` (**2단계**, `feature/jwt-security-demo`(1단계)에서 분기)
> 대상 코드: `com.basic.myspringboot.security.jwt` + `security.models`(UserInfo·RefreshToken) + `security.service`
>
> **단계 안내**: **1단계(`feature/jwt-security-demo`)** 는 secret 하드닝까지이고 토큰 subject 가 email 이라 **공격이 성공**한다. **이 2단계**는 ① subject 를 **uuid** 로 바꿔 email 위조를 막고(PII 제거), ② **Refresh 토큰**(서버 저장 + 회전)을 추가한다.

---

## 1. 개념 요약

**JWT(JSON Web Token)** 는 `header.payload.signature` 세 부분을 `.` 으로 이은 문자열이다(각각 base64url).
- **header**: 알고리즘 등 (예: `{"alg":"HS256"}`)
- **payload**: 클레임 (예: `{"sub":"admin@aa.com","iat":..,"exp":..}`)
- **signature**: header+payload 를 **secret 으로 서명**한 값

**핵심 2가지**
1. **서명 ≠ 암호화**: payload 는 **암호화가 아니라 base64 인코딩**일 뿐이다. 누구나 디코딩해 내용을 볼 수 있다. → **민감정보를 넣지 말 것.**
2. **secret 이 곧 신뢰의 뿌리**: 서버는 "이 토큰이 우리 secret 으로 서명됐는가"만 본다. **secret 이 유출되면 누구나 유효한 토큰(관리자 포함)을 위조**할 수 있다.

> 이 앱은 대칭키 **HS256**(발급·검증이 같은 secret)을 쓴다. 그래서 secret 유출 = 위조 가능.

---

## 2. 이 앱의 JWT 구현 (이미 잘 된 점)

`JwtService` / `JwtAuthenticationFilter`:
- **HS256 + 32바이트 이상 키**, 만료(`exp`) 검증
- 검증은 `Jwts.parser().verifyWith(key).parseSignedClaims(token)` → **서명 불일치·`alg:none`·만료 토큰을 거부**
- 필터는 실패 시 예외를 던지지 않고 **미인증으로 통과**시켜 뒤 단계가 401 응답(fail-safe)
- **권한(roles)을 토큰이 아니라 DB에서 로드**(`loadUserByUsername`) → 토큰을 위조해도 **role 을 자기 마음대로 넣을 수 없다**

```java
// 검증 핵심 (JwtService)
Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
```

**남은 약점 2가지** → 이 문서에서 다룬다.
- secret **기본값이 소스에 하드코딩**(리포지토리에 공개) → 유출 시 위조
- **토큰 무효화(로그아웃·revocation)·Refresh 부재** → 탈취 토큰이 만료까지 유효

### 취약점 → 방어 지도 (요약)

JWT의 안전은 거의 전부 **secret(서명 키) 관리**에 달려 있다. 아래 4가지 중 **이번에 코드를 바꾼 것은 #1 하나**다.

| # | 취약점 | 위험 | 방어 | 이번 작업 |
|---|---|---|---|---|
| 1 | **secret이 약함/공개**(소스 하드코딩) | 유출 시 **누구나 admin 토큰 위조** | ① secret을 **env로 분리**·강하게 ② 기동 시 **약한 secret 거부(fail-closed)** | ✅ **코드 추가** |
| 2 | alg:none·서명 변조 | 서명 우회 | `verifyWith()`로 서명 필수 검증 | 기존 코드(변경 없음) |
| 3 | payload 노출(base64) | **email 등 PII 유출** | 토큰 subject를 **email→uuid**(불투명 식별자)로, 필터는 uuid로 조회 | ✅ **코드 추가** |
| 4 | 탈취 토큰 장기 유효 | 로그아웃·탈취 후에도 유효 | **짧은 만료 + Refresh**(서버 저장·회전·로그아웃 폐기) | ✅ **2단계 코드** |

> HS256은 **같은 secret으로 서명·검증**한다. 그래서 secret 유출 = 위조 가능 → secret 관리가 JWT 보안의 핵심이다.

---

## 3. 공격 실습 (취약 상태)

> 취약 상태 = `application.properties` 의 기본 secret + `jwt.allow-insecure-secret=true`

> ⚠️ **중요 — 이 브랜치는 방어가 누적된다.** HEAD 에는 **4-2(토큰 subject를 uuid로)** 가 이미 적용돼 있다. 그래서 `jwt_forge.py admin@aa.com`(**email** subject)는 현재 코드에서 **401**로 막힌다 — 이것은 버그가 아니라 **4-2 방어가 작동**하는 것이다(= 4-2 표의 "예전 방식 위조 → 401"). 아래 3-1 은 **현재 코드(HEAD) 기준**으로 재현한다. 4-2 적용 *이전*의 email 위조 성공(200)을 그대로 보려면 그 변경 전 커밋에서 실행한다.

### 3-1. Secret 유출 → 토큰 위조 → 관리자 탈취 ⭐

`application.properties` 의 secret 은 `secret.getBytes()` 로 쓰이므로, HMAC 키 = **그 문자열의 UTF-8(ASCII) 바이트**다. 이 값만 알면 공격자가 **비밀번호 없이** 유효한 토큰을 직접 서명할 수 있다. 단, HEAD 에서는 subject 가 **uuid** 이므로 **유효한 uuid** 가 필요하다(토큰을 한 번 가로채거나 로그·DB 에서 얻었다고 가정).

```bash
B=http://localhost:8080
# (1) admin 토큰을 한 번 확보해 그 안의 uuid(sub) 를 읽는다 (토큰 탈취 가정)
RT=$(curl -s -X POST "$B/api/userinfos/login" -H "Content-Type: application/json" \
  -d '{"email":"admin@aa.com","password":"pwd1"}' | python -c "import sys,json;print(json.load(sys.stdin)['accessToken'])")
UUID=$(echo "$RT" | cut -d. -f2 | python -c "import sys,base64,json;s=sys.stdin.read().strip();s+='='*(-len(s)%4);print(json.loads(base64.urlsafe_b64decode(s))['sub'])")
echo "admin uuid = $UUID"
# (2) 알려진 secret + 그 uuid 로 위조 → 비밀번호 없이 admin
FU=$(python docs/security/jwt_forge.py "$UUID")
curl -s -w "\n%{http_code}\n" "$B/api/userinfos/me" -H "Authorization: Bearer $FU"
```
**검증 결과** (test 프로파일, 검증됨):

| 요청 | 결과 |
|---|---|
| 유효 uuid + 알려진 secret 위조 → `/me` | **200** → `{"email":"admin@aa.com","roles":["ROLE_ADMIN",…]}` 🔴 |
| (참고) `jwt_forge.py admin@aa.com`(email) → `/me` | **401** ✅ (4-2 uuid 방어) |

→ **secret 하나로 유효한 토큰을 찍어낼 수 있다.** uuid 하드닝(4-2) 덕분에 "유효한 uuid" 라는 추가 조건이 붙었지만, **근본 원인은 공개된 secret** 이다. (roles 는 DB에서 오므로, admin 의 uuid 로 위조하면 admin 권한을 그대로 획득)

#### `jwt_forge.py` 는 무엇을 하나 (교육용 위조 스크립트)

외부 라이브러리 없이 **표준 라이브러리만으로** JWT 를 직접 서명(위조)한다. 핵심은 "서버와 똑같은 방식으로 서명 키를 만드는 것"이다.

```python
# 서버의 jwt.secret 과 동일한 문자열. 서버가 secret.getBytes() 로 키를 만들므로
# 여기서도 이 "문자열의 UTF-8 바이트" 를 HMAC 키로 쓴다 → 서명이 일치한다.
SECRET = "5367566B...7437"

def forge(sub, ttl=3600, alg="HS256"):
    header  = {"alg": alg}                               # 예: {"alg":"HS256"}
    payload = {"sub": sub, "iat": now, "exp": now+ttl}   # sub 에 원하는 사용자(예: admin@aa.com)
    signing_input = b64url(header) + "." + b64url(payload)
    if alg == "none":
        return signing_input + "."                       # 서명 없는 토큰(alg:none 데모)
    sig = hmac_sha256(SECRET, signing_input)             # 알려진 secret 으로 서명
    return signing_input + "." + b64url(sig)             # header.payload.signature
```

**동작 단계**
1. `header`·`payload`(JSON)를 각각 **base64url** 로 인코딩해 `.` 으로 잇는다 → `signing_input`
2. `signing_input` 을 **알려진 secret 으로 HMAC-SHA256 서명** → 세 번째 칸(signature)
3. `header.payload.signature` 를 출력 → 서버는 같은 secret 으로 검증하므로 **유효한 토큰으로 인정**

**사용법**
```bash
python docs/security/jwt_forge.py                 # 기본: sub=admin@aa.com, alg=HS256
python docs/security/jwt_forge.py user@aa.com     # 다른 사용자로 위조
python docs/security/jwt_forge.py admin@aa.com none  # alg:none 토큰(3-2 데모)
```
> 핵심 포인트: **위조가 가능한 이유는 secret 이 공개됐기 때문**이다. secret 이 강하고 비공개면 이 스크립트의 서명이 서버 키와 달라 **401** 이 된다(4-1 안전 버전에서 확인). 이 스크립트는 **교육용**이며 이 저장소의 공개 기본 secret 에만 맞춰져 있다.

### 3-2. alg:none · 서명 변조 → 이미 차단됨

고전적 JWT 공격들을 시도해도 `verifyWith` 가 막는다(검증됨):

| 공격 | 결과 |
|---|---|
| `alg:none` (서명 제거) | **401** ✅ |
| 서명 변조(bad signature) | **401** ✅ |
| 토큰 없음 | **401** ✅ |

```bash
python docs/security/jwt_forge.py admin@aa.com none   # alg:none 토큰 → 서버는 401
```
> 교훈: jjwt 0.12 의 `verifyWith().parseSignedClaims()` 는 서명을 반드시 검증한다. **직접 base64 만 붙인 토큰은 통하지 않는다.**

### 3-3. payload 는 암호화가 아니다 (base64 노출)

```bash
echo "$FT" | cut -d. -f2 | python -c "import sys,base64,json;s=sys.stdin.read().strip();s+='='*(-len(s)%4);print(json.loads(base64.urlsafe_b64decode(s)))"
# {'sub': 'admin@aa.com', 'iat': ..., 'exp': ...}
```
→ 토큰만 있으면 **누구나 클레임을 읽는다.** 비밀번호·주민번호·권한근거 등 **민감정보를 payload 에 넣지 말 것.** 이 앱도 원래 subject 에 **email(PII)** 이 들어 있었다 → **4-2 에서 email 대신 불투명 uuid 로 교체**했다.

---

## 4. 방어 (안전 버전)

### 4-1. Secret 외부화 + 기동 시 fail-closed

**이번에 수정한 코드는 여기 하나다.** `JwtService` 생성자가 기동 시 **약한/기본 secret 을 감지**해, 운영에서는 취약 상태로 **아예 기동하지 못하게**(fail-closed) 한다.

**Before — `JwtService` 생성자 (약한 secret도 그대로 사용)**
```java
public JwtService(@Value("${jwt.secret}") String secret,
                  @Value("${jwt.access-expire-seconds}") long accessExpireSeconds) {
    this.key = Keys.hmacShaKeyFor(secret.getBytes());   // 검증 없이 바로 키 생성
    this.accessExpireSeconds = accessExpireSeconds;
}
```

**After — 약한/기본/짧은 secret 이면 기동 거부**
```java
public JwtService(@Value("${jwt.secret}") String secret,
                  @Value("${jwt.access-expire-seconds}") long accessExpireSeconds,
                  @Value("${jwt.allow-insecure-secret:false}") boolean allowInsecureSecret) {
    validateSecret(secret, allowInsecureSecret);        // ★ 추가: 약하면 기동 실패
    this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    this.accessExpireSeconds = accessExpireSeconds;
}

private void validateSecret(String secret, boolean allowInsecureSecret) {
    boolean weak = secret == null || secret.isBlank()
            || secret.getBytes(StandardCharsets.UTF_8).length < 32   // HS256 최소 길이(32바이트)
            || KNOWN_WEAK_SECRETS.contains(secret.trim());           // 알려진 기본/샘플 값(리포지토리 공개값 포함)
    if (!weak) return;
    if (!allowInsecureSecret)                                        // 운영: 취약하면
        throw new IllegalStateException("약한/기본 secret …");        //   아예 못 뜨게(fail-closed)
    log.warn("약한/기본 secret … 실습 전용으로 계속");                 // 실습: 경고만 남기고 진행
}
```

**`application.properties` — 플래그 추가 (Before에는 없던 줄)**
```properties
# true  = 실습(취약 데모 허용: 기본 secret으로도 기동)
# false = 운영(약한/기본 secret이면 기동 거부). 반드시 JWT_SECRET 주입
jwt.allow-insecure-secret=${JWT_ALLOW_INSECURE_SECRET:true}
# JWT_SECRET=<충분히 길고 무작위한 값>   (환경변수/시크릿 매니저)
```

**검증 결과** (검증됨):

| 설정 | 결과 |
|---|---|
| `allow-insecure=false` + 기본 secret | **기동 실패** (`IllegalStateException`) ✅ fail-closed |
| **강한** secret(env) 로 교체 후, 유출된 **기본 secret 위조** 토큰으로 `/me` | **401** ✅ 무력화 |
| 강한 secret 앱에서 **정상 로그인 토큰**으로 `/me` | **200** ✅ |

> 즉 secret 을 강하게 두고 env 로 관리하면, 리포지토리에 남은 기본 secret 이 유출돼도 **위조가 통하지 않는다.**

### 4-2. 토큰 subject 를 uuid 로 (payload 최소화 — PII 제거)

> **PII(Personally Identifiable Information, 개인 식별 정보)란?** 특정 개인을 **직접**(이름·주민번호·email·전화번호) 또는 **간접**(생년월일·주소·IP)으로 알아볼 수 있는 정보. **JWT payload 는 암호화가 아니라 base64** 라 누구나 읽을 수 있으므로, 토큰·로그·URL 처럼 노출되기 쉬운 곳에는 **PII 를 넣지 않는 것**이 원칙이다.

payload 는 공개(base64)이므로 **email 같은 PII 를 넣지 않는다.** 로그인에 쓰는 email 대신 **의미 없는 불투명 식별자(`UserInfo.uuid`)** 를 토큰 subject 로 담고, 필터는 그 uuid 로 사용자를 조회한다.

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
| 예전 방식 위조(subject=email, secret 서명) | **401** ✅ (uuid 아님 → 사용자 없음) |
| 랜덤 uuid 위조(secret 서명) | **401** ✅ (그런 사용자 없음) |

**부가 효과**
- 토큰에 **PII(email)가 남지 않는다** → 토큰이 노출돼도 로그인 식별자가 드러나지 않음
- email 을 바꿔도 토큰에 영향 없음(식별자 분리)
- 방어 심화: secret 이 유출돼도 **유효한 uuid 를 알아야** 위조가 통한다(uuid 는 응답으로 노출하지 않음)

> 주의: 이는 **payload 최소화**이지 암호화가 아니다. uuid 역시 base64 로 보이므로, 민감정보는 여전히 넣지 않는다.

### 4-3. Secret 관리 원칙
- 소스·`application.properties` 에 **실제 secret 을 두지 않는다**(env/시크릿 매니저)
- **충분히 길고 무작위**(HS256 ≥ 32바이트, 권장 더 길게), 서비스별로 다르게
- **주기적 로테이션** + 유출 시 즉시 교체(교체하면 기존 토큰 전부 무효)

### 4-4. 토큰 무효화 → Refresh 토큰 (서버 저장 + 회전) 🆕 2단계 구현

**문제**: JWT access 토큰은 **stateless** 라 서버가 기억하지 않는다. 그래서 탈취/로그아웃된 토큰을 **만료 전에 무효화하기 어렵다.** 1단계는 로그아웃 = 클라이언트가 토큰을 버리는 것뿐이라, 탈취 토큰이 만료까지 유효했다.

**해결(2단계)**: access 는 **짧게** 두고, 만료되면 **Refresh 토큰**으로 새 access 를 받는다. Refresh 는 **JWT 가 아니라 무작위 불투명 문자열**이며 **서버 DB 에 저장**한다 → 서버가 들고 있으므로 **로그아웃·유출 시 폐기**할 수 있고, 갱신 때마다 **교체(회전)** 한다.

**설계**
- access 만료 짧게(운영 권장 5~15분) / refresh 길게(예: 14일, `jwt.refresh-expire-seconds`)
- 로그인 응답 = `accessToken` + `refreshToken`
- `POST /api/userinfos/refresh` : refresh 제출 → **새 access + 새 refresh**(기존 refresh 는 1회용으로 폐기 = 회전)
- `POST /api/userinfos/logout` : refresh 를 서버에서 **폐기**

**추가/변경 코드(한눈에)**

| 파일 | 구분 | 한 일 |
|---|---|---|
| `RefreshToken` | 추가 | 엔티티(token·userUuid·expiresAt). DB 저장 |
| `RefreshTokenRepository` | 추가 | `findByToken` |
| `RefreshTokenService` | 추가 | `issue`(발급)·`rotate`(회전)·`revoke`(폐기) |
| `AuthResponse` / `RefreshRequest` | 수정/추가 | 응답에 `refreshToken` 추가 / 요청 DTO |
| `UserInfoController` | 수정 | 로그인에 refresh 발급 + `/refresh`·`/logout` |
| `SecurityConfig` | 수정 | `/refresh`·`/logout` permitAll |
| `application.properties` | 수정 | `jwt.refresh-expire-seconds` |

```java
// 회전(RefreshTokenService.rotate): 유효하면 폐기 후 새 토큰 발급
RefreshToken rt = repository.findByToken(presented)
        .orElseThrow(() -> new BadCredentialsException("유효하지 않은 refresh"));
if (rt.getExpiresAt().isBefore(Instant.now())) { repository.delete(rt); throw ...만료; }
repository.delete(rt);          // 1회용 → 즉시 폐기
return issue(rt.getUserUuid()); // 새 refresh 발급(회전)
```

**검증 결과** (test 프로파일, 검증됨):

| 단계 | 결과 |
|---|---|
| 로그인 | `accessToken`(JWT) + `refreshToken`(불투명 64자) 발급 ✅ |
| `POST /refresh`(유효 refresh) | 새 access + **새 refresh**(회전, 값 바뀜) ✅ |
| 예전 refresh 재사용 | **401** ✅ (1회용 → 폐기됨) |
| `POST /logout` 후 그 refresh 로 `/refresh` | **401** ✅ (서버에서 폐기) |

> 트레이드오프: refresh 서버 저장은 상태를 다시 두는 것이라 JWT 의 stateless 장점을 일부 포기한다. 대신 **무효화(로그아웃·회전·탈취 대응)** 를 얻는다. 운영 보강: refresh **원문 대신 해시 저장**, 재사용 탐지 시 **해당 사용자 전체 refresh 폐기**.

---

## 5. 방어 정리

| 위험 | 방어 |
|---|---|
| secret 유출 → 위조 | 강한 secret **env 관리**, 소스에 두지 않기, 기동 시 **약한 secret 거부(fail-closed)**, 로테이션 |
| `alg:none`·서명 변조 | `verifyWith()` 로 **서명 필수 검증**(이미 적용) |
| payload 노출 | **민감정보 미포함**(서명일 뿐 암호화 아님). subject 를 email→**uuid**(불투명)로 교체 |
| 탈취 토큰 장기 유효 | **짧은 access + Refresh(서버 저장·회전·로그아웃 폐기)** — 2단계 구현 |
| 전송 중 탈취 | **HTTPS/TLS** 필수(평문 금지) |

---

## 6. 자주 묻는 질문 (FAQ)

**Q1. `alg:none` 은 "알고리즘을 쓰지 않는다"는 뜻인가요?**
네 — **서명이 없는 토큰**이다. 과거 일부 라이브러리가 헤더의 `alg` 를 그대로 믿어, `alg` 를 `none` 으로 바꾸고 서명을 지운 토큰을 검증 없이 통과시켰다(인증 우회). 이 앱은 `verifyWith(key)` 로 서명을 반드시 요구하므로 `alg:none`·서명 변조를 거부한다(401). `alg` 는 공격자가 바꿀 수 있는 값이므로 믿지 말고, **서버가 기대하는 키·알고리즘으로만 검증**한다.

**Q2. 설정파일의 `jwt.secret` 이 git 에 올라가 있으면 괜찮은가요?**
원칙상 **문제**다. secret 이 저장소에 있으면(특히 public) 누구나 관리자 토큰을 위조할 수 있다. 다만 이 앱 값은 **env override 를 전제로 한 데모용 기본값**이고 보호할 실데이터가 없어 **실습에서만** 허용한다. 운영이면 치명적 취약점. 한 번 커밋한 secret 은 **git history 에 영구히 남으므로**, 파일에서 지우는 것만으론 부족하고 반드시 **새 값으로 교체(로테이션)** 해야 한다.

**Q3. `jwt.allow-insecure-secret=false` 는 무슨 뜻인가요?**
약한/기본 secret 이면 **앱 기동을 거부(fail-closed)** 한다는 뜻이다. 단 `false` 만으론 부족하고, **강한 `JWT_SECRET` 을 환경변수로 주입**하는 것과 **쌍으로** 설정해야 실제로 안전하다. (false 로 두고 강한 secret 을 안 주면 기본값이 약해 기동이 실패한다 — 의도된 안전 동작.)

**Q4. 약한/강한 secret 은 byte 수(길이)를 말하나요?**
길이는 **최소 조건**일 뿐이다(HS256 ≥ 32byte = 256bit). **강함 = 길이 + 무작위(엔트로피) + 비밀 유지**, 셋 다 필요하다. 길어도 예측 가능하거나 **공개되면 약하다** — 이 앱의 64byte 기본값이 "길지만 공개되어 약한" 예다. 강한 secret 은 무작위로 생성한다(예: `openssl rand -base64 48`).

**Q5. PII 가 무엇인가요?**
**개인 식별 정보(Personally Identifiable Information)** — 이름·주민번호·email·전화번호처럼 개인을 알아볼 수 있는 정보다. JWT payload 는 암호화가 아니라 base64 라 누구나 읽으므로 **PII 를 넣지 않는다.** 그래서 이 앱은 토큰 subject 를 **email → uuid**(불투명 식별자)로 바꿨다(4-2 참고).

**Q6. access 와 refresh 토큰의 차이는?**
**access** 는 API 호출마다 `Authorization` 헤더로 보내는 **단기 JWT**(권한 증표)다. 자주 노출되므로 **짧게** 둔다. **refresh** 는 access 가 만료됐을 때 **새 access 를 받기 위한 장기 자격**으로, 평소엔 보관만 하고 `/refresh` 호출 때만 쓴다. 이 앱의 refresh 는 **JWT 가 아니라 서버 DB 에 저장한 무작위 값**이라 **폐기(로그아웃)·회전**이 가능하다. 요약: **access=짧고 자주, refresh=길고 가끔·서버가 통제**.

---

## 7. 관련 문서
- **이전 단계**: `feature/jwt-security-demo` (**1단계** — secret 하드닝, email subject라 공격 성공 시연)
- 개념: `OWASP_Top10_2025_한글요약` (#7 인증, #4 암호화 하드닝 체크리스트)
- 접근 제어: `02_Insecure_DOR` (인증 ≠ 인가 — 위조로 인증돼도 인가는 별개)
- 프론트: 토큰 저장 위치(sessionStorage/localStorage)와 XSS 연계는 프론트 보안편에서 다룸
