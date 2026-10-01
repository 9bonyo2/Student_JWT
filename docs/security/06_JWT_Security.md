# 06. JWT 보안 실습

> OWASP Top 10 2025 **#7 인증 실패**, **#4 암호화 실패**
> 브랜치: `feature/jwt-security-demo`
> 대상 코드: `com.basic.myspringboot.security.jwt`(JwtService·JwtAuthenticationFilter) + `application.properties`

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
| 4 | 탈취 토큰 장기 유효 | 로그아웃·탈취 후에도 유효 | **짧은 만료 + Refresh** | 개념 |

> HS256은 **같은 secret으로 서명·검증**한다. 그래서 secret 유출 = 위조 가능 → secret 관리가 JWT 보안의 핵심이다.

---

## 3. 공격 실습 (취약 상태)

> 취약 상태 = `application.properties` 의 기본 secret + `jwt.allow-insecure-secret=true`

### 3-1. Secret 유출 → 토큰 위조 → 관리자 탈취 ⭐

`application.properties` 의 secret 은 `secret.getBytes()` 로 쓰이므로, HMAC 키 = **그 문자열의 UTF-8(ASCII) 바이트**다. 이 값만 알면 공격자가 **비밀번호 없이** admin 토큰을 직접 서명할 수 있다.

`docs/security/jwt_forge.py` (표준 라이브러리만 사용):
```bash
B=http://localhost:8080
FT=$(python docs/security/jwt_forge.py admin@aa.com)      # admin 토큰 위조
curl -s -w "\n%{http_code}\n" "$B/api/userinfos/me" -H "Authorization: Bearer $FT"
```
**검증 결과** (test 프로파일, 검증됨):

| 요청 | 결과 |
|---|---|
| 위조 admin 토큰으로 `/me` | **200** → `{"email":"admin@aa.com","roles":["ROLE_ADMIN","ROLE_USER"]}` 🔴 |

→ **비밀번호를 몰라도 secret 하나로 관리자 세션을 얻는다.** (roles 는 DB에서 오므로, admin 계정명으로 위조하면 admin 권한을 그대로 획득)

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

### 4-4. 토큰 무효화 부재 → 짧은 만료 (개념)

JWT 는 **stateless** 라 서버가 발급 후 기억하지 않는다. 그래서 **탈취/로그아웃된 개별 토큰을 곧바로 무효화하기 어렵다.**
- 이 앱: 로그아웃 = 클라이언트가 토큰을 버리는 것뿐. **탈취된 토큰은 만료(3600초)까지 유효.**
- 방어책:
  - **짧은 access 만료(예: 5~15분)** + **Refresh 토큰**으로 재발급(회전) → 탈취 창(window) 최소화
  - **서버측 revocation**(선택): `jti`(토큰 고유 id) **denylist**(로그아웃·유출 시 등록), 또는 사용자별 **token-version** 컬럼(비번 변경·강제 로그아웃 시 증가 → 이전 토큰 무효)
  - 민감 작업은 **재인증**
- 트레이드오프: revocation 은 서버에 상태를 다시 두는 것이라 JWT 의 stateless 장점을 일부 포기한다. **먼저 "짧은 만료 + Refresh"** 로 대부분의 위험을 줄인다.

---

## 5. 방어 정리

| 위험 | 방어 |
|---|---|
| secret 유출 → 위조 | 강한 secret **env 관리**, 소스에 두지 않기, 기동 시 **약한 secret 거부(fail-closed)**, 로테이션 |
| `alg:none`·서명 변조 | `verifyWith()` 로 **서명 필수 검증**(이미 적용) |
| payload 노출 | **민감정보 미포함**(서명일 뿐 암호화 아님). subject 를 email→**uuid**(불투명)로 교체 |
| 탈취 토큰 장기 유효 | **짧은 만료 + Refresh 회전**, 필요 시 revocation(jti/token-version) |
| 전송 중 탈취 | **HTTPS/TLS** 필수(평문 금지) |

---

## 6. 관련 문서
- 개념: `OWASP_Top10_2025_한글요약` (#7 인증, #4 암호화 하드닝 체크리스트)
- 접근 제어: `02_Insecure_DOR` (인증 ≠ 인가 — 위조로 인증돼도 인가는 별개)
- 프론트: 토큰 저장 위치(sessionStorage/localStorage)와 XSS 연계는 프론트 보안편에서 다룸
