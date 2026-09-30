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
→ 토큰만 있으면 **누구나 클레임을 읽는다.** 비밀번호·주민번호·권한근거 등 **민감정보를 payload 에 넣지 말 것.**

---

## 4. 방어 (안전 버전)

### 4-1. Secret 외부화 + 기동 시 fail-closed

`JwtService` 가 기동 시 **약한/기본 secret 을 감지**해, 운영에서는 취약 상태로 **아예 기동하지 못하게** 한다.
```java
// jwt.allow-insecure-secret=false(운영) 이고 secret 이 약하면 기동 실패(fail-closed)
private void validateSecret(String secret, boolean allowInsecureSecret) {
    boolean weak = secret == null || secret.isBlank()
            || secret.getBytes(StandardCharsets.UTF_8).length < 32   // HS256 최소 길이
            || KNOWN_WEAK_SECRETS.contains(secret.trim());            // 알려진 기본/샘플 값
    if (!weak) return;
    if (!allowInsecureSecret) throw new IllegalStateException("약한/기본 secret …");
    log.warn("약한/기본 secret … 실습 전용으로 계속");
}
```
```properties
# 운영: 환경변수로 강한 secret 주입 + 취약 secret 이면 기동 거부
jwt.allow-insecure-secret=false
# JWT_SECRET=<충분히 길고 무작위한 값>   (환경변수/시크릿 매니저)
```

**검증 결과** (검증됨):

| 설정 | 결과 |
|---|---|
| `allow-insecure=false` + 기본 secret | **기동 실패** (`IllegalStateException`) ✅ fail-closed |
| **강한** secret(env) 로 교체 후, 유출된 **기본 secret 위조** 토큰으로 `/me` | **401** ✅ 무력화 |
| 강한 secret 앱에서 **정상 로그인 토큰**으로 `/me` | **200** ✅ |

> 즉 secret 을 강하게 두고 env 로 관리하면, 리포지토리에 남은 기본 secret 이 유출돼도 **위조가 통하지 않는다.**

### 4-2. Secret 관리 원칙
- 소스·`application.properties` 에 **실제 secret 을 두지 않는다**(env/시크릿 매니저)
- **충분히 길고 무작위**(HS256 ≥ 32바이트, 권장 더 길게), 서비스별로 다르게
- **주기적 로테이션** + 유출 시 즉시 교체(교체하면 기존 토큰 전부 무효)

### 4-3. 토큰 무효화 부재 → 짧은 만료 (개념)

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
| payload 노출 | **민감정보 미포함**(서명일 뿐 암호화 아님) |
| 탈취 토큰 장기 유효 | **짧은 만료 + Refresh 회전**, 필요 시 revocation(jti/token-version) |
| 전송 중 탈취 | **HTTPS/TLS** 필수(평문 금지) |

---

## 6. 관련 문서
- 개념: `OWASP_Top10_2025_한글요약` (#7 인증, #4 암호화 하드닝 체크리스트)
- 접근 제어: `02_Insecure_DOR` (인증 ≠ 인가 — 위조로 인증돼도 인가는 별개)
- 프론트: 토큰 저장 위치(sessionStorage/localStorage)와 XSS 연계는 프론트 보안편에서 다룸
