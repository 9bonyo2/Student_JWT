# 06. JWT 보안 실습 — 1단계 (secret 하드닝)

> OWASP Top 10 2025 **#7 인증 실패**, **#4 암호화 실패**
> 브랜치: `feature/jwt-security-demo` (**1단계**)
> 대상 코드: `com.basic.myspringboot.security.jwt`(JwtService·JwtAuthenticationFilter) + `application.properties`
>
> **단계 안내**: 이 문서는 **1단계(secret 하드닝)** 다. 토큰 subject 는 아직 **email** 이라 secret 유출 시 **공격이 성공**한다. **2단계(`feature/jwt-advanced-demo`)** 에서 subject 를 uuid 로 바꿔 공격을 막고, **Refresh 토큰**을 추가한다.

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

### 취약점 → 방어 지도 (요약)

JWT의 안전은 거의 전부 **secret(서명 키) 관리**에 달려 있다. **1단계에서 코드를 바꾼 것은 #1 하나**이고, #3·#4 는 **2단계**에서 코드로 다룬다.

| # | 취약점 | 위험 | 방어 | 단계 |
|---|---|---|---|---|
| 1 | **secret이 약함/공개**(소스 하드코딩) | 유출 시 **누구나 admin 토큰 위조** | ① secret을 **env로 분리**·강하게 ② 기동 시 **약한 secret 거부(fail-closed)** | ✅ **1단계 코드** |
| 2 | alg:none·서명 변조 | 서명 우회 | `verifyWith()`로 서명 필수 검증 | 기존 코드 |
| 3 | payload 노출(base64) | **email 등 PII 유출** | 토큰 subject를 **email→uuid**(불투명)로 | 🔜 **2단계 코드** |
| 4 | 탈취 토큰 장기 유효 | 로그아웃·탈취 후에도 유효 | **짧은 만료 + Refresh**(서버저장·회전) | 🔜 **2단계 코드** |

> HS256은 **같은 secret으로 서명·검증**한다. 그래서 secret 유출 = 위조 가능 → secret 관리가 JWT 보안의 핵심이다.

---

## 3. 공격 실습 (취약 상태)

> 취약 상태 = `application.properties` 의 기본 secret + `jwt.allow-insecure-secret=true`
> 1단계는 토큰 subject 가 **email** 이므로, 아래 공격이 **그대로 성공**한다.

### 3-1. Secret 유출 → 토큰 위조 → email 로 role 까지 알아내고 관리자 탈취 ⭐

**이 공격은 2단계로 이어진다**: **① 탈취한 토큰을 디코딩해 email 확인**(아직 role 은 모른다) → **② 그 email 로 새 토큰을 위조**해 `/me` 를 호출하면 **role 까지 드러나고, 동시에 관리자 권한도 얻는다.**

**① 탈취한 토큰 디코딩 → email 확인**

JWT payload 는 암호화가 아니라 base64 이므로, 토큰(`$STOLEN`)만 있으면 누구나 클레임을 읽는다. (가정: 공격자가 XSS·네트워크 스니핑 등 어떤 경로로 로그인된 토큰을 하나 탈취했다.)

```bash
echo "$STOLEN" | cut -d. -f2 | python -c "import sys,base64,json;s=sys.stdin.read().strip();s+='='*(-len(s)%4);print(json.loads(base64.urlsafe_b64decode(s)))"
# {'sub': 'admin@aa.com', 'iat': ..., 'exp': ...}
```
→ `sub` 에서 **email(`admin@aa.com`)은 알아냈지만, role 은 토큰에 없다**(이 앱은 roles 를 토큰에 넣지 않고 DB 에서 로드한다 — 2절 참고). role 을 알려면 이 email 로 실제 인증을 통과해야 한다.

**② 알아낸 email 로 토큰 위조 → `/me` 호출 → role 까지 확인 + 관리자 권한 획득**

secret 은 `secret.getBytes()` 로 쓰이므로, HMAC 키 = **그 문자열의 UTF-8(ASCII) 바이트**다. 이 값만 알면 공격자가 **비밀번호 없이** ① 에서 알아낸 email 로 직접 서명할 수 있다.

```bash
B=http://localhost:8080
FT=$(python docs/security/jwt_forge.py admin@aa.com)      # ①에서 알아낸 email 로 위조
curl -s -w "\n%{http_code}\n" "$B/api/userinfos/me" -H "Authorization: Bearer $FT"
```
**검증 결과** (test 프로파일, 검증됨):

| 요청 | 결과 |
|---|---|
| 위조 admin 토큰으로 `/me` | **200** → `{"email":"admin@aa.com","roles":["ROLE_ADMIN","ROLE_USER"]}` — **role 도 이 순간 알아낸다** 🔴 |

→ **비밀번호를 몰라도 secret 하나로 email → role → 관리자 세션까지 전부 얻는다.** (roles 는 DB에서 오므로, email 만 알면 위조 토큰으로 role 까지 자동으로 드러난다)

> 💡 2단계에서 subject 를 uuid 로 바꾸면, ① 에서 탈취한 토큰을 디코딩해도 **email 이 아니라 의미 없는 uuid** 만 보인다. 그 uuid 를 그대로 다시 넣어 위조해도 **원래 소유자 본인으로 검증될 뿐**이라 공격 의미가 없고, admin 의 진짜 uuid 는 애초에 알아낼 방법이 없다 → **401** (= 2단계 방어)

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

3-1 **①** 에서 이미 보았듯, JWT 의 payload 는 base64 인코딩일 뿐 암호화가 아니다. 토큰만 있으면 서버 없이도 **누구나 클레임을 읽는다.** 비밀번호·주민번호·권한근거 등 **민감정보를 payload 에 넣지 말 것.** 1단계는 subject 에 **email(PII)** 이 들어 있다 → **2단계에서 불투명 uuid 로 교체**한다.

---

## 4. 방어 (안전 버전) — 1단계

### 4-1. Secret 외부화 + 기동 시 fail-closed

**1단계에서 수정한 코드는 여기 하나다.** `JwtService` 생성자가 기동 시 **약한/기본 secret 을 감지**해, 운영에서는 취약 상태로 **아예 기동하지 못하게**(fail-closed) 한다.

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
            || KNOWN_WEAK_SECRETS.contains(secret.trim());           // 알려진 기본/샘플 값
    if (!weak) return;
    if (!allowInsecureSecret)                                        // 운영: 취약하면
        throw new IllegalStateException("약한/기본 secret …");        //   아예 못 뜨게(fail-closed)
    log.warn("약한/기본 secret … 실습 전용으로 계속");                 // 실습: 경고만 남기고 진행
}
```

**`application.properties` — 플래그 추가**
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

### 4-2. Secret 관리 원칙
- 소스·`application.properties` 에 **실제 secret 을 두지 않는다**(env/시크릿 매니저)
- **충분히 길고 무작위**(HS256 ≥ 32바이트, 권장 더 길게), 서비스별로 다르게
- **주기적 로테이션** + 유출 시 즉시 교체(교체하면 기존 토큰 전부 무효)

### 4-3. 토큰 무효화 부재 → 짧은 만료 (개념, 2단계에서 구현)

JWT 는 **stateless** 라 서버가 발급 후 기억하지 않는다. 그래서 **탈취/로그아웃된 개별 토큰을 곧바로 무효화하기 어렵다.**
- 1단계 현재: 로그아웃 = 클라이언트가 토큰을 버리는 것뿐. **탈취된 토큰은 만료(3600초)까지 유효.**
- 방어책: **짧은 access 만료 + Refresh 토큰**(재발급·회전), 서버측 revocation(로그아웃·유출 시 무효화)
- → **2단계(`feature/jwt-advanced-demo`)에서 "서버 저장 + 회전" Refresh 로 실제 구현**한다.

---

## 5. 방어 정리 (1단계)

| 위험 | 방어 | 단계 |
|---|---|---|
| secret 유출 → 위조 | 강한 secret **env 관리**, 소스에 두지 않기, 기동 시 **약한 secret 거부(fail-closed)**, 로테이션 | 1단계 ✅ |
| `alg:none`·서명 변조 | `verifyWith()` 로 **서명 필수 검증** | 기존 ✅ |
| payload 노출(PII) | subject 를 email→**uuid**(불투명)로 교체 | 2단계 🔜 |
| 탈취 토큰 장기 유효 | **짧은 만료 + Refresh 회전**, revocation | 2단계 🔜 |
| 전송 중 탈취 | **HTTPS/TLS** 필수(평문 금지) | 운영 |

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

> **`KNOWN_WEAK_SECRETS` 의 `5367...` 값은 왜 등록돼 있나?**
> 실제로 어디선가 유출된 사고가 있었던 게 아니라, **"이미 노출된 secret" 상황을 교육용으로 일부러 연출한 값**이다. 처음부터 이 공개 저장소의 소스에 커밋해 두어 **누구나 알 수 있는 상태**로 만든 것 — 그래서 이 값으로 위조 공격이 성공하는 것 자체가 "공개되면(길이·무작위성과 무관하게) 약하다"는 교훈의 시연이다. `KNOWN_WEAK_SECRETS` 에 정확히 이 문자열이 등록돼 있어, `validateSecret()` 이 길이 조건(64바이트, 통과)과 무관하게 **"알려진 값"이라는 이유만으로** 거부한다.
>
> **그런데 이 블록리스트는 "실시간 유출 감지기"가 아니다.** `KNOWN_WEAK_SECRETS` 는 미리 등록해 둔 값만 거부하는 **고정 목록**일 뿐이다. 만약 담당자가 **직접 생성한 새 secret**이 나중에(채팅에 붙여넣기·실수로 커밋 등으로) 유출돼도, 그 값은 이 목록에 없으므로 `validateSecret()` 은 여전히 "강하다"고 판단해 **정상 기동한다** — 코드가 그 유출을 알아서 막아주지 않는다. 담당자가 유출 사실 자체를 모르면, 공격자는 정상 서명된 토큰으로 조용히 들어오고 **아무 이상 없이 뚫린다.**
>
> **"모름"을 줄이기 위한 실질적 장치들**
>
> | 대책 | 역할 |
> |---|---|
> | **커밋 전 시크릿 스캐너**(`git-secrets`, `gitleaks`, GitHub Secret Scanning 등) | 실수로 secret 이 커밋되는 순간(= 유출 시작점)을 **기계적으로 잡아냄** — 사람이 몰라도 도구가 안다 |
> | **정기 로테이션(일정 주기)** | "유출을 알았을 때만"이 아니라 **몰라도 주기적으로 교체** → 모르는 유출이 있었더라도 피해 기간을 유한하게 제한 |
> | **비정상 사용 모니터링**(평소 안 쓰던 IP·시간대의 admin 로그인, 짧은 시간 반복 호출 등) | secret 자체는 못 잡아도 **악용 "결과"는 탐지** — 5-3 토큰 무효화·감사 로깅(OWASP #9)과 연결 |
> | **비밀 관리소**(Vault, AWS/Azure Secrets Manager 등) | 사람이 환경변수를 직접 복붙하지 않게 해 **실수로 어딘가에 붙여넣는 경로 자체**를 줄인다 |
>
> 즉 "유출을 담당자가 알아야만 안전하다"는 구조 자체가 취약하므로, **사람이 몰라도 자동으로 잡거나(스캐너), 몰라도 피해가 제한되게(정기 로테이션·모니터링) 설계**하는 것이 핵심이다.

**Q5. PII 가 무엇인가요?**
**개인 식별 정보(Personally Identifiable Information)** — 이름·주민번호·email·전화번호처럼 개인을 알아볼 수 있는 정보다. JWT payload 는 암호화가 아니라 base64 라 누구나 읽으므로 **PII 를 넣지 않는다.** 이 앱도 1단계는 subject 에 email 이 있어, **2단계에서 uuid 로 교체**한다.

**Q6. UUID 생성기 사이트에서 만든 값으로 `jwt.secret` 을 바꾸면, `KNOWN_WEAK_SECRETS` 도 같이 바꿔야 하나요?**
**아니요.** `KNOWN_WEAK_SECRETS` 는 "허용 목록"이 아니라 **블록리스트**(이 저장소의 공개 기본값·`secret`·`changeit` 같은 흔한 샘플값만 등록)다. 새로 만든 값이 이 목록에 없고 길이가 32바이트 이상이면 `validateSecret()` 을 그대로 통과하므로, **임의로 만든 값을 매번 이 목록에 추가할 필요가 없다.** 다만 **UUID 생성기 웹사이트 사용 자체는 권장하지 않는다**:
- UUID(36자)는 길이 조건(≥32바이트)은 통과하지만, UUIDv4 의 실제 무작위성은 **약 122비트**(버전·variant 비트 고정, 하이픈은 엔트로피 0)로 권장 수준(`openssl rand` 급, 256비트 이상)보다 약하다.
- **제3자 웹사이트가 생성한 값은 전송·로깅 여부를 확인할 수 없어 신뢰하기 어렵다.**
- 어딘가에(채팅·문서·이슈 등) **한 번이라도 붙여넣은 값은 더 이상 비밀이 아니다** — Q2 의 "노출된 secret 은 교체해야 한다"와 같은 이유다.

→ 새 secret 이 필요하면 **Q4** 처럼 로컬에서 `openssl rand -base64 48` 로 생성하고, **소스에 커밋하지 않고 `JWT_SECRET` 환경변수로만 주입**한다.

> **실습 안내 — 지금 당장 바꿔야 하나?**
> **아니오.** 1단계 공격 실습(위조 성공 데모)이 목적이면 `application.properties` 의 기본 secret 은 **그대로 두는 것이 의도된 상태**다(공개된 기본값이라 공격이 성공하는 것 자체가 교육 포인트). 대신 secret 을 바꿔서 **"강한 secret 이면 위조가 막힌다"(4-1 안전 버전)** 를 시연해 보고 싶다면:
>
> **① `openssl rand -base64 48` 이 뜻하는 것** — `48`은 **시드(seed)가 아니라 "생성할 원본 바이트 수"**다. `openssl rand`는 고정 입력을 받는 게 아니라 **실행할 때마다 OS 의 CSPRNG(암호학적 난수 생성기)에서 새 엔트로피를 가져와** 매번 다른 값을 만든다(재현 불가능해야 비밀로서 의미가 있다). `48`바이트 = 384비트 엔트로피(HS256 최소 권장 256비트보다 넉넉)이고, `-base64`는 그 원본 바이트를 복사·붙여넣기 가능한 문자열로 인코딩하는 것뿐이다(원본 3바이트 → base64 4글자이므로 결과는 64자).
>
> **② 생성한 값을 셸(커밋하지 않고 그 세션에만 적용)에 주입**
>
> | 셸 | 명령 |
> |---|---|
> | PowerShell | `$env:JWT_SECRET = "<생성한 값>"` |
> | cmd.exe | `set "JWT_SECRET=<생성한 값>"` (⚠️ `=` 양옆에 공백을 넣지 말 것 — `set "NAME=VALUE"`처럼 **이름=값 전체**를 따옴표로 감싼다. `set NAME = "VALUE"`로 쓰면 공백까지 변수 이름/값에 포함돼 버린다) |
> | Git Bash | `JWT_SECRET="<생성한 값>" ./mvnw.cmd spring-boot:run` (그 실행 한 번에만 적용) |
>
> ```powershell
> # PowerShell 예시 (전체 흐름)
> openssl rand -base64 48                 # ① 로컬에서 강한 secret 생성 (매번 다른 값)
> $env:JWT_SECRET = "<위에서 생성한 값>"   # ② 커밋 X, 이 세션에만 적용
> .\mvnw.cmd spring-boot:run               # cmd.exe 라면 .\ 없이 mvnw.cmd spring-boot:run
>
> # 확인: 유출된 "기본" secret 으로 위조한 토큰은 이제 401, 정상 로그인 토큰은 200
> ```
> 환경변수를 설정하지 않고 끄면 기본 공개 secret 으로 되돌아가 **다시 공격이 성공**한다(1단계 데모 상태). 이 환경변수는 그 세션에만 적용되고 커밋되지 않으므로 **데모 전환용으로 안전**하다.

**Q7. `jwt.allow-insecure-secret` 의 기본값만 `false` 로 바꿨더니 기동이 안 됩니다. 왜 그런가요?**
**버그가 아니라 fail-closed 가 의도대로 작동한 것이다.** `application.properties` 의 `jwt.secret` 은 그대로 **커밋된 공개 기본값**(`KNOWN_WEAK_SECRETS` 에 등록된 값)을 쓰는데, `jwt.allow-insecure-secret` 기본값만 `false` 로 바꾸면:

```java
boolean weak = ... || KNOWN_WEAK_SECRETS.contains(secret.trim());  // 공개 기본값 → weak=true
if (!weak) return;
if (!allowInsecureSecret)                // false 로 바꿨으므로
    throw new IllegalStateException(...); // → 기동 거부 (BeanInstantiationException 으로 감싸짐)
```
**"약한 secret(기본값 그대로) + `allow-insecure-secret=false`"** 조합이 되어, Q3 에서 설명한 **"의도된 안전 동작"**이 그대로 발동한 것이다. `allow-insecure-secret` 과 `jwt.secret` 은 **쌍으로** 바뀌어야 하며, 하나만 바꾸면 이렇게 항상 실패한다.

| 목적 | 해야 할 일 |
|---|---|
| 1단계 공격 실습 계속하기(이 브랜치의 기본 목적) | `jwt.allow-insecure-secret=${JWT_ALLOW_INSECURE_SECRET:true}` 로 **되돌린다**(커밋된 원래 값) |
| "강한 secret 이면 위조가 막힌다" 시연 | `allow-insecure-secret` 은 건드릴 필요 없이 `true` 로 두고, **Q6 처럼 `JWT_SECRET` 환경변수만** 강한 값으로 주입한다 — secret 이 강하면 `weak=false` 가 되어 `allowInsecureSecret` 값 자체를 보지 않는다 |

> 💡 즉 `jwt.allow-insecure-secret` 은 "secret 이 약할 때만" 의미가 있는 **보조 안전장치**다. secret 을 강하게 주입하면 이 플래그를 `true`/`false` 어느 쪽에 둬도 결과는 같다(둘 다 통과).

---

## 7. 다음 단계 · 관련 문서
- **다음 단계**: `feature/jwt-advanced-demo` (**2단계**) — 토큰 subject 를 **uuid** 로(PII 제거, email 위조 차단) + **Refresh 토큰**(서버 저장 + 회전) 추가
- 개념: `OWASP_Top10_2025_한글요약` (#7 인증, #4 암호화 하드닝 체크리스트)
- 접근 제어: `02_Insecure_DOR` (인증 ≠ 인가 — 위조로 인증돼도 인가는 별개)
- 프론트: 토큰 저장 위치(sessionStorage/localStorage)와 XSS 연계는 프론트 보안편에서 다룸
