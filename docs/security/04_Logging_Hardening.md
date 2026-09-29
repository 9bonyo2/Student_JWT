# 04. 보안 감사 로깅 적용 (Logging Hardening)

> OWASP Top 10 2025 **#9 로깅·경보 실패(Logging & Alerting Failures)**
> 브랜치: `feature/logging-hardening`
> 성격: 취약/안전 데모가 아니라, **실제 앱에 보안 로깅을 추가한 하드닝**

---

## 1. 목표

"공격을 기록·감지·대응한다"의 **첫 단계 = 제대로 기록하기**를 실제 앱에 적용한다.

- 로그인 **성공/실패** 기록 (무차별 대입 탐지의 근거)
- **접근 거부(403)·인증 실패(401)** 를 요청 맥락과 함께 기록
- **민감정보(비밀번호·JWT)는 남기지 않기**, 사용자 식별자는 **마스킹**
- `[AUDIT]` 태그로 감사 로그를 구분 (나중에 SIEM 등에서 필터링)

---

## 2. 적용 내용

| 파일 | 변경 | 내용 |
|---|---|---|
| `security/logging/SecurityAuditListener.java` | 신규 | 인증 성공/실패 이벤트 → 감사 로그 (이메일 마스킹) |
| `exception/advice/DefaultExceptionAdvice.java` | 수정 | 401/403 로그에 `[AUDIT]` + 메서드·URI·IP 추가 |
| `application.properties` | 수정 | 감사 로거 레벨(INFO) 지정 |

### 2-1. 인증 이벤트 리스너

```java
@Component
@Slf4j
public class SecurityAuditListener {
    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        log.info("[AUDIT] 로그인 성공 - user={}", mask(event.getAuthentication().getName()));
    }
    @EventListener
    public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        log.warn("[AUDIT] 로그인 실패 - user={}, reason={}",
                 mask(event.getAuthentication().getName()),
                 event.getException().getClass().getSimpleName());
    }
    // user@aa.com -> us***@aa.com (민감정보 마스킹)
    private String mask(String value) { ... }
}
```
> Spring Security 가 발행하는 인증 이벤트를 받는다. 폼 로그인·REST 로그인 모두 `AuthenticationManager` 를 거치므로 이벤트가 발생한다.

### 2-2. 예외 처리 감사 보강 (401/403)

```java
@ExceptionHandler(AccessDeniedException.class)
protected ResponseEntity<ErrorObject> handleException(AccessDeniedException e, HttpServletRequest request) {
    log.warn("[AUDIT] 접근 거부(403) - {} {} from {} : {}",
             request.getMethod(), request.getRequestURI(), clientIp(request), e.getMessage());
    ...
}
```
> 403(접근 거부)은 **권한 상승 시도의 신호**일 수 있어 "누가·무엇을" 함께 남긴다.

---

## 3. 실습 — 감사 로그 확인

앱을 기동한 뒤(예: 8080), 아래를 순서대로 호출하고 콘솔/로그를 본다.

```bash
# 아래 명령들은 전체 URL 사용

# 1) 로그인 실패 (틀린 비밀번호)
curl -s -o /dev/null -w "%{http_code}\n" -X POST "http://localhost:8080/api/userinfos/login" \
  -H "Content-Type: application/json" -d '{"email":"user@aa.com","password":"WRONG"}'

# 2) 로그인 성공 → 토큰 획득
TOKEN=$(curl -s -X POST "http://localhost:8080/api/userinfos/login" \
  -H "Content-Type: application/json" -d '{"email":"user@aa.com","password":"pwd2"}' \
  | sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p')

# 3) 403 유발 (user가 admin(id=1) 프로필 접근)
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" "http://localhost:8080/api/idor/profiles-safe/1"
```

### 실제 출력 (검증됨)

```
[AUDIT] 로그인 실패 - user=us***@aa.com, reason=BadCredentialsException
[AUDIT] 인증 실패(401) - POST /api/userinfos/login from 0:0:0:0:0:0:0:1 : 자격 증명에 실패하였습니다.
[AUDIT] 로그인 성공 - user=us***@aa.com
[AUDIT] 접근 거부(403) - GET /api/idor/profiles-safe/1 from 0:0:0:0:0:0:0:1 : 본인 또는 관리자만 조회할 수 있습니다
```

확인 포인트:
- ✅ 이메일이 **`us***@aa.com`** 로 마스킹됨 (원본 노출 안 함)
- ✅ **비밀번호·JWT 토큰은 로그에 전혀 없음**
- ✅ 401/403에 **메서드·URI·출처 IP** 포함 → "누가 무엇을" 파악 가능
- ✅ `[AUDIT]` 태그로 감사 로그만 골라볼 수 있음

### 3-1. 단계별 로그와 grep 확인

여러 요청을 한 번에 보내면 로그가 섞인다. **요청을 하나씩 보내고, 해당 요청의 로그만 grep으로 확인**한다. (각 명령은 전체 URL을 그대로 사용)

**① 로그인 실패 (틀린 비밀번호) → HTTP 401**
```bash
curl -s -o /dev/null -X POST "http://localhost:8080/api/userinfos/login" \
  -H "Content-Type: application/json" -d '{"email":"user@aa.com","password":"WRONG"}'
```
출력 로그 (2줄):
```
[AUDIT] 로그인 실패 - user=us***@aa.com, reason=BadCredentialsException
[AUDIT] 인증 실패(401) - POST /api/userinfos/login from ...::1 : 자격 증명에 실패하였습니다.
```
확인:
```bash
grep -E "로그인 실패|인증 실패" logs/spring.log | tail -2
```

**② 로그인 성공 → HTTP 200 (토큰 발급)**
```bash
curl -s -X POST "http://localhost:8080/api/userinfos/login" \
  -H "Content-Type: application/json" -d '{"email":"user@aa.com","password":"pwd2"}'
```
출력 로그 (1줄):
```
[AUDIT] 로그인 성공 - user=us***@aa.com
```
확인:
```bash
grep "로그인 성공" logs/spring.log | tail -1
```

**③ 접근 거부 (user가 admin 프로필) → HTTP 403** (위 ②에서 받은 `TOKEN` 사용)
```bash
curl -s -o /dev/null -H "Authorization: Bearer $TOKEN" "http://localhost:8080/api/idor/profiles-safe/1"
```
출력 로그 (1줄):
```
[AUDIT] 접근 거부(403) - GET /api/idor/profiles-safe/1 from ...::1 : 본인 또는 관리자만 조회할 수 있습니다
```
확인:
```bash
grep "접근 거부" logs/spring.log | tail -1
```

> **참고**: 2줄이 나오는 건 ①(실패)뿐이다. ②는 1줄(성공), ③도 1줄(403). 전체를 한 번에 보려면 `grep "\[AUDIT\]" logs/spring.log`.

---

## 4. 여기까지가 "탐지"의 토대

이번 실습은 로깅·경보 5단계 중 **① 기록**에 해당한다. 이후 단계는 개념으로 이해한다:

| 단계 | 내용 | 이 앱 |
|---|---|---|
| ① 기록 | 중요한 것 남기고, 민감정보는 빼기 | ✅ 이번 적용 |
| ② 중앙 집중 | SIEM·ELK로 로그 모으기 | 개념 |
| ③ 탐지·경보 | 다수 로그인 실패=무차별 대입 등 규칙 | 개념 |
| ④ 보관·보호 | 90~180일+, append-only 무결성 | 개념 |
| ⑤ 대응 연계 | 경보→플레이북/SOAR | 개념 |

> 예: 이후 CSRF·무차별 대입 데모에서 **"공격이 `[AUDIT]` 로그에 이렇게 남는다"** 를 함께 보여줄 수 있다.

---

## 5. 관련 문서

- 개념: `OWASP_Top10_2025_한글요약` (#9 보충)
- 접근 거부(403)가 나온 IDOR: `02_Insecure_DOR`
