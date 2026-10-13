# 10. 로그인 시도 제한 (Account Lockout / Brute Force 방어) 실습

> OWASP Top 10 2025 **#7 식별 및 인증 실패**(Identification and Authentication Failures)
> 브랜치: `feature/bruteforce-demo` (`feature/security-misconfig-demo`에서 분기)
> 대상 코드: `UserInfo.java`, `LoginAttemptService.java`(신규), `UserInfoController.java`, `application.properties`

---

## 1. 개념 요약

로그인에 **시도 횟수 제한이 없으면**, 공격자는 Burp Suite Intruder 같은 자동화 도구로 비밀번호 후보 목록을 초당 수십~수백 번 반복 대입할 수 있다. 서버 입장에선 정상 로그인 요청과 구분이 안 되므로, 사전 공격(dictionary attack)·크리덴셜 스터핑이 "뚫리느냐"가 아니라 "**언제** 뚫리느냐"의 시간 문제가 된다.

이 브랜치 이전(`feature/security-misconfig-demo`까지)에는 `/api/userinfos/login`에 이런 제한이 전혀 없었다 — 그 상태가 이 문서의 "1단계(취약)"다.

---

## 2. 변경 내역 — 1단계(취약) → 2단계(조치)

### 2-1. 1단계(취약) — 기존 상태

```java
@PostMapping("/login")
public ResponseEntity<AuthResponse> authenticateAndGetToken(@Valid @RequestBody AuthRequest authRequest) {
    Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                    authRequest.getEmail(),
                    authRequest.getPassword()
            ));
    // ... 성공 시 토큰 발급
}
```

비밀번호가 몇 번을 틀리든 서버는 매번 똑같이 `authenticationManager.authenticate(...)`를 수행한다 — 틀린 횟수를 기억하지 않는다.

### 2-2. 2단계(조치) — 추가된 코드

**`UserInfo.java`** — 계정 잠금 상태를 저장할 필드 추가:

```java
//[로그인 시도 제한 - bruteforce-demo] 연속 로그인 실패 횟수. 로그인 성공 시 0으로 초기화된다.
@Column(nullable = false)
private int failedLoginCount;

//[로그인 시도 제한 - bruteforce-demo] 이 시각 이전까지는 비밀번호가 맞아도 로그인을 거부한다.
//  null 이면 잠겨 있지 않은 상태. LoginAttemptService 가 설정/해제한다.
private Instant lockedUntil;
```

**`LoginAttemptService.java`**(신규) — 잠금 판단·실패 누적·성공 시 초기화를 전담:

```java
@Service
@RequiredArgsConstructor
@Slf4j
public class LoginAttemptService {

    private final UserInfoRepository repository;

    @Value("${login.lockout.max-attempts}")
    private int maxAttempts;

    @Value("${login.lockout.duration-seconds}")
    private long lockDurationSeconds;

    /** 잠겨 있으면 LockedException 을 던진다(비밀번호 검증 전에 즉시 차단). */
    @Transactional(readOnly = true)
    public void assertNotLocked(String email) {
        repository.findByEmail(email).ifPresent(user -> {
            Instant lockedUntil = user.getLockedUntil();
            if (lockedUntil != null && lockedUntil.isAfter(Instant.now())) {
                long remainingSeconds = Duration.between(Instant.now(), lockedUntil).getSeconds() + 1;
                throw new LockedException(
                        "로그인 시도 횟수를 초과하여 계정이 잠겼습니다. 약 " + remainingSeconds + "초 후 다시 시도하세요");
            }
        });
    }

    /** 로그인 성공 시 실패 횟수와 잠금을 초기화한다. */
    @Transactional
    public void onSuccess(String email) { /* failedLoginCount=0, lockedUntil=null 저장 */ }

    /** 로그인 실패 시 호출. 실패 횟수를 누적하고, 임계치를 넘으면 계정을 잠근다. */
    @Transactional
    public void onFailure(String email) {
        repository.findByEmail(email).ifPresent(user -> {
            int count = user.getFailedLoginCount() + 1;
            user.setFailedLoginCount(count);
            if (count >= maxAttempts) {
                user.setLockedUntil(Instant.now().plusSeconds(lockDurationSeconds));
                log.warn("[AUDIT] 로그인 시도 제한 - 계정 잠금 - user={}, 실패 횟수={}, 잠금 시간={}초",
                        mask(email), count, lockDurationSeconds);
            }
            repository.save(user);
        });
    }
}
```

**`UserInfoController.login()`** — 잠금 확인 → 인증 시도 → 결과에 따라 초기화/누적:

```java
@PostMapping("/login")
public ResponseEntity<AuthResponse> authenticateAndGetToken(@Valid @RequestBody AuthRequest authRequest) {
    //이미 잠긴 계정이면 비밀번호 검증 없이 즉시 거부한다
    loginAttemptService.assertNotLocked(authRequest.getEmail());

    Authentication authentication;
    try {
        authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authRequest.getEmail(), authRequest.getPassword()));
    } catch (AuthenticationException e) {
        loginAttemptService.onFailure(authRequest.getEmail());
        throw e;
    }

    UserInfoUserDetails userDetails = (UserInfoUserDetails) authentication.getPrincipal();
    loginAttemptService.onSuccess(authRequest.getEmail());
    // ... 이후 토큰 발급은 기존과 동일
}
```

**`application.properties`**:

```properties
# [로그인 시도 제한 - bruteforce-demo] (OWASP #7) 연속 로그인 실패 임계치 초과 시 계정을 일정 시간 잠근다.
login.lockout.max-attempts=5
# 잠금 시간 ( 초 ) - 300초 = 5분
login.lockout.duration-seconds=300
```

> **왜 이 지점(컨트롤러)에서 막았나**: `UserDetails.isAccountNonLocked()`를 오버라이드해 Spring Security의 내부 `LockedException`에 맡기는 방법도 있지만, 그 경로는 메시지가 영문 고정값이고 "몇 초 후 재시도"같은 정보를 줄 수 없다. 대신 `authenticationManager.authenticate(...)` 호출 **앞뒤**를 직접 감싸서, 잠금 여부를 비밀번호 검증 전에 먼저 확인하고(불필요한 해시 비교를 생략), 실패/성공 결과에 따라 직접 카운트를 갱신한다 — 흐름이 컨트롤러 한 곳에 보여서 교육용으로 추적하기 쉽다.

### 2-3. 변경/추가 파일 한눈에 보기

| 파일 | 구분 | 한 일 |
|---|---|---|
| `UserInfo` | 수정 | `failedLoginCount`, `lockedUntil` 필드 추가 |
| `LoginAttemptService` | 추가 | 잠금 확인(`assertNotLocked`)·실패 누적(`onFailure`)·성공 초기화(`onSuccess`) |
| `UserInfoController` | 수정 | `login()`에서 잠금 확인 → 인증 시도 → 성공/실패에 따라 `LoginAttemptService` 호출 |
| `application.properties` | 수정 | `login.lockout.max-attempts=5`, `login.lockout.duration-seconds=300` 추가 |

---

## 3. 공격 실습 — 검증됨(2026-10-14)

### 3-1. curl 로 메커니즘 확인

```bash
# 같은 계정에 틀린 비밀번호로 5회 연속 요청
for i in 1 2 3 4 5; do
  curl -s -X POST http://localhost:8081/api/userinfos/login \
    -H "Content-Type: application/json" \
    -d '{"email":"user@aa.com","password":"wrongpw"}'
done
```

**결과(실측)**:

| 시도 | 결과 |
|---|---|
| 1~4회 | `401` `"자격 증명에 실패하였습니다."` (평소와 동일) |
| 5회(임계치 도달) | `401` `"자격 증명에 실패하였습니다."` — **이 응답 자체는 평소와 같다**(잠금은 이 요청의 실패 처리 *이후*에 걸림). 서버 로그에 `[AUDIT] 로그인 시도 제한 - 계정 잠금 - 실패 횟수=5` 기록 |
| 6회째(비밀번호를 **맞게** 넣어도) | `401` `"로그인 시도 횟수를 초과하여 계정이 잠겼습니다. 약 N초 후 다시 시도하세요"` |

로그인 성공(올바른 비밀번호) 후 다시 틀린 비밀번호를 시도하면, 카운트가 0부터 다시 쌓이는 것도 확인됨(성공 시 초기화).

### 3-2. Burp Suite Intruder로 자동화 재현

1. **Proxy**로 정상 로그인 요청 1건을 가로채서 **Send to Intruder**.
2. **Positions** 탭: `Attack type = Sniper`, 요청 본문의 `password` 값만 `§...§`로 마킹(`email`은 고정).
3. **Payloads** 탭: 흔한 비밀번호 10~20개(사전 리스트) 또는 `Simple list`로 짧은 후보군 입력.
4. **Options → Grep - Match**에 `잠겼습니다` 문자열을 추가해 두면, 결과 테이블에서 **몇 번째 요청부터 잠금 메시지로 바뀌는지** 체크박스로 바로 확인된다.
5. **Start attack** → 결과 테이블의 `Status code`는 전부 `401`로 동일하지만, 5번째 응답까지는 `잠겼습니다` 컬럼이 비어 있고 6번째부터 체크된다 — 자동화된 공격이라도 서버가 **5회 지점에서 차단선을 그었다**는 것을 한눈에 확인할 수 있다.

### 3-3. Burp Suite Repeater로 우회 시도 — 교훈: 안 되는 이유

잠긴 상태에서 **Repeater**로 요청을 다시 보내되, `X-Forwarded-For` 헤더를 다른 IP로 바꿔서 재시도:

```
POST /api/userinfos/login
X-Forwarded-For: 203.0.113.77
...
{"email":"user@aa.com","password":"pwd2"}
```

**결과**: 여전히 `401` `"잠겼습니다"`. 이 구현은 **IP가 아니라 계정(email) 기준**으로 잠그기 때문에, 헤더를 조작해 다른 IP처럼 보여도 우회되지 않는다.

> **그런데 이 설계에는 반대 방향의 약점이 있다** — §4-3 참고.

---

## 4. 방어 원리

### 4-1. 비밀번호 검증보다 먼저 잠금을 확인한다

```java
loginAttemptService.assertNotLocked(authRequest.getEmail());
```
잠긴 계정이면 `authenticationManager.authenticate(...)`(비밀번호 해시 비교 포함)를 아예 호출하지 않는다 — 불필요한 CPU 비용을 줄이고, 잠겨 있다는 사실을 더 빠르고 명확하게 응답한다.

### 4-2. 성공하면 즉시 초기화한다

```java
loginAttemptService.onSuccess(authRequest.getEmail());
```
실패를 몇 번 하다가도 결국 올바른 비밀번호로 로그인하면 카운트를 0으로 되돌린다 — 정상 사용자가 비밀번호를 몇 번 오타 냈다고 누적되어 다음에 불이익을 받지 않게 한다.

### 4-3. 한계와 트레이드오프 (중요)

**계정 기준 잠금은 가용성 공격(DoS)에 노출된다.** 공격자가 피해자의 **이메일만** 알면(비밀번호는 몰라도) 일부러 5번 틀려서 그 계정을 잠가버릴 수 있다 — 정작 피해자 본인도 5분(또는 설정한 시간) 동안 로그인할 수 없다. 이번 §3-3에서 확인했듯 IP 기준이 아니므로, "한 사람이 계정 여러 개를 공격"하는 시나리오엔 강하지만 "여러 사람이 한 계정을 공격"하는 시나리오엔 취약하다.

실무에서는 아래를 조합해 완화한다(이 브랜치엔 미적용 — 범위 밖):
- **IP 기준 속도 제한**(예: Bucket4j)을 계정 기준과 병행 — 짧은 시간에 과도한 요청을 보내는 IP 자체도 함께 제한.
- **점진적 백오프**(실패할 때마다 잠금 시간을 2배씩 늘리는 등) — 고정 300초 대신 1차 5회/5초, 2차 10회/1분처럼 단계화.
- **CAPTCHA**(일정 실패 횟수 이후 사람인지 확인) — 자동화 도구의 반복 자체를 어렵게 만듦.

### 검증 (안전 버전, 검증됨)

| 테스트 | 결과 |
|---|---|
| 같은 계정 5회 연속 실패 | 5회째까지는 평소와 같은 401, 5회째 처리 중 계정 잠금(`[AUDIT]` 로그) |
| 잠긴 상태에서 **올바른** 비밀번호로 재시도 | 401 "잠겼습니다" — 비밀번호 정답 여부와 무관하게 거부 |
| 로그인 성공 후 재실패 | 카운트가 0부터 다시 쌓임(성공 시 초기화 확인) |
| Repeater로 `X-Forwarded-For` 변조 후 재시도 | 여전히 401 — 계정 기준이라 IP 변조로 우회되지 않음 |

---

## 5. 방어 정리

| 방법 | 설명 |
|---|---|
| **계정 잠금**(핵심, 적용됨) | 연속 N회(기본 5회) 실패 시 일정 시간(기본 300초) 해당 계정의 로그인을 거부 |
| **실패 비용 최소화** | 잠긴 계정은 비밀번호 검증 자체를 생략하고 즉시 거부 |
| **성공 시 초기화** | 정상 사용자의 일시적 오타가 누적되어 불이익을 주지 않음 |
| IP 기준 속도 제한(미적용·향후 보강) | 계정 잠금의 DoS 악용(§4-3)을 보완 — 여러 계정을 공격하는 IP 자체를 제한 |

> **교육 포인트**: "시도 횟수 제한"은 브루트포스를 막는 가장 기본적인 방어지만, **공짜가 아니다** — 어떤 단위(계정? IP? 둘 다?)로 제한하느냐에 따라 막는 공격과 새로 생기는 약점(가용성 공격)이 달라진다. Burp Suite Intruder/Repeater로 직접 찔러보면 "막힌 것"과 "그 대신 생긴 약점"을 둘 다 눈으로 확인할 수 있다.

---

## 6. 관련 문서
- OWASP Top 10 2025 #7 식별 및 인증 실패
- 전체 진행: `00_App_Security_Review.md`
- 같은 `/api/userinfos/login` 경로를 다루는 다른 보강: `06_JWT_Security.md`(토큰 발급/회전), `04_Logging_Hardening.md`(인증 실패 감사 로그 — 이 문서의 잠금 로그도 같은 `[AUDIT]` 규칙을 따름)
