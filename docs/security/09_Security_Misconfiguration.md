# 09. 보안 설정 오류 (Security Misconfiguration) 실습

> OWASP Top 10 2025 **#2 보안 설정 오류**(Security Misconfiguration) — 2021년 #5에서 #2로 순위가 올라간 항목
> 브랜치: `feature/security-misconfig-demo` (`feature/deserialization-demo`에서 분기)
> 대상 코드: `application.properties`(Actuator 설정) + `SecurityConfig.java`

---

## 1. 개념 요약

**보안 설정 오류**는 코드의 로직 결함이 아니라, **설정값 하나가 기본 보호를 꺼버려서** 생기는 취약점이다. OWASP 정의상 전형적인 예시가 "기본 비밀번호·불필요한 기능 활성화·상세 오류 노출"인데, 이번 데모는 그중 "불필요한 기능 활성화"에 해당한다.

이 앱은 운영 모니터링을 위해 **Spring Boot Actuator**(`spring-boot-starter-actuator`)를 이미 의존성으로 가지고 있다. Actuator는 `/actuator/env`(현재 적용된 설정값 전체), `/actuator/beans`(스프링 빈 목록), `/actuator/mappings`(모든 URL 매핑) 같은, **애플리케이션 내부 구조와 설정을 그대로 보여주는** 엔드포인트를 제공한다. 운영 점검에는 유용하지만, **누구나 인증 없이** 조회할 수 있다면 그 자체로 정보 유출이다.

**이 브랜치에서 발견한 핵심 결함**: `SecurityConfig`의 `formLoginFilterChain`은 `/actuator/**`에 대한 규칙이 전혀 없다 → 결국 맨 마지막 `.anyRequest().permitAll()`에 걸려 **이미 인증 없이 열려 있었다.** 지금까지는 `management.endpoints.web.exposure.include`가 기본값(`health`만)이라 피해가 드러나지 않았을 뿐, **노출 범위를 넓히는 설정 한 줄만 추가되면 바로 실제 사고로 이어지는 "잠재 결함"**이었다.

---

## 2. 변경 내역 — 1단계(취약) → 2단계(조치)

### 2-1. 1단계(취약) — `application.properties`

```properties
# [보안 설정 오류 데모 - 1단계(취약)] Actuator 를 전부 노출한다.
management.endpoints.web.exposure.include=*

# [보안 설정 오류 데모 - 1단계(취약)] Actuator 는 기본적으로 /actuator/env 의 값 자체를
# "******" 로 가려서 보여준다(최신 Spring Boot 기본값: show-values=NEVER). 그런데 디버깅 편의로
# 이 기본 보호를 직접 꺼버리는 설정이 실무에서 자주 발견된다 → 그 상태를 재현한다.
management.endpoint.env.show-values=always

partner.billing.code=PTNR-8841-REALCODE
```

**처음 가정했던 것과 실제가 달랐던 부분** — 처음엔 "`password`/`secret`/`key`/`token` 같은 단어가 이름에 없으면 Spring Boot의 자동 마스킹(Sanitizer)을 피해서 평문으로 샌다"고 가정하고 `partner.billing.code`만 추가했다. 그런데 실제로 서버에 curl을 날려보니 `jwt.secret`까지 포함해서 **전부 `******`로 가려져 있었다** — 최신 Spring Boot는 `show-values` 기본값 자체가 `NEVER`라서, 이름이 뭐든 **값 자체를 아예 안 보여준다.** 그래서 실무에서 더 흔하게 발생하는 원인, 즉 **누군가 디버깅 편의로 `show-values=always`를 직접 켜서 이 기본 보호를 꺼버리는 설정**을 추가해서 재현했다. (이 과정 자체가 "가정하지 말고 실측하라"는 교훈을 보여준다.)

### 2-2. 2단계(조치) — `application.properties`

```properties
# [보안 설정 오류 데모 - 2단계(조치)] Actuator 노출 범위를 꼭 필요한 것만으로 축소한다.
management.endpoints.web.exposure.include=${ACTUATOR_EXPOSURE:health,info}

# show-values 는 Spring Boot 기본값(NEVER)을 그대로 쓴다.
# (1단계에서 always 로 바꿔 평문 노출을 재현했던 설정을 제거함)

partner.billing.code=PTNR-8841-REALCODE
```

### 2-3. 2단계(조치) — `SecurityConfig.java`

```java
auth.requestMatchers("/login/**").permitAll()
        .requestMatchers("/users/**").authenticated()
        //[보안 설정 오류 하드닝] (OWASP #2) Actuator는 노출 범위(exposure.include)를
        //최소화해도, 혹시 나중에 다시 넓어질 경우를 대비해 인증을 한 겹 더 요구한다.
        //헬스체크는 로드밸런서 등 외부 도구가 인증 없이 호출해야 하므로 예외로 둔다.
        .requestMatchers("/actuator/health", "/actuator/info").permitAll()
        .requestMatchers("/actuator/**").hasAuthority("ROLE_ADMIN")
        //로그인 페이지·정적 리소스·루트 등 나머지는 접근 허용
        .anyRequest().permitAll();
```

### 2-4. 변경/추가 파일 한눈에 보기

| 파일 | 구분 | 한 일 |
|---|---|---|
| `application.properties` | 수정 | 1단계: Actuator 전체 노출 + `show-values=always` + 데모용 설정값 추가 → 2단계: 노출 범위 축소(`health,info`), `show-values` 기본값 복귀 |
| `SecurityConfig.java` | 수정 | `/actuator/health`·`/actuator/info`는 허용, 나머지 `/actuator/**`는 `ROLE_ADMIN` 인증 요구 추가 |
| `actuator_probe.py` | 추가 | `/actuator/env` 등의 노출 여부·값을 조회만 하는 점검 스크립트 |

---

## 3. 공격 실습 (검증됨 — 2026-10-05)

### 3-1. 1단계(취약) 상태에서 — 노출 확인

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/actuator/env
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/actuator/beans
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/actuator/mappings
```

**결과**: 셋 다 `200` — 인증 토큰이나 세션 없이 그대로 조회됐다.

```bash
curl -s http://localhost:8080/actuator/env   # JSON 전체에서 propertySources[].properties 확인
```

**결과(실측)**:

| 키 | 1단계(취약)에서의 값 |
|---|---|
| `partner.billing.code` | `PTNR-8841-REALCODE` (평문 그대로) |
| `jwt.secret` | 평문 노출 확인됨 — **실제 운영 비밀키라 이 문서엔 값을 싣지 않는다** |
| `voucher.hmac-secret` | 평문 노출 확인됨 — 동일한 이유로 값 미게재 |

> **중요한 교훈**: `show-values=always`는 "이름이 수상해 보이는 값만" 가리는 게 아니라 **마스킹 기능 자체를 전부 끈다.** `jwt.secret`처럼 이름에 `secret`이 들어 있어 평소엔 자동으로 가려지는 값도, 이 설정 한 줄 때문에 **전부** 평문으로 샌다. (실습 중 실제로 서버에 주입돼 있던 `JWT_SECRET` 값이 이 과정에서 노출되었으므로, 데모 종료 후 해당 비밀키를 교체(rotate)하는 것을 권장한다.)

### 3-2. 2단계(조치) 적용 후 — 차단 확인

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/actuator/env
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/actuator/beans
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/actuator/mappings
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/actuator/health
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/actuator/info
```

**결과(실측)**:

| 경로 | 1단계(취약) | 2단계(조치) |
|---|---|---|
| `/actuator/env` | `200` (평문 노출) | `302` (로그인 페이지로 리다이렉트, 데이터 미노출) |
| `/actuator/beans` | `200` | `302` |
| `/actuator/mappings` | `200` | `302` |
| `/actuator/health` | `200` | `200` (그대로 허용 — 모니터링 도구용) |
| `/actuator/info` | `200` | `200` |

`302`는 인증되지 않은 요청을 로그인 페이지로 돌려보낸 것이라, 응답 본문에는 로그인 폼 HTML만 담겨 있고 **실제 데이터는 전혀 포함되지 않는다.** 노출 범위를 좁힌 것(`health,info`만 노출)과 `SecurityConfig`의 인증 요구, 두 조치 중 **인증 계층이 먼저 요청을 가로채서 차단**하는 것까지 확인했다 — 혹시 나중에 노출 범위 설정이 다시 넓어져도 이 계층이 한 번 더 막아준다는 뜻이다.

### 3-3. 점검 스크립트로 재현

```bash
python docs/security/actuator_probe.py http://localhost:8080
```
`actuator_probe.py`는 값을 변조하지 않고 **조회만** 한다 — `/actuator/env`에서 `partner.billing.code`/`jwt.secret`/`voucher.hmac-secret` 값을 확인하고, `/actuator/beans`·`/actuator/mappings`·`/actuator/health`·`/actuator/info`의 HTTP 상태코드를 출력한다.

---

## 4. 방어 원리

### 4-1. 불필요한 기능 끄기 — 노출 범위 최소화

```properties
management.endpoints.web.exposure.include=${ACTUATOR_EXPOSURE:health,info}
```
Actuator가 제공하는 기능을 전부 켜 둘 필요는 없다. **로드밸런서·모니터링 도구가 실제로 쓰는 것**(`health`, `info`)만 남기고, `env`/`beans`/`mappings`처럼 내부 구조·설정을 드러내는 엔드포인트는 꺼 둔다. 운영 중 정말 필요하면 환경변수(`ACTUATOR_EXPOSURE`)로만 넓히게 해서, "기본값은 최소"가 유지되게 한다.

### 4-2. 심층 방어 — 인증을 한 겹 더

```java
.requestMatchers("/actuator/health", "/actuator/info").permitAll()
.requestMatchers("/actuator/**").hasAuthority("ROLE_ADMIN")
```
4-1만으로도 지금은 막히지만, **설정 하나(`exposure.include`)에만 안전을 의존하는 것은 위험하다** — 누군가 운영 편의로 그 값을 다시 넓히는 순간 똑같은 사고가 재현된다. `SecurityConfig`에 별도로 인증 규칙을 둬서, 노출 범위 설정과 무관하게 **관리자만** 접근하도록 두 번째 방어선을 만든다. 이번 실습에서 노출 범위를 좁히는 것만으로 이미 `env`/`beans`/`mappings`가 사라졌지만(§3-2), 이 인증 계층이 먼저 요청을 가로채 `302`로 돌려보내는 것까지 확인했다 — 두 방어가 동시에 작동한다.

### 4-3. 기본값을 함부로 끄지 않기

```properties
# 1단계에서 always 로 바꿔 평문 노출을 재현했던 설정을 제거함
```
`show-values=NEVER`(기본값)는 "이름이 수상한 값만" 가리는 정교한 기능이 아니라, **값 자체를 통째로 숨기는 안전한 기본값**이다. 디버깅하다가 `******`가 거추장스러워서 `always`로 바꾸는 것은, 그 기본 보호를 "필요할 때만 잠깐"이 아니라 **영구적으로 꺼버리는 것**과 같다. 디버깅이 끝나면 반드시 되돌려야 하고, 가장 안전한 방법은 **처음부터 건드리지 않는 것**이다.

### 검증 (안전 버전, 검증됨)

| 테스트 | 결과 |
|---|---|
| 노출 범위를 `health,info`로 축소 | `env`/`beans`/`mappings` 자체가 더 이상 응답하지 않음 |
| `SecurityConfig`에 `/actuator/**` 인증 요구 추가 | 인증 없는 요청은 `302`(로그인 페이지)로 차단, 데이터 미노출 |
| `/actuator/health`, `/actuator/info` | 인증 없이도 `200` 유지 — 모니터링 기능은 그대로 동작 |

---

## 5. 방어 정리

| 방법 | 설명 |
|---|---|
| **노출 범위 최소화**(핵심) | 꼭 필요한 Actuator 엔드포인트(`health`,`info`)만 켜 두기 — "불필요한 기능 끄기" |
| **인증 요구**(심층 방어) | 노출 범위 설정이 나중에 넓어져도 대비할 수 있도록 `/actuator/**`에 별도 인증 규칙 추가 |
| **기본값 유지** | `show-values` 같은 보안 기본값은 디버깅 편의로 끄지 않기 — 끈 경우 반드시 원복 |
| 비밀값 교체(사고 대응) | 실제로 노출된 적이 있는 비밀키(`JWT_SECRET` 등)는 재사용하지 말고 교체(rotate) |

> **교육 포인트**: 이번 데모는 새 코드를 "취약하게" 작성해서 만든 취약점이 아니라, **이미 있던 설정(`anyRequest().permitAll()`)과 흔한 운영 습관(Actuator 전체 노출, 디버깅용 `show-values=always`)이 겹쳤을 때** 실제 사고로 이어진다는 것을 보여준다. 보안 설정 오류는 "아직 아무도 안 건드렸을 뿐인" 잠재 결함인 경우가 많다.

---

## 6. 관련 문서
- OWASP Top 10 2025 #2 보안 설정 오류 — 2021년 #5에서 #2로 순위 상승
- 전체 진행: `00_App_Security_Review.md`
- 실무 팁: 이 데모의 `jwt.secret`/`voucher.hmac-secret` 자동 마스킹 여부는 `06_JWT_Security.md`, `08_Insecure_Deserialization.md`에서 다룬 비밀키들과 같은 값이다 — "비밀키 자체를 안전하게 관리"하는 것과 "그 값을 보여주는 창구(Actuator)를 잠그는 것"은 서로 다른, 둘 다 필요한 방어다.
