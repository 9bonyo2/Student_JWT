# 05. CSRF (Cross-Site Request Forgery) 실습

> OWASP Top 10 2025 **#1 접근 제어 실패**(넓게) 
> 브랜치: `feature/csrf-demo`
> 대상 코드: `com.basic.myspringboot.vuln.csrf` + `SecurityConfig`(세션 체인)

---

## 1. 개념 요약

**CSRF(Cross-Site Request Forgery, 사이트 간 요청 위조)** 는 **로그인된 사용자의 브라우저**가 공격자의 페이지에 의해, 본인도 모르게 상태 변경 요청(비밀번호 변경·이체 등)을 보내게 되는 공격이다.

- 브라우저는 특정 사이트로 요청할 때 **그 사이트의 쿠키(JSESSIONID 등)를 자동 첨부**한다.
- 공격자는 피해자를 자기 페이지로 유인해, 피해자 몰래 대상 사이트로 **위조 요청**을 보낸다.
- 대상 사이트가 "이 요청이 정말 우리 화면에서 온 것인지"를 검증하지 않으면 그대로 실행된다.

**핵심**: CSRF는 **세션+쿠키 기반 인증**의 문제다. JWT를 `Authorization` 헤더로 보내는 REST는 쿠키가 자동 전송되지 않아 CSRF 위험이 낮다.

---

## 2. 이 앱의 취약점

`SecurityConfig`의 **세션(폼 로그인) 체인에 CSRF가 비활성화**되어 있었다.
```java
// (취약) 세션+쿠키 기반인데 CSRF 보호가 꺼져 있음
return http.csrf(csrf -> csrf.disable()) ...
```
→ 로그인된 사용자를 노려 비밀번호 변경 등 위조 요청이 가능하다.

**표적 엔드포인트** (세션 인증): `POST /users/change-password` (로그인 사용자의 비밀번호 변경)

### 2-1. CsrfDemoController (데모 컨트롤러)

세션 인증 하에서 **로그인 사용자의 비밀번호를 변경**하는 데모 엔드포인트다. `GET`은 폼, `POST`는 변경 처리이며, 로그인 주체(`UserInfoUserDetails`)의 `UserInfo` 비밀번호를 BCrypt로 바꾼다.

```java
@Controller
@RequestMapping("/users")
public class CsrfDemoController {
    @GetMapping("/change-password")           // 변경 폼
    public String form() { return "change-password"; }

    @PostMapping("/change-password")          // 변경 처리 = CSRF 표적
    public String changePassword(@RequestParam String newPassword,
                                 @AuthenticationPrincipal UserInfoUserDetails me, Model model) {
        UserInfo user = userInfoRepository.findByEmail(me.getUsername()).orElseThrow(...);
        user.setPassword(passwordEncoder.encode(newPassword));   // 상태 변경
        userInfoRepository.save(user);
        return "change-password";
    }
}
```
- 이 **POST가 CSRF의 표적**이다. 폼(`change-password.html`)은 `th:action`이라 CSRF 활성 시 `_csrf` 토큰이 자동 삽입되고, 공격자 페이지의 위조 요청은 토큰이 없어 차단된다.

### 2-2. change-password.html (비밀번호 변경 폼)

Thymeleaf 폼 페이지. `th:action`으로 POST하며, CSRF 활성 시 hidden `_csrf` 토큰이 자동 삽입된다.
```html
<form th:action="@{/users/change-password}" method="post">
  <input type="password" name="newPassword" required />
  <button type="submit">변경</button>
  <!-- CSRF 활성 시 여기에 <input type="hidden" name="_csrf" ...> 자동 삽입 -->
</form>
```
- **접근 경로**: 로그인 후 네비게이션(navbar)의 "비밀번호 변경" 링크(`sec:authorize="isAuthenticated()"`)로 들어간다.
- 정상 폼은 토큰이 있어 통과, 공격자 페이지의 위조 폼은 토큰이 없어 **403**.

### 2-3. PRG(Post-Redirect-Get) 패턴

비밀번호 변경(POST) 처리 후, 변경 폼에 머물지 않고 다른 경로(`/users/index`)로 **리다이렉트**한다. 성공 메시지는 **flash attribute**로 전달한다.
```java
// 변경 처리 후
redirectAttributes.addFlashAttribute("msg", email + " 의 비밀번호가 변경되었습니다.");
return "redirect:/users/index";   // 폼에 머물지 않고 이동
```
**PRG = POST → Redirect → GET.** 이점:
- **새로고침 시 폼 재제출(중복 변경) 방지** — POST 결과 화면을 새로고침하면 브라우저가 "재전송?"을 묻는 문제를 없앤다
- 성공 메시지를 flash로 한 번만 표시(리다이렉트된 페이지에서)
- 사용자가 변경 폼에 머물지 않고 목록으로 자연스럽게 이동

> 흐름: 변경 POST → **302 redirect** → GET `/users/index` → 성공 메시지(alert) 표시 (검증됨)

---

## 3. 공격 실습 (취약 상태)

### 3-1. 공격자 페이지
`docs/security/csrf_attack.html` — 방문하면 `onload`로 위조 폼이 자동 제출된다.
```html
<body onload="document.getElementById('csrf').submit()">
  <form id="csrf" action="http://localhost:8080/users/change-password" method="post">
    <input type="hidden" name="newPassword" value="attacker_pw_1234" />
  </form>
</body>
```

### 3-2. 시나리오
1. 피해자가 앱에 폼 로그인 (세션 쿠키 `JSESSIONID` 보유)
2. 피해자가 공격자 페이지 방문 (메일·링크로 유도)
3. 브라우저가 위조 요청을 보내며 **세션 쿠키를 자동 첨부**
4. CSRF 보호가 없으면 → **비밀번호가 `attacker_pw_1234`로 변경** → 계정 탈취

### 3-3. curl 재현 (검증됨)
```bash
B=http://localhost:8080; JAR=cookies.txt
# 1) 피해자 로그인 → 세션 쿠키
curl -s -c $JAR -X POST "$B/login-process" -d "username=user@aa.com&password=pwd2"
# 2) 위조 요청 (쿠키O, CSRF 토큰X)
curl -s -b $JAR -X POST "$B/users/change-password" -d "newPassword=attacker_pw_1234"
# 3) 공격자 비번으로 로그인 → 성공하면 탈취 완료
curl -s -X POST "$B/api/userinfos/login" -H "Content-Type: application/json" \
  -d '{"email":"user@aa.com","password":"attacker_pw_1234"}'
```
결과: 위조 POST **HTTP 200**, 공격자 비번 로그인 **HTTP 200** → **CSRF 공격 성공(계정 탈취)**

### 3-4. CSRF 설정 on/off 결과 비교

같은 공격 절차를 CSRF 비활성/활성에서 각각 실행한 결과(검증됨):

| 단계 | CSRF **비활성**(취약) | CSRF **활성**(안전) |
|---|---|---|
| 로그인(토큰없이) | **302** 성공 | **403** (로그인도 토큰 필요) |
| 위조 change-password | **200** (비번 변경) | **403** 차단 |
| 공격자 비번 로그인 | **200** (탈취) | **401** 실패 |

> **주의**: CSRF 비활성으로 바꾼 뒤에도 로그인이 403이면, `csrf.disable()` 변경 후 **앱을 재시작하지 않은 것**이다(변경 미적용). 취약 상태에선 로그인이 **302**로 성공해야 한다.
> CSRF 활성 시엔 로그인조차 토큰이 필요하므로, curl로 로그인하려면 먼저 `GET /login`에서 `_csrf` 토큰을 받아야 한다. (브라우저 폼은 Thymeleaf가 자동 처리)

---

## 4. 방어 (안전 버전)

세션 체인의 CSRF 보호를 **켠다**(Spring Security 기본값). JWT 체인은 헤더 기반이라 그대로 둔다.
```java
// (안전) 세션+쿠키 기반이므로 CSRF 보호 활성화(기본값). csrf.disable() 제거
return http
        .authorizeHttpRequests(auth -> { ... })
        .formLogin( ... )
```
- **Thymeleaf 폼**(`th:action`)에는 hidden `_csrf` 토큰이 **자동 삽입**되어 정상 동작
- 공격자 페이지의 위조 요청은 **토큰이 없어 403**으로 거부

### 검증 (안전 상태, 검증됨)
| 테스트 | 결과 |
|---|---|
| `/login` 폼의 `_csrf` 토큰 | 자동 주입됨 (`nKFCV2ulcr0_...`) |
| 정상 로그인 (토큰 포함) | **302**  |
|  위조 요청 (토큰 없음) | **403** (차단)  |
|  정상 변경 (토큰 포함) | **200**  |

> **교육 포인트**: "REST(JWT 헤더)는 CSRF를 꺼도 되지만, 세션+쿠키는 반드시 켜야 한다." 인증 방식에 따라 CSRF 판단이 다르다.

### curl로 CSRF 토큰 받아 로그인하기

CSRF가 켜진 상태에서는 `curl`로 `/login-process`를 바로 호출하면 토큰이 없어 `403`으로 거부된다. 브라우저는 Thymeleaf가 폼에 `_csrf` 히든 필드를 자동으로 넣어주지만, `curl`은 직접 두 단계를 거쳐야 한다.

1. `GET /login` — 세션 쿠키(`JSESSIONID`)와, 응답 HTML의 `<input name="_csrf" value="...">`에 담긴 토큰을 함께 받는다.
2. 같은 쿠키 + 받은 토큰으로 `POST /login-process`를 호출한다.

```bash
EMAIL=admin@aa.com; PASSWORD=pwd1; B=http://localhost:8080; JAR=$(mktemp)

# 1) 로그인 페이지에서 세션 쿠키 + _csrf 토큰 획득
LOGIN_PAGE=$(curl -s -c "$JAR" "$B/login")
CSRF=$(echo "$LOGIN_PAGE" | grep -o 'name="_csrf" value="[^"]*"' | sed 's/.*value="\([^"]*\)".*/\1/')

# 2) 같은 쿠키(세션)로 로그인 시도
curl -s -b "$JAR" -c "$JAR" -X POST "$B/login-process" \
  --data-urlencode "username=$EMAIL" \
  --data-urlencode "password=$PASSWORD" \
  --data-urlencode "_csrf=$CSRF" \
  -D - -o /dev/null | grep -i "^HTTP\|^Location"
```

**결과(검증됨)**:

| 케이스 | 자격 증명 | 결과 |
|---|---|---|
| 성공 | `admin@aa.com` / `pwd1` | `302` → `Location: /users/index` |
| 실패 | `user@aa.com` / 틀린 비밀번호 | `302` → `Location: /login?error` |

두 경우 모두 `403`이 아니라 `302`가 나온다는 점이 중요하다 — CSRF 토큰 검증은 통과했고, 그 뒤의 아이디·비밀번호 검증 결과에 따라 성공/실패 리다이렉트만 갈리는 것이다. 토큰 자체가 빠지거나 틀리면 이 단계까지 가지도 못하고 `403`으로 막힌다.

### 4-1. 명시적 CSRF 설정

Spring Security는 CSRF가 **기본 활성**이라 아무것도 안 하면 켜진다. 명시하거나 토큰 저장소를 바꾸려면:

```java
// (1) 기본값으로 명시적 활성화
http.csrf(Customizer.withDefaults());

// (2) 토큰 저장소를 세션에 (기본 동작을 명시)
http.csrf(csrf -> csrf.csrfTokenRepository(new HttpSessionCsrfTokenRepository()));

// (3) SPA용: JS가 읽을 수 있는 쿠키에 토큰 저장
http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));

// (4) 특정 경로만 예외(예: 순수 REST)
http.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"));
```
> 이 앱은 JWT 체인(`/api/**`)은 `csrf.disable()`, 세션 체인은 기본 활성(disable 제거)으로 인증 방식별로 구분했다.

### 4-2. Thymeleaf 폼의 `_csrf` 자동 삽입 원리

- Spring Security가 `RequestDataValueProcessor`(CsrfRequestDataValueProcessor)를 제공하고, Thymeleaf가 `th:action` 폼을 렌더링할 때 이 프로세서를 호출해 **hidden `_csrf` 필드를 자동 추가**한다. (`thymeleaf-extras-springsecurity6` 의존성이 있으면 동작)
- 렌더링 결과(브라우저가 받는 HTML):
```html
<form action="/users/change-password" method="post">
  <input type="hidden" name="_csrf" value="nKFCV2ulcr0_lR56..."/>
  ...
</form>
```
- 그래서 `th:action` 폼은 개발자가 토큰을 신경 쓰지 않아도 되고, **공격자 페이지는 이 토큰 값을 알 수 없어 403**이 된다.
- AJAX/수동 요청은 `${_csrf.token}`, `${_csrf.headerName}`으로 토큰을 꺼내 헤더/파라미터에 넣는다.

---

## 5. 추가 이슈 : 상태 변경 GET (취약 재현 vs 안전)

CSRF의 두 번째 벡터는 **상태 변경을 GET으로 받는 것**이다. **CSRF 토큰은 GET 요청에는 적용되지 않으므로**, CSRF를 켜도 `<img src="http://localhost:8080/users/delete/1">` 한 줄로 삭제가 트리거된다. 이 위험을 직접 눈으로 보기 위해, 이 앱은 **같은 경로에 안전(POST)·취약(GET) 삭제를 함께** 두었다.

### 5-1. 안전 버전 : 삭제를 POST(+CSRF 토큰)로

삭제는 상태 변경이므로 POST로 받는다. Thymeleaf가 `_csrf` 토큰을 자동 삽입하고, 위조 요청은 토큰이 없어 차단된다.
```java
@PostMapping("/delete/{id}")          // 안전  index.html 삭제 폼이 사용
public String deleteUser(@PathVariable long id) { deleteById(id); return "redirect:/users/index"; }
```
```html
<!-- index.html : POST 폼(_csrf 자동 삽입) -->
<form th:action="@{/users/delete/{id}(id=${user.id})}" method="post" style="display:inline"
      onsubmit="return confirm('Are you sure?')">
  <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
</form>
```

### 5-2. 취약 버전(예전 방식) : GET 삭제 — `<img>` 공격 재현

같은 경로에 **GET 핸들러를 함께** 둔다. HTTP 메서드가 달라(GET↔POST) 별도로 매핑되며, GET은 CSRF 토큰 검증 대상이 아니므로 토큰 없이도 실행된다.
```java
//[취약  - 공격 재현 실습 전용] GET 은 CSRF 토큰 검증을 우회한다
@GetMapping("/delete/{id}")
public String deleteUserLegacyVulnerable(@PathVariable long id) { deleteById(id); return "redirect:/users/index"; }
```
공격자 페이지(`csrf_attack.html`)에 아래 한 줄만 있으면, 로그인된 피해자가 그 페이지를 여는 순간 **세션 쿠키(JSESSIONID)가 자동 첨부**되어 삭제가 실행된다.
```html
<!-- 이미지 로딩 = GET 요청. _csrf 토큰이 없어도 GET 이라 통과된다 -->
<img src="http://localhost:8080/users/delete/1" width="1" height="1" />
```
**브라우저 재현 시 주의(SameSite/CORS)**: `<img>` 자동 공격은 브라우저 방어 계층 때문에 조건이 까다롭다.
- `file://` → Origin이 `null`이라 앱의 CORS 필터가 거부("Invalid CORS request")
- `127.0.0.1:5500` → `localhost:8080`과 **다른 site**라 SameSite=Lax가 쿠키를 막음(크로스사이트 `<img>` 차단 = 브라우저 보조 방어)
- 성공시키려면 **같은 site**에서 서빙(`http://localhost:5500`, 호스트명을 `localhost`로) + 로그인 상태여야 한다.
- 서버 취약점만 확실히 보려면 아래 **curl**이 가장 명확하다(브라우저 계층 우회).

curl 재현 (검증됨, 2026-09-30). **`{id}`는 자리표시자다** — 그대로 실행하면 `long` 변환 실패로 500이 난다. 아래는 삭제할 **테스트 User를 스스로 만들어** `$ID`에 담으므로 실데이터를 건드리지 않는다.
```bash
B=http://localhost:8080; JAR=cookies.txt
# 0) 삭제 대상 테스트 User 생성 (JWT 발급 → POST /api/users → 생성된 id 획득)
TOKEN=$(curl -s -X POST "$B/api/userinfos/login" -H "Content-Type: application/json" \
  -d '{"email":"admin@aa.com","password":"pwd1"}' | python -c "import sys,json;print(json.load(sys.stdin)['accessToken'])")
ID=$(curl -s -X POST "$B/api/users" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"victim","email":"victim@test.local"}' | python -c "import sys,json;print(json.load(sys.stdin)['id'])")
echo "target ID=$ID"

# 1) 세션 로그인 (CSRF 활성이라 _csrf 필요 → GET /login 에서 추출)
CSRF=$(curl -s -c $JAR "$B/login" | grep -oP 'name="_csrf"[^>]*value="\K[^"]+')
curl -s -b $JAR -c $JAR -X POST "$B/login-process" \
  --data-urlencode "username=user@aa.com" --data-urlencode "password=pwd2" \
  --data-urlencode "_csrf=$CSRF"                          # 세션 인증(302)

# 2) 세션 쿠키만(토큰X)으로 GET 삭제 = <img> 재현
curl -s -o /dev/null -w "GET delete -> %{http_code}\n" -b $JAR "$B/users/delete/$ID"   # 302 = 삭제됨
```
> 직접 만든 사용자 대신 목록의 실제 id를 지우려면 `ID=1` 처럼 **존재하는 값**으로 바꿔 쓴다(그 사용자는 삭제된다).

**명령 해설** — 실제 공격은 마지막 한 줄(5)뿐이고, 앞 단계는 그 조건(로그인 세션·삭제 대상)을 curl로 갖추는 준비다.

| 단계 | 명령 | 하는 일 / 이유 |
|---|---|---|
| 1 | `TOKEN=…login` | 관리자로 **JWT 발급**. `/api/users`(User 생성)가 인증을 요구하므로 먼저 토큰을 받는다 |
| 2 | `ID=…/api/users` | 지울 **테스트 User를 생성**하고 응답 JSON에서 `id`를 뽑아 `$ID`에 저장(실데이터 보호) |
| 3 | `CSRF=…/login` | 로그인 페이지의 hidden `_csrf` 값을 추출. **CSRF가 켜져 있어 로그인 POST에도 토큰이 필요**하다 |
| 4 | `…/login-process` | username·password·`_csrf`로 **세션 로그인** → 응답 쿠키 `JSESSIONID`가 `$JAR`에 저장(302) |
| 5 | `…/users/delete/$ID` | **세션 쿠키만**(`-b $JAR`, `_csrf` 없음) 실어 `GET` 삭제. GET이라 토큰 검증을 건너뛰어 302 삭제 → `<img src=".../delete/ID">`가 하는 일 |

> 보조 도구: `python -c "…json…"` 은 응답 JSON에서 값 하나(`accessToken`/`id`)를 꺼내는 용도, `grep -oP '…\K…'` 는 HTML에서 `_csrf` value만 추출하는 용도다.

**검증 결과** — 동일하게 *세션 쿠키만 보내고 `_csrf`는 없이* 삭제 시도(대비):

| 요청 | 전송 | 결과 |
|---|---|---|
| `GET /users/delete/{id}` | JSESSIONID만 (토큰X) | **302 → 삭제됨**  (GET은 CSRF 미검증) |
| `POST /users/delete/{id}` | JSESSIONID만 (토큰X) | **403 → 차단**  (POST는 토큰 필수) |

> 두 요청은 **HTTP 메서드만 다르다.** GET은 삭제 성공, POST는 403 → "상태 변경을 GET으로 두는 설계" 자체가 CSRF 토큰을 무력화함을 실측으로 확인.

### 5-3. 진짜 방어 : GET 핸들러 제거

`<img>` GET 삭제는 **CSRF 토큰으로 막을 수 없다.** 유일한 방어는 **상태 변경을 GET으로 받지 않는 것** — 즉 GET 핸들러를 제거하고 POST(+`_csrf`)만 남기는 것이다.

| 동작 | 안전 POST만 있을 때 | 취약 GET이 있을 때 |
|---|---|---|
| `<img>` GET 삭제 | **405** (거부)  | **302** (삭제됨)  |
|  위조 삭제 POST(토큰X) | **403** (CSRF 차단)  | **403**  |
|  정상 삭제 POST(토큰O) | **302** (삭제됨)  | **302**  |

> **교육 포인트**: "토큰만 켜면 안전"이 아니다. **GET으로 상태를 바꾸는 설계 자체**가 CSRF 토큰을 무력화한다. 방어는 토큰 + "상태 변경은 비-GET" 두 가지가 함께여야 한다.
> **참고**: GET 삭제를 제거한 뒤 405가 500으로 바뀌지 않으려면, #10 예외 하드닝의 catch-all(`@ExceptionHandler(Exception.class)`)이 표준 MVC 예외(405/404 등)를 삼키지 않아야 한다(`ErrorResponse`는 재던짐).

---

## 6. 방어 정리

| 방법 | 설명 |
|---|---|
| **CSRF 토큰** | 세션+쿠키 기반은 CSRF 보호 활성화 (Spring Security 기본, Thymeleaf 자동 주입) |
| **상태 변경은 비-GET** | 삭제·변경을 GET으로 두지 않기 (GET은 CSRF 토큰 미적용) |
| SameSite 쿠키 | `SameSite=Lax/Strict`로 쿠키의 교차 사이트 전송 제한(보조) |
| Referer/Origin 검증 | 요청 출처 확인(보조) |
| 재인증 | 민감 작업(비번 변경)에 현재 비밀번호 재확인 |

> REST(JWT 헤더)는 쿠키 자동 전송이 없어 CSRF 위험이 낮지만, **JWT를 쿠키에 저장하면 다시 CSRF 대상**이 된다.

---

## 7. 관련 문서
- OWASP Top 10 2025 #1 접근제어 vs #7 인증
- 로깅: 비밀번호 변경은 `[AUDIT]` 로그로 기록됨 (`04_Logging_Hardening`)
