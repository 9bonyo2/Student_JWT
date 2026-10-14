# 08. 역직렬화 무결성 실패 (Insecure Deserialization) 실습

> OWASP Top 10 2025 **#8 무결성 실패**(Integrity Failures)
> 브랜치: `feature/deserialization-demo`
> 대상 코드: `com.basic.myspringboot.vuln.deserialization`

---

## 1. 개념 요약

**무결성 실패(Integrity Failures)** 는 "데이터나 코드가 **검증 없이** 바뀔 수 있는" 문제를 통칭한다. 이번 실습은 그중 가장 대표적인 사례인 **역직렬화(Deserialization)** 를 다룬다.

- **직렬화(Serialize)**: 객체(메모리의 데이터)를 저장·전송 가능한 바이트/문자열로 바꾸는 것.
- **역직렬화(Deserialize)**: 그 바이트/문자열을 다시 객체로 복원하는 것.
- **문제**: 그 바이트/문자열이 **클라이언트(신뢰할 수 없는 쪽)로부터 온 것**이고, 서버가 **복원된 객체의 내용을 검증 없이 신뢰**하면, 공격자가 그 안의 값을 마음대로 바꿔서 제출할 수 있다.

> **참고 — 더 심각한 변형 (RCE / 가젯체인 / ysoserial)**
>
> - **RCE** = **R**emote **C**ode **E**xecution(원격 코드 실행 / 임의 코드 실행). 공격자가 서버에서 자기가 원하는 명령을 실행시키는, 가장 심각한 수준의 취약점이다.
> - **가젯체인(gadget chain)**: 특정 라이브러리 "하나"가 아니라, **이미 클래스패스에 있는 여러 클래스의 메서드 호출을 연결(chain)** 해서 결과적으로 코드 실행까지 이어지는 "경로"다. 역직렬화 시 자동으로 호출되는 `readObject()`, `equals()`, `hashCode()`, `toString()` 같은 메서드들이, 공격자가 짜놓은 순서대로 **도미노처럼 연쇄 호출**되어 마지막에 `Runtime.exec()` 같은 위험한 호출까지 이어지게 만드는 것이다.
> - **ysoserial**: 이 "도미노 설계도(가젯체인)"를 **자동으로 만들어주는 도구**다. 구버전 Apache Commons Collections, Spring, Groovy, Hibernate 등 **여러 라이브러리에 실제로 존재하는** 가젯체인들을 공격 가능한 직렬화 페이로드로 조립해준다. 즉 ysoserial 자체가 취약점이 아니라, **다른 라이브러리들의 가젯체인을 이용해 PoC(개념증명) 페이로드를 생성하는 모의해킹용 오픈소스 도구**다.
>
> **이 실습은 RCE 가젯체인은 다루지 않는다** — 이 앱에는 그런 라이브러리가 없어 안전하게 재현할 수 없기 때문이다. 대신 역직렬화의 더 보편적인 문제, 즉 **"역직렬화된 객체의 필드 값을 재검증 없이 믿으면 생기는 피해"** 를 실제로 동작하는 코드로 보여준다 — "포장(직렬화 포맷)이 멀쩡하다"는 것이 "내용물(필드 값)을 믿어도 된다"는 뜻은 아니라는 점은 RCE든 이 데모든 동일한 핵심이다.

---

## 2. 이 앱의 취약점

**시나리오**: 쿠폰(Voucher) 기능. 서버는 쿠폰 코드를 받아 할인율을 담은 `Voucher` 객체를 만들어 **Java 직렬화 + Base64** 로 클라이언트에 내려준다(`voucherToken`). 클라이언트는 결제 확인 시 이 토큰을 그대로 서버에 돌려준다.

### 2-1. Voucher — 직렬화되는 객체

```java
public class Voucher implements Serializable {
    private static final long serialVersionUID = 1L;
    private String code;            // 서버가 재조회할 수 있는 유일한 신뢰 가능 입력
    private int discountPercent;    // 토큰 안에 있다고 해서 믿으면 안 되는 값
    private String issuedToUuid;
}
```
`discountPercent` 는 `int` 라서, 직렬화 스트림에 **고정 4바이트 빅엔디안**으로 그대로 박힌다 — 즉 Base64 를 디코딩한 뒤 **그 4바이트만 바꿔치기**해도 값이 바뀐다.

> **쉽게 말하면**: 컴퓨터는 `int`(정수) 하나를 저장할 때 **항상 4바이트(= 4칸)를 고정으로** 쓴다. 문자열처럼 길이가 늘었다 줄었다 하지 않는다 — 신청서 양식에 "할인율: `[ ][ ][ ][ ]`" 처럼 **항상 4칸짜리 빈칸**이 있고, 거기에 숫자를 적어 넣는 것과 같다.
>
> **"빅엔디안"**은 그 4칸에 숫자를 적는 **순서**다 — 사람이 숫자를 쓸 때처럼 **큰 자릿수를 앞(왼쪽)에, 작은 자릿수를 뒤(오른쪽)에** 적는 방식이다. 할인율 10은 16진수로 `0x0000000A` 인데, 이 순서 그대로 `00 00 00 0a` 라는 4개의 바이트가 스트림에 적힌다.
>
> 즉 **"4칸짜리 빈칸에, 늘 같은 순서로 숫자가 적혀 있다"**는 뜻이다. 그래서 공격자는 암호를 풀 필요 없이, **그 4칸(`00 00 00 0a`)을 찾아서 다른 숫자(`00 00 00 64` = 100)로 덮어쓰기만** 하면 값이 바뀐다 — §3-2의 실측 바이트 덤프가 바로 이 "4칸"을 보여주는 것이다.

### 2-2. DeserializationDemoService — 안전/취약을 나란히 둔다 (CSRF·XSS 데모와 동일한 패턴)

```java
// 공통 : 쿠폰 코드 → 할인율을 서버 정책에서 조회해 Voucher 생성 → 직렬화 + Base64
public IssueResponse issue(String code) {
    int discountPercent = COUPON_POLICY.getOrDefault(code, 0);
    Voucher voucher = new Voucher(code, discountPercent, UUID.randomUUID().toString());
    return new IssueResponse(code, discountPercent, serialize(voucher));
}
```
**①  취약 — 역직렬화한 값을 그대로 신뢰**
```java
public ApplyResponse applyVulnerable(String voucherToken, long orderAmount) {
    Voucher voucher = deserialize(voucherToken);
    int discountPercent = voucher.getDiscountPercent();   // 변조된 값이라도 그대로 신뢰
    long finalAmount = applyDiscount(orderAmount, discountPercent);
    return new ApplyResponse(voucher.getCode(), discountPercent, orderAmount, finalAmount);
}
```
**②  안전 — code 로 서버 정책을 다시 조회(재검증)**
```java
public ApplyResponse applySafe(String voucherToken, long orderAmount) {
    Voucher voucher = deserialize(voucherToken);
    int trustedDiscountPercent = COUPON_POLICY.getOrDefault(voucher.getCode(), 0);   // 재검증
    long finalAmount = applyDiscount(orderAmount, trustedDiscountPercent);
    return new ApplyResponse(voucher.getCode(), trustedDiscountPercent, orderAmount, finalAmount);
}
```
두 메서드 모두 **역직렬화 자체는 똑같이 한다** — 차이는 딱 하나, **역직렬화로 얻은 `discountPercent`를 쓰는가(①), 버리고 `code`로 다시 조회하는가(②)** 뿐이다.

| | ① `applyVulnerable` | ② `applySafe` |
|---|---|---|
| 할인율 출처 | **토큰 안의 `discountPercent` 필드값** | **서버가 가진 `COUPON_POLICY` 맵** |
| `voucher.getCode()`의 쓰임 | 응답 표시용으로만 사용 | **맵 조회 키**로 사용 |
| 공격자가 바꿀 수 있는 것 | discountPercent 값 자체(결과에 **직접** 반영됨) | code 값 → 그래도 결과는 맵에 있는 값(10/20/50/0) 중 하나로만 제한됨 |

**왜 ②가 안전한가**: 핵심은 "**클라이언트가 보낸 값을, 결과 계산에 쓸 때는 신뢰하지 않는다**"는 원칙이다. `applySafe`는 토큰에서 꺼낸 `discountPercent`를 **아예 쓰지 않고 버린다.** 대신 `code`라는 **식별자(key)**만 가져와서, **서버 메모리 안에 고정된 `COUPON_POLICY` 맵**(공격자가 절대 건드릴 수 없는 서버 쪽 데이터)에서 진짜 할인율을 다시 조회한다. 그래서 공격자가 토큰의 어느 4바이트를 어떻게 바꾸든:
- `discountPercent` 필드를 바꿔도 → `applySafe`는 그 필드를 읽지도 않으므로 **아무 영향이 없다.**
- `code` 필드를 바꿔도 → 결과는 `COUPON_POLICY`에 **미리 정의된 값(10/20/50) 또는 기본값(0)** 중 하나일 뿐, 공격자가 **임의의 숫자(예: 100)를 주입할 방법이 없다** — 맵은 "키 → 서버가 정한 값"만 돌려주기 때문이다.

즉 `applyVulnerable`은 "역직렬화된 객체의 필드"를 **결과값으로 직접 사용**하고, `applySafe`는 그 필드를 **단서(어떤 정책을 찾을지)로만 쓰고 실제 값은 서버가 재계산**한다. 이 차이 하나가 "토큰 변조가 결과에 영향을 주는가, 아닌가"를 가른다.

> 참고 — 이것도 완전한 해법은 아니다. `deserialize()` 자체는 여전히 `ObjectInputStream.readObject()`를 쓰고 있어서, §4-2·4-3에서 다룬 "포맷 자체를 안전하게" + "서명" 같은 더 근본적인 방어는 별도로 필요하다.

### 2-3. 변경/추가 파일 한눈에 보기 — 1단계(재검증, HMAC 적용 전)

| 파일 | 한 일 |
|---|---|
| `Voucher.java` | 직렬화 대상 엔티티(코드/할인율/발급대상) |
| `IssueRequest`/`IssueResponse` | 발급 요청/응답 DTO |
| `ApplyRequest`/`ApplyResponse` | 적용 요청/응답 DTO |
| `DeserializationDemoService` | 발급·취약 적용·안전 적용(재검증) 로직 + 직렬화/역직렬화 공통 로직 |
| `DeserializationDemoController` | `POST /api/vuln/deserialize/{issue,apply,apply-safe}` |
| `docs/security/voucher_tamper.py` | 공격 재현용 바이트 패치 스크립트 |

> HMAC 서명(2단계) 관련 변경은 §2-4에서 따로 정리한다 — `DeserializationDemoService`/`Controller`/`voucher_tamper.py`에 메서드·분기가 **추가**되고, `application.properties`에 `voucher.hmac-secret`이 **신규**로 생긴다.

`SecurityConfig` 수정은 필요 없다 — `/api/vuln/**` 는 SQLi 데모 때부터 이미 인증 없이 열려 있다.

**Voucher** — 직렬화 대상 엔티티(§2-1 에서 본 것과 동일, 여기서도 한눈에 보기 위해 다시 싣는다):
```java
public class Voucher implements Serializable {
    private static final long serialVersionUID = 1L;
    private String code;            // 서버가 재조회할 수 있는 유일한 신뢰 가능 입력
    private int discountPercent;    // 토큰 안에 있다고 해서 믿으면 안 되는 값
    private String issuedToUuid;
}
```

**요청/응답 DTO** — `code`/`voucherToken`/`orderAmount` 만 오가는 단순 record 들이다:
```java
public record IssueRequest(@NotBlank String code) {}
public record IssueResponse(String code, int discountPercent, String voucherToken) {}

public record ApplyRequest(@NotBlank String voucherToken, @Positive long orderAmount) {}
public record ApplyResponse(String code, int appliedDiscountPercent, long orderAmount, long finalAmount) {}
```

**직렬화/역직렬화 — 이 데모의 실제 핵심 로직** (`DeserializationDemoService`). `serializeToBytes`/`deserializeFromBytes`는 "순수 바이트 변환"만 담당하는 공통 로직으로 분리해 두었다 — §2-4의 서명 버전도 이 두 메서드를 그대로 재사용한다:
```java
private String serialize(Voucher voucher) {
    return Base64.getEncoder().encodeToString(serializeToBytes(voucher));
}

private byte[] serializeToBytes(Voucher voucher) {
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
         ObjectOutputStream oos = new ObjectOutputStream(bos)) {
        oos.writeObject(voucher);
        return bos.toByteArray();
    } catch (Exception e) {
        throw new IllegalStateException("voucher 직렬화 실패", e);
    }
}

//  바로 이 메서드가 교육 대상이다 : 클라이언트가 보낸 바이트를 그대로 역직렬화한다.
private Voucher deserialize(String voucherToken) {
    return deserializeFromBytes(Base64.getDecoder().decode(voucherToken));
}

private Voucher deserializeFromBytes(byte[] bytes) {
    try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
         ObjectInputStream ois = new ObjectInputStream(bis)) {
        return (Voucher) ois.readObject();
    } catch (Exception e) {
        throw new IllegalArgumentException("유효하지 않은 voucherToken 입니다", e);
    }
}
```

**DeserializationDemoController** — 세 엔드포인트를 서비스로 그대로 위임한다:
```java
@PostMapping("/issue")
public IssueResponse issue(@Valid @RequestBody IssueRequest request) {
    return deserializationDemoService.issue(request.code());
}

@PostMapping("/apply")                 //  취약
public ApplyResponse applyVulnerable(@Valid @RequestBody ApplyRequest request) {
    return deserializationDemoService.applyVulnerable(request.voucherToken(), request.orderAmount());
}

@PostMapping("/apply-safe")            //  안전(재검증)
public ApplyResponse applySafe(@Valid @RequestBody ApplyRequest request) {
    return deserializationDemoService.applySafe(request.voucherToken(), request.orderAmount());
}
```

**voucher_tamper.py** — 토큰을 Base64 디코딩해서 `discountPercent`의 4바이트를 찾아 덮어쓰는, 공격 스크립트의 1단계 버전이다:
```python
def tamper(token: str, old_percent: int, new_percent: int) -> str:
    data = bytearray(base64.b64decode(token))
    idx = data.find(struct.pack(">i", old_percent))   # "4칸"의 시작 위치를 찾는다
    data[idx:idx + 4] = struct.pack(">i", new_percent)  # 그 4칸만 덮어쓴다
    return base64.b64encode(bytes(data)).decode()
```

### 2-4. HMAC 적용 전체 흐름 — 2단계(서명) 메서드별 역할과 흐름 한눈에 보기

`applySafe`의 "재검증" 전략에 이어, §4-3에서 다룰 **서명(HMAC)** 전략을 코드로 구현했다. 코드를 보기 전에 먼저 **HMAC이 뭔지, 전체가 어떻게 흘러가는지**부터 정리한다.

> **쉽게 말하면 — HMAC이 뭔가요?**
>
> **HMAC**(Hash-based Message Authentication Code, 해시 기반 메시지 인증 코드)은 "데이터가 바뀌지 않았다"를 증명하는 **특수한 지문**이다. 두 단계로 이해하면 쉽다.
>
> 1. **해시(hash)** 먼저: 어떤 데이터든 넣으면 **고정된 길이의 짧은 값("지문")**을 뽑아내는 계산이다. 입력이 **단 1바이트라도 다르면 지문이 완전히 달라진다** — 같은 입력이면 항상 같은 지문이 나온다.
> 2. 그런데 평범한 해시는 **아무나** 계산할 수 있다. 그래서 공격자가 데이터를 바꾸고, 바뀐 데이터에 맞는 지문도 새로 계산해서 같이 보내면 들통나지 않는다.
> 3. **HMAC**은 이 지문을 계산할 때 **서버만 아는 비밀 키(key)**를 함께 섞는다. 그 비밀 키를 모르는 사람은 데이터에 맞는 "올바른" 지문을 **새로 만들어낼 수 없다** — 이게 평범한 해시와 HMAC의 차이다.
>
> **"HMAC을 붙인다"**는 뜻: 택배 상자를 테이프로 봉하고, 그 위에 **비밀 키로만 찍을 수 있는 특수 도장**을 찍어 같이 보내는 것과 같다. 상자(데이터)가 열리고 내용물이 바뀌면, 원래 도장은 더 이상 맞지 않게 되고 — 공격자는 그 도장을 찍는 도장 자체(비밀 키)가 없으므로 새로 맞는 도장을 찍을 수도 없다. 받는 쪽(서버)은 도착한 데이터로 **똑같은 계산을 다시 해서** 같이 온 도장과 비교만 하면, 중간에 바뀌었는지 바로 알 수 있다.
>
> 그래서 `voucherToken`은 `code(데이터) + "." + signature(그 데이터의 HMAC 지문)` 형태가 되고, `applySigned`는 받은 `code`로 지문을 다시 계산해서 `signature`와 비교한다. 하나라도 다르면 즉시 거부한다.

**이 코드에 처음 보일 수 있는 클래스들 — 한 번에 정리**

`DeserializationDemoService`의 `import` 목록에 낯선 클래스가 많다. 역할별로 묶어서 정리한다.

*직렬화·바이트 처리용 (§2-3에서부터 쓰인다)*

| 클래스 | 역할 |
|---|---|
| `ByteArrayOutputStream` | 바이트를 차례로 쌓아두는 "메모리 속 임시 창고". 직렬화된 바이트가 여기 쌓인다 |
| `ObjectOutputStream` | 객체(`Voucher`)를 바이트로 "번역"하는 도구. 번역 결과를 `ByteArrayOutputStream`에 써 넣는다 |
| `ByteArrayInputStream` | 저장된 바이트 배열을 다시 읽어오기 위한 입력 통로 |
| `ObjectInputStream` | 바이트를 다시 객체로 "복원 번역"하는 도구(= 역직렬화) |
| `Base64` | 바이트(이진 데이터)를 텍스트(문자열)로 바꿔주는 변환기. HTTP/JSON은 텍스트만 다루기 때문에, 바이트를 그대로 보낼 수 없어서 꼭 필요하다 |
| `UUID` | 무작위 고유 식별자를 만든다. 이 데모에서는 `issuedToUuid`(발급 대상 표시용)에만 쓰이고, 보안 로직과는 무관하다 |
| `StandardCharsets` | 문자열을 바이트로 바꿀 때 어떤 글자표(인코딩, 예: UTF-8)를 쓸지 지정한다 — `hmacKey`를 만들 때 비밀 키 문자열을 바이트로 바꾸는 데 쓰인다 |

*HMAC 서명(§4-3, 이 절)에만 쓰이는 클래스*

| 클래스 | 역할 |
|---|---|
| `Mac` | **"도장"을 실제로 찍어주는 도구.** 데이터 + 비밀 키를 넣으면 HMAC 지문(서명)을 계산해 돌려준다 |
| `SecretKeySpec` | 평범한 비밀 키 문자열(바이트 배열)을, `Mac`이 알아볼 수 있는 "열쇠" 형태로 감싸주는 포장지 |
| `MessageDigest` | 두 바이트 배열이 완전히 같은지 **안전하게** 비교해주는 도구. 서명이 일치하는지 확인할 때(`MessageDigest.isEqual`) 쓴다 |

**"도장 찍기"를 코드로 구현한 원리**

앞서 HMAC을 "비밀 키로만 찍을 수 있는 특수 도장"이라고 비유했다. 이게 실제로 어느 코드인지 짚어본다.

1. **도장(열쇠) 만들기** — 서버가 뜰 때 딱 한 번, 비밀 키 문자열을 `SecretKeySpec`으로 감싸서 `hmacKey` 필드에 저장해 둔다(생성자: `new SecretKeySpec(hmacSecret.getBytes(...), "HmacSHA256")`). 이 `hmacKey`가 바로 "도장 그 자체"다 — 아무도 복제할 수 없는, 서버만 가진 물건이다.
2. **도장 찍기** — `hmac(data)` 메서드 전체가 "도장을 찍는 행위"다:
   - `Mac.getInstance("HmacSHA256")` : 도장을 찍을 기계를 준비한다
   - `mac.init(hmacKey)` : 그 기계에 1번에서 만든 도장(비밀 키)을 장착한다
   - `mac.doFinal(data)` : 데이터 위에 도장을 찍어서, 그 결과(지문 = 서명 바이트)를 뽑아낸다
3. **도장이 일치하는지 확인하기** — `deserializeSigned`에서, 받은 데이터(`raw`)로 **똑같이 도장을 다시 찍어보고**(`hmac(raw)` → `expected`), 그 결과와 토큰에 같이 온 지문(`signature`)을 비교한다. 완전히 같아야(`MessageDigest.isEqual(expected, signature)`) 통과다. 데이터가 단 1바이트라도 바뀌었으면, 다시 찍은 도장(`expected`)이 원래 지문(`signature`)과 달라져서 바로 들통난다.
4. **왜 `==`나 `Arrays.equals`가 아니라 `MessageDigest.isEqual`을 쓰는가**: 보통의 비교는 **다른 바이트를 만나는 즉시 멈춘다.** 그래서 비교에 걸리는 시간을 정밀하게 측정하면 "앞의 몇 바이트까지는 맞았다"는 정보가 새어나갈 수 있다(타이밍 공격). `MessageDigest.isEqual`은 **항상 똑같은 시간**이 걸리도록 끝까지 비교해서, 이런 정보 유출 자체를 막는다.

**메서드별 역할 (2단계에서 새로 생긴 것만)**

| 메서드 | 역할 |
|---|---|
| `issueSigned(code)` | 서명이 붙은 토큰 발급 |
| `serializeSigned(voucher)` | §2-3의 `serializeToBytes` 결과 + **그 바이트의 HMAC 지문**을 합쳐 `code.signature` 형태로 |
| `applySigned(...)` | 서명을 먼저 검증하고, 통과하면 `discountPercent` 신뢰 |
| `deserializeSigned(token)` | **서명을 먼저 재계산·비교**하고, 통과해야만 §2-3의 `deserializeFromBytes` 호출 |
| `hmac(data)` | 주어진 바이트의 HMAC-SHA256 지문을 계산(비밀 키 사용) — 위 설명의 "도장 찍기"가 바로 이 메서드다 |

**흐름 (쿠폰 발급 → 결제 적용까지, `issueSigned` → `applySigned`)**

1. 클라이언트가 쿠폰 코드(예: `WELCOME10`)로 `issueSigned` 호출
2. 서버가 `COUPON_POLICY`에서 할인율(10)을 조회해 `Voucher` 객체 생성
3. `serializeSigned(voucher)` 내부에서:
   1. `serializeToBytes(voucher)` → 순수 직렬화 바이트(`raw`) 생성
   2. `hmac(raw)` → 이 바이트에 대한 **HMAC 지문**을 비밀 키로 계산
   3. `code = base64(raw)`, `signature = base64(그 지문)`
   4. `"code.signature"` 문자열을 `voucherToken`으로 반환
4. 클라이언트는 이 `voucherToken`을 그대로 보관하다가, 결제 시 다시 제출
5. 클라이언트가 `applySigned(voucherToken, 주문금액)` 호출
6. `deserializeSigned(voucherToken)` 내부에서:
   1. `.`을 기준으로 `code` 부분과 `signature` 부분을 분리
   2. `code`를 디코딩해 `raw` 바이트를 복원
   3. `hmac(raw)`를 **다시 계산** → `expected`
   4. `expected`와 전달받은 `signature`를 `MessageDigest.isEqual`로 비교
   5. **다르면** → 즉시 `IllegalArgumentException` → 여기서 끝, `deserializeFromBytes`조차 호출되지 않는다
   6. **같으면** → `deserializeFromBytes(raw)` 호출 → `Voucher` 객체 복원
7. 서명이 통과했으므로 `voucher.getDiscountPercent()`를 그대로 신뢰해서 최종 금액 계산
8. `ApplyResponse` 반환

**`applySafe` vs `applySigned` — 무엇이 다르고, 왜 둘 다 "안전"인가**

| | `applySafe` | `applySigned` |
|---|---|---|
| 토큰에 서명이 있는가 | 없음 | 있음(HMAC) |
| `discountPercent` 필드를 신뢰하는가 |  안 믿음 — `code`로 재조회 |  믿음 — 서명이 보증 |
| 변조를 막는 방식 | 그 필드를 **안 쓴다**(회피) | 변조 자체를 **탐지한다**(검증) |
| 토큰에 필드가 여러 개라면 | 필드마다 재검증 로직이 필요 | 서명 하나로 전체를 보증 |
| 서버가 꼭 가지고 있어야 하는 것 | 재조회용 원본 데이터(`COUPON_POLICY`) | 비밀 키(`hmacKey`) 하나만 |
| 클라이언트에 상태를 완전히 맡길 수 있는가 |  (서버가 매번 재조회) |  (JWT처럼 자체 완결적) |

**왜 `applySigned`가 더 안전하고 확장성 있는가**: `applySafe`는 "그 필드를 믿지 않는다"는, **딱 그 필드 하나에 국한된** 해결책이다 — `Voucher`에 필드가 10개였다면 10개 전부에 대해 재검증 로직을 따로 만들어야 한다. 반면 `applySigned`는 "데이터 전체가 발급 당시 그대로인가"를 **서명 하나로 한 번에 보증**한다 — 필드가 몇 개든, 어떤 값이든, 서명만 검증하면 전부 안전하다. 또한 `applySafe`는 서버가 재조회할 수 있는 "원본 진실의 원천"(이 데모의 `COUPON_POLICY`)이 있어야만 가능한 방어인데, 복잡한 계산 결과처럼 재조회가 불가능한 데이터라면 이 방법을 쓸 수 없다. `applySigned`는 그런 제약이 없다 — 그래서 JWT 같은 범용 토큰 방식은 "재검증"이 아니라 "서명"을 쓴다.

**변경/추가 파일 한눈에 보기 — 2단계(HMAC 서명) 추가분**

| 파일 | 추가/변경 내용 |
|---|---|
| `DeserializationDemoService` | `issueSigned`/`serializeSigned`/`applySigned`/`deserializeSigned`/`hmac` 메서드 추가 |
| `DeserializationDemoController` | `POST /api/vuln/deserialize/{issue-signed,apply-signed}` 엔드포인트 추가 |
| `docs/security/voucher_tamper.py` | 서명 있는 토큰(`code.signature`)은 `code` 부분만 변조하도록 분기 추가 |
| `application.properties` | `voucher.hmac-secret` 추가(서명 키, `jwt.secret`과 동일 패턴) |

**서명 생성/검증 — `serializeSigned`·`deserializeSigned`·`hmac`** (§2-3의 `serializeToBytes`/`deserializeFromBytes`를 그대로 재사용한다):
```java
// code = base64(직렬화 바이트), signature = base64(HMAC-SHA256(그 바이트, 서버만 아는 key))
private String serializeSigned(Voucher voucher) {
    byte[] raw = serializeToBytes(voucher);
    String code = Base64.getEncoder().encodeToString(raw);
    String signature = Base64.getEncoder().encodeToString(hmac(raw));
    return code + "." + signature;
}

//  여기가 §4-1(재검증)과의 차이다 : 역직렬화를 "시도하기 전에" 서명을 먼저 검증한다.
private Voucher deserializeSigned(String voucherToken) {
    int dot = voucherToken.indexOf('.');
    byte[] raw = Base64.getDecoder().decode(voucherToken.substring(0, dot));
    byte[] signature = Base64.getDecoder().decode(voucherToken.substring(dot + 1));
    byte[] expected = hmac(raw);
    if (!MessageDigest.isEqual(expected, signature)) {   // 타이밍 공격을 피하는 상수 시간 비교
        throw new IllegalArgumentException("서명이 유효하지 않습니다 — 토큰이 변조되었습니다");
    }
    return deserializeFromBytes(raw);   // 서명이 맞아야만 여기까지 온다
}

private byte[] hmac(byte[] data) {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(hmacKey);   // hmacKey 는 application.properties 의 voucher.hmac-secret 에서 주입
    return mac.doFinal(data);
}
```
서명이 검증을 통과했다는 것은 "발급 당시 그대로"라는 뜻이므로, `applySigned`는 §2-2의 ①처럼 `discountPercent`를 **그대로 신뢰해도 된다** — JWT의 서명 검증과 정확히 같은 논리다:
```java
public ApplyResponse applySigned(String voucherToken, long orderAmount) {
    Voucher voucher = deserializeSigned(voucherToken);   // 서명 불일치면 여기서 즉시 거부
    int discountPercent = voucher.getDiscountPercent();  // 서명으로 보증됐으므로 그대로 신뢰해도 된다
    long finalAmount = applyDiscount(orderAmount, discountPercent);
    return new ApplyResponse(voucher.getCode(), discountPercent, orderAmount, finalAmount);
}
```

**DeserializationDemoController** — 서명 엔드포인트 2개가 추가된다(§2-3의 세 엔드포인트에 이어):
```java
@PostMapping("/issue-signed")          // §4-3
public IssueResponse issueSigned(@Valid @RequestBody IssueRequest request) {
    return deserializationDemoService.issueSigned(request.code());
}

@PostMapping("/apply-signed")          //  안전(서명)
public ApplyResponse applySigned(@Valid @RequestBody ApplyRequest request) {
    return deserializationDemoService.applySigned(request.voucherToken(), request.orderAmount());
}
```

**voucher_tamper.py** — §2-3의 `tamper()` 본문이 `_tamper_bytes()`로 이름이 바뀌고, 서명 있는 토큰(`code.signature`)은 **앞부분(code)만** 변조하도록 분기가 추가된다(서명은 일부러 그대로 둔다 — 그래야 "서명이 더 이상 맞지 않는다"는 상황이 재현된다):
```python
def _tamper_bytes(token: str, old_percent: int, new_percent: int) -> str:
    data = bytearray(base64.b64decode(token))
    idx = data.find(struct.pack(">i", old_percent))   # "4칸"의 시작 위치를 찾는다
    data[idx:idx + 4] = struct.pack(">i", new_percent)  # 그 4칸만 덮어쓴다
    return base64.b64encode(bytes(data)).decode()

def tamper(token: str, old_percent: int, new_percent: int) -> str:
    if "." in token:   # §4-3 서명 토큰 : code 만 변조, 서명(뒷부분)은 그대로 둔다
        code_part, signature_part = token.split(".", 1)
        return _tamper_bytes(code_part, old_percent, new_percent) + "." + signature_part
    return _tamper_bytes(token, old_percent, new_percent)
```

---

## 3. 공격 실습 (검증됨 — 2026-10-04)

### 3-1. 시나리오

1. 공격자가 흔한 쿠폰 코드(`WELCOME10`, 10% 할인)로 **정상적으로** `voucherToken`을 발급받는다.
2. 토큰을 Base64 디코딩해서, `discountPercent`(10)가 저장된 **4바이트**를 찾아 **100으로 바꿔치기**한다.
3. 변조된 토큰을 `/apply`(취약)에 제출 → 서버가 **100% 할인**(공짜)을 그대로 적용한다.
4. 같은 변조 토큰을 `/apply-safe`(안전)에 제출 → 서버가 `code`로 재조회해 **원래 10%만** 적용한다(변조 무의미).

### 3-2. 왜 "4바이트만 바꾸면" 되는가

Java 직렬화 스트림에서 `int` 필드는 포맷이 고정돼 있어 **빅엔디안 4바이트**로 그대로 들어간다. 발급받은 토큰을 디코딩한 바이트 중, `discountPercent=10`에 해당하는 구간은 다음과 같이 **정확히 한 곳**에 나타난다(실측):
```
... 78 70 00 00 00 0a 74 00 09 57 45 4c 43 4f 4d 45 31 30 ...
                └┬┘
          discountPercent = 10 (0x0000000A)
```
이 4바이트를 `00 00 00 64`(100)로 바꾸면, 서버는 **완전히 유효한 `Voucher` 객체**로 역직렬화한다 — Java 직렬화 자체의 포맷/무결성 검사는 통과하기 때문이다(체크섬이나 서명이 없다). **"역직렬화가 성공했다" ≠ "내용이 변조되지 않았다"** 라는 게 이 공격의 핵심이다.

### 3-3. curl 재현

```bash
B=http://localhost:8080

# 1) 쿠폰 발급 (WELCOME10 = 10%)
ISSUE=$(curl -s -X POST "$B/api/vuln/deserialize/issue" -H "Content-Type: application/json" -d '{"code":"WELCOME10"}')
TOKEN=$(echo "$ISSUE" | python -c "import sys,json;print(json.load(sys.stdin)['voucherToken'])")

# 2) 정상 토큰 적용 (10000원 주문)
curl -s -X POST "$B/api/vuln/deserialize/apply" -H "Content-Type: application/json" \
  -d "{\"voucherToken\":\"$TOKEN\",\"orderAmount\":10000}"

# 3) 토큰 변조: 10% -> 100% (바이트 패치)
TAMPERED=$(python docs/security/voucher_tamper.py "$TOKEN" 10 100)

# 4) 변조 토큰 -> 취약 엔드포인트
curl -s -X POST "$B/api/vuln/deserialize/apply" -H "Content-Type: application/json" \
  -d "{\"voucherToken\":\"$TAMPERED\",\"orderAmount\":10000}"

# 5) 변조 토큰 -> 안전 엔드포인트
curl -s -X POST "$B/api/vuln/deserialize/apply-safe" -H "Content-Type: application/json" \
  -d "{\"voucherToken\":\"$TAMPERED\",\"orderAmount\":10000}"
```

**명령 해설**

| 단계 | 명령 | 하는 일 / 이유 |
|---|---|---|
| 1 | `.../issue` | 흔한 쿠폰 코드로 **정상 토큰** 발급(10% 할인) |
| 2 | `.../apply` (정상 토큰) | 변조 전 기준값 확인 — 10000원 주문에 10% 할인 적용되는지 |
| 3 | `voucher_tamper.py` | 토큰을 Base64 디코딩 → `discountPercent`(10)의 4바이트를 찾아 100으로 치환 → 다시 Base64 인코딩 |
| 4 | `.../apply` (변조 토큰) | **실제 공격.** 변조된 할인율이 그대로 적용되는지 확인 |
| 5 | `.../apply-safe` (변조 토큰) | 같은 변조 토큰이 안전 버전에서는 무력화되는지 확인(대비) |

**결과**:

| 요청 | 적용된 할인율 | 최종 금액(10000원 주문) |
|---|---|---|
| 정상 토큰 → `/apply` | 10% (정상) | 9000 |
| 변조 토큰 → `/apply`(취약) | **100%**(변조값 그대로)  | **0**(공짜) |
| 변조 토큰 → `/apply-safe`(안전) | 10%(서버가 재조회)  | 9000 |

→ **같은 변조 토큰**인데 어느 엔드포인트가 받느냐에 따라 결과가 갈린다. "역직렬화된 값을 그대로 쓰는가, 재검증하는가"의 차이뿐이다.

### 3-4. 서명(§4-3) 재현 — 같은 4바이트 변조가 서명 앞에서는 통하지 않는다

```bash
B=http://localhost:8080

# 1) 서명 토큰 발급 (WELCOME10 = 10%)
ISSUE=$(curl -s -X POST "$B/api/vuln/deserialize/issue-signed" -H "Content-Type: application/json" -d '{"code":"WELCOME10"}')
TOKEN=$(echo "$ISSUE" | python -c "import sys,json;print(json.load(sys.stdin)['voucherToken'])")

# 2) 정상 토큰 적용
curl -s -X POST "$B/api/vuln/deserialize/apply-signed" -H "Content-Type: application/json" \
  -d "{\"voucherToken\":\"$TOKEN\",\"orderAmount\":10000}"

# 3) 토큰 변조: code 부분의 10% -> 100%, 서명은 그대로 둔다
TAMPERED=$(python docs/security/voucher_tamper.py "$TOKEN" 10 100)

# 4) 변조 토큰 -> 서명 엔드포인트 (거부되어야 한다)
curl -s -w "\nHTTP %{http_code}\n" -X POST "$B/api/vuln/deserialize/apply-signed" -H "Content-Type: application/json" \
  -d "{\"voucherToken\":\"$TAMPERED\",\"orderAmount\":10000}"
```

**결과 (검증됨 — 2026-10-04)**:

| 요청 | 결과 |
|---|---|
| 정상 서명 토큰 → `/apply-signed` | 10% 할인 적용  (9000원) |
| 변조 토큰(100%, 서명 그대로) → `/apply-signed` | **서명 불일치로 즉시 거부**  역직렬화조차 시도되지 않음 |
| 같은 변조 토큰(서명 없이) → `/apply`(취약, 대비용) | **100%** 적용 — 서명이 없었다면 그대로 뚫림 |

`/apply-safe`는 "변조된 값을 쓰지 않음"으로 막고, `/apply-signed`는 "변조 자체를 탐지해서 거부함"으로 막는다 — 접근 방식이 다르다: 전자는 **값을 버리고 재조회**, 후자는 **변조 여부를 수학적으로 검증**한다.

---

## 4. 방어

### 4-1. 즉시 적용 — 재검증(안전 버전에서 이미 적용)

클라이언트가 보낸 역직렬화 결과 중 **민감한 필드는 절대 그대로 쓰지 않는다.** `code`처럼 "서버가 가진 원본과 대조 가능한 값"만 꺼내고, `discountPercent`처럼 "결과에 영향을 주는 값"은 **서버가 다시 계산**한다. — §2-2의 `applySafe`가 이 원칙 그대로다.

### 4-2. 더 근본적인 방어 — Java 네이티브 직렬화를 쓰지 않는다

재검증은 이 데모 하나는 막아주지만, "역직렬화 자체"가 가진 위험(클래스패스에 가젯체인이 있으면 RCE)은 그대로 남는다. 실무 권장:
- 클라이언트와 주고받는 데이터는 **JSON**(Jackson)처럼 "임의 클래스를 복원하지 않는" 포맷을 쓴다. `ObjectInputStream.readObject()`처럼 **클래스패스의 어떤 클래스든** 복원을 시도하는 방식은 피한다.
- Java 네이티브 직렬화를 꼭 써야 한다면, `ObjectInputFilter`(Java 9+)로 **역직렬화 가능한 클래스를 화이트리스트로 제한**한다.

### 4-3. 상태를 클라이언트에 맡겨야 한다면 — 서명(무결성 보호)  구현됨

"클라이언트가 상태를 들고 다닌다"는 아이디어 자체는 JWT(§06 문서)와 같다. **JWT가 안전한 이유는 서명이 있기 때문**이다 — payload 가 바뀌면 서명 검증이 깨진다. §4-1의 `applySafe`는 이 쿠폰 토큰에 서명이 없다는 전제 하에 "값을 믿지 않는" 방식으로 방어했다. 이번에는 같은 원리를 토큰 자체에 적용해서, "서명이 있으면 믿어도 되는" 버전을 §3-4에서 실제로 구현·검증했다:
```
voucherToken = base64(직렬화된 Voucher) + "." + HMAC-SHA256(직렬화된 Voucher, 서버만 아는 key)
```
서버(`applySigned`)는 적용 시 HMAC을 다시 계산해 비교하고, 일치하지 않으면 **역직렬화를 시도하기도 전에** 거부한다 — 4바이트를 바꾸는 순간 서명이 깨져 변조를 즉시 탐지한다(구현: `DeserializationDemoService#issueSigned`/`applySigned`, 엔드포인트: `POST /api/vuln/deserialize/{issue-signed,apply-signed}`).

### 검증 (안전 버전, 검증됨 — 2026-10-04)

| 테스트 | 결과 |
|---|---|
| 정상 토큰 → `/apply-safe` | 10% 할인 적용  |
| 변조 토큰(100%) → `/apply-safe` | 여전히 **10%**만 적용(서버 재조회)  |
| 변조 토큰(100%) → `/apply`(취약, 대비용) | **100%** 적용  |
| 정상 서명 토큰 → `/apply-signed` | 10% 할인 적용  |
| 변조 토큰(100%, 서명 그대로) → `/apply-signed` | **서명 불일치로 거부**  (§3-4) |

---

## 5. 방어 정리

| 방법 | 설명 | 이 브랜치 구현 |
|---|---|---|
| **민감 필드 재검증(핵심)** | 역직렬화 결과 중 결과에 영향을 주는 값은 서버가 다시 조회/계산 |  `applySafe` |
| 무결성 서명 | HMAC/서명으로 변조 자체를 탐지(JWT와 같은 원리) |  `issueSigned`/`applySigned` |
| 역직렬화 포맷 자체를 안전하게 | Java 네이티브 직렬화 대신 JSON 등 "임의 클래스 복원 없는" 포맷 사용 | 미구현(권장 설명만) |
| 클래스 화이트리스트 | 꼭 Java 직렬화를 써야 하면 `ObjectInputFilter`로 복원 가능 클래스 제한 | 미구현(권장 설명만) |

> **교육 포인트**: "역직렬화에 성공했다"는 "포맷이 맞다"는 뜻일 뿐, **"내용이 믿을 만하다"는 뜻이 아니다.** 신뢰 경계를 넘어온 데이터는 포맷 검사와 내용 검증을 분리해서, 결과에 영향을 주는 값은 항상 서버 쪽 진실의 원천으로 다시 확인해야 한다.

---

## 6. 관련 문서
- OWASP Top 10 2025 #8 무결성 실패
- 서명·무결성의 원리: `06_JWT_Security` — 이 문서의 §4-3·§3-4에서 구현한 "서명으로 변조 탐지"는 JWT가 이미 하고 있는 것과 같은 개념
- 유사 구조: `05_CSRF`, `07_XSS` — "안전 핸들러 + 취약 핸들러를 같은 데이터에 나란히 두고 비교"하는 실습 패턴이 동일
