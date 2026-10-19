# 03. 소프트웨어 공급망 보안 실습 — CVE · SBOM

> OWASP Top 10 2025 **#3 소프트웨어 공급망 실패(Software Supply Chain Failures)**
> 실습 환경: Student_JWT (Maven / Spring Boot 3.4.5)

---

## 1. 개념 정리

### 소프트웨어 공급망이란?
`pom.xml`이 선언하는 외부 라이브러리 **+ 그것들이 딸고 오는 전이 의존성(transitive dependency)** 전체를 말한다.

- 이 앱은 직접 선언한 의존성이 약 15개지만, **실제로는 104개 구성요소**가 함께 들어온다.
- 이 중 **하나라도 취약하거나 오염되면** 내 앱이 감염된다 → 이것이 공급망 위험이다.

### CVE (Common Vulnerabilities and Exposures)
- **공개적으로 알려진 취약점에 붙는 고유 식별번호**. 형식: `CVE-연도-번호`
- 예: **CVE-2021-44228** = Log4Shell (log4j2의 원격코드실행 취약점)
- 심각도 점수(CVSS 0~10)가 매겨지고, **NVD**(National Vulnerability Database)에서 조회
- 한마디로 **"취약점의 주민등록번호"**

### SBOM (Software Bill of Materials)
- 앱에 들어간 **모든 구성요소(라이브러리·버전·라이선스)의 목록 = 부품표**
- 새 CVE가 터졌을 때 **"우리가 그 라이브러리를 쓰나?"를 즉시 확인**하는 근거
- 표준 형식: **CycloneDX**, SPDX
- 한마디로 **"내 앱의 성분표"**

### 취약점 스캔
- **SBOM(내 부품) ↔ CVE 데이터베이스(NVD)** 를 대조하는 작업
- 도구: **OWASP Dependency-Check**(빌드 시 스캔), **GitHub Dependabot**(자동 감지·PR)

```
SBOM (내 앱 부품 목록) ──대조──▶ CVE DB(NVD)
        └──── 취약점 스캔 도구 ────┘
                 ▼
   "이 라이브러리가 CVE-XXXX에 취약 → 업데이트하세요"
```

---

## 2. 실습 ① — SBOM 생성

프로젝트 루트에서 실행한다.

```bash
./mvnw org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
```

생성 결과:
```
target/bom.json   ← JSON 형식 SBOM
target/bom.xml    ← XML 형식 SBOM
```

> `target/`은 빌드 산출물이라 `.gitignore` 대상이다(저장소에 커밋되지 않음).

---

## 3. SBOM 읽어보기 (이 앱 실제 결과)

| 항목 | 값 |
|---|---|
| 형식(bomFormat) | CycloneDX |
| 사양(specVersion) | 1.6 |
| **총 구성요소 수** | **104개** (직접 선언 ~15개 + 전이 의존성) |

구성요소 개수 세기:
```bash
python -c "import json; d=json.load(open('target/bom.json',encoding='utf-8')); print('구성요소:', len(d['components']))"
```

주요 라이브러리(발췌):
```
spring-boot-starter-* : 3.4.5
jjwt-api              : 0.12.7
mariadb-java-client   : 3.4.2
lombok                : 1.18.38
log4j-core            : 2.24.3   ← 주목!
```

> **포인트**: 내가 `pom.xml`에 직접 쓴 것보다 훨씬 많은(104개) 구성요소가 실제로 실행된다. "내가 모르는 코드"가 이렇게 많이 들어온다는 것을 눈으로 확인한다.

---

## 4. CVE와 연결 — Log4Shell 시연

**Log4Shell (CVE-2021-44228)** 은 `log4j-core` **2.15 미만**에서 원격코드실행이 가능했던 초대형 취약점이다. 이 앱에도 log4j2가 들어있으니 확인해 보자.

```bash
python -c "import json; [print(c['group'], c['name'], c['version']) for c in json.load(open('target/bom.json',encoding='utf-8'))['components'] if 'log4j' in c['name']]"
```

실제 결과:
```
org.apache.logging.log4j log4j-core     2.24.3
org.apache.logging.log4j log4j-api      2.24.3
org.apache.logging.log4j log4j-slf4j2-impl 2.24.3
...
```

→ `log4j-core 2.24.3`은 **2.15 이상**이므로 Log4Shell에 **안전**하다(Spring Boot BOM이 패치된 버전으로 관리).

> **핵심 교훈**: SBOM이 있으면 새 CVE가 터졌을 때 **"우리가 영향받는지"를 몇 초 만에** 확인할 수 있다. Log4Shell 사태 때 많은 조직이 자기가 log4j를 쓰는지도 몰라 대응이 늦었다.

---

## 5. (선택) 실습 ② — 취약점 스캔

SBOM(내 부품)을 CVE DB와 대조해 실제 취약점을 찾는다.

```bash
./mvnw org.owasp:dependency-check-maven:check -Dnvd.api.key=발급받은키
# → target/dependency-check-report.html (브라우저로 열어 확인)
```

> **NVD API 키 필수**: 2024년부터 NVD가 API 키 없는 호출을 차단한다. 키가 없으면 `Invalid API Key, length of 0 too short...` 오류로 바로 실패한다. https://nvd.nist.gov/developers/request-an-api-key 에서 이메일로 무료 발급(즉시~최대 몇 시간) 받아 `-Dnvd.api.key=...`로 전달하거나 `~/.m2/settings.xml`에 등록한다.
>
>  **첫 실행 주의**: 키가 있어도 NVD 취약점 데이터베이스(수백 MB)를 내려받아 **시간이 오래 걸린다**(10~20분+). 

GitHub 저장소를 쓴다면 **Dependabot**을 켜는 것이 가장 간편하다(설정에서 활성화 → 취약 의존성 자동 감지·업데이트 PR).

---

## 6. 진행 요약

1. **개념** — 공급망 / CVE / SBOM / 취약점 스캔 (1절)
2. **실습 ①** — `makeAggregateBom` 으로 SBOM 생성 (2절)
3. **읽기** — 104개 구성요소 확인, "내가 모르는 코드가 이렇게 많다" (3절)
4. **CVE 연결** — log4j-core 버전 확인, Log4Shell 안전 여부 판단 (4절)
5. **(선택) 스캔** — Dependency-Check / Dependabot 소개 (5절)

**한 줄 정리**: 공급망 보안은 **무엇을 쓰는지 정확히 알고(SBOM) → 취약점을 스캔하고(CVE 대조) → 검증된 버전만 신뢰하기**의 반복이다.
