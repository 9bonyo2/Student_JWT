package com.basic.myspringboot.vuln.sqli;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * [ 교육용 - SQL Injection 시연 컨트롤러 ]
 *
 * ⚠️ 경고 : SQL 인젝션을 "체험"하기 위한 강의용 엔드포인트다. 실제 서비스에 배포하지 말 것.
 *
 * 실습 편의를 위해 SecurityConfig 에서 /api/vuln/** 는 인증 없이 접근하도록 열어 두었다.
 * ( 실무에서는 이런 검색 API 도 인증 뒤에 있지만, 인증이 SQL 인젝션을 막아 주지는 않는다 )
 *
 * 비교 실습 :
 *   [JdbcTemplate]
 *   GET /api/vuln/sqli/students?name=Alice         (🔴 취약 : 문자열 결합)
 *   GET /api/vuln/sqli/students-safe?name=Alice    (🟢 안전 : 파라미터 바인딩)
 *   GET /api/vuln/sqli/students/debug?name=...      (실행되는 SQL 문자열 확인)
 *
 *   [JPA 네이티브 쿼리] - "도구가 아니라 문자열 결합이 문제"임을 증명
 *   GET /api/vuln/sqli/students-jpa?name=Alice      (🔴 취약 : createNativeQuery + 결합)
 *   GET /api/vuln/sqli/students-jpa-safe?name=Alice (🟢 안전 : setParameter 바인딩)
 */
@RestController
@RequestMapping("/api/vuln/sqli")
@RequiredArgsConstructor
public class SqlInjectionDemoController {

    private final SqlInjectionDemoService sqlInjectionDemoService;
    private final JpaSqlInjectionDemoService jpaSqlInjectionDemoService;

    /** 🔴 취약한 검색 : 같은 입력이라도 UNION/OR 페이로드가 그대로 실행된다 */
    @GetMapping("/students")
    public List<Map<String, Object>> searchVulnerable(@RequestParam(defaultValue = "") String name) {
        return sqlInjectionDemoService.searchVulnerable(name);
    }

    /** 🟢 안전한 검색 : 동일 페이로드를 넣어도 검색어로만 취급된다 */
    @GetMapping("/students-safe")
    public List<Map<String, Object>> searchSafe(@RequestParam(defaultValue = "") String name) {
        return sqlInjectionDemoService.searchSafe(name);
    }

    /** 입력값이 어떤 SQL 문자열로 완성되는지 그대로 보여준다 ( 원리 이해용 ) */
    @GetMapping("/students/debug")
    public Map<String, Object> debug(@RequestParam(defaultValue = "") String name) {
        return sqlInjectionDemoService.debugVulnerableSql(name);
    }

    //------------------------------------------------------------------
    // JPA 네이티브 쿼리 버전 : 도구가 JPA 여도 문자열 결합이면 동일하게 취약하다
    //------------------------------------------------------------------

    /** 🔴 JPA 네이티브 쿼리 + 문자열 결합 : JdbcTemplate 데모와 동일하게 뚫린다 */
    @GetMapping("/students-jpa")
    public List<?> searchJpaVulnerable(@RequestParam(defaultValue = "") String name) {
        return jpaSqlInjectionDemoService.searchVulnerable(name);
    }

    /** 🟢 JPA 네이티브 쿼리 + 바인딩 : 같은 페이로드도 검색어로만 취급된다 */
    @GetMapping("/students-jpa-safe")
    public List<?> searchJpaSafe(@RequestParam(defaultValue = "") String name) {
        return jpaSqlInjectionDemoService.searchSafe(name);
    }
}
