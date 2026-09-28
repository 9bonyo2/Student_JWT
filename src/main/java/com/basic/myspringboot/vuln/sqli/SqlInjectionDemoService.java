package com.basic.myspringboot.vuln.sqli;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * [ 교육용 - SQL Injection 시연 서비스 ]
 *
 * ⚠️ 경고 : 이 클래스는 SQL 인젝션 취약점을 "일부러" 만들어 보여주기 위한 강의용 코드다.
 *          실제 서비스 코드에 절대 이런 방식(문자열 결합 쿼리)을 사용하면 안 된다.
 *
 * 같은 JdbcTemplate 을 사용하되,
 *   - searchVulnerable() : 사용자 입력을 SQL 문자열에 그대로 결합 -> 취약
 *   - searchSafe()       : '?' 파라미터 바인딩 사용             -> 안전
 * 두 메서드를 나란히 비교하여 "무엇이 차이를 만드는가"를 학생이 코드로 이해하게 한다.
 */
@Service
@RequiredArgsConstructor
public class SqlInjectionDemoService {

    private final JdbcTemplate jdbcTemplate;

    /**
     * 🔴 취약한 검색.
     *
     * 사용자 입력 name 이 SQL 문자열에 그대로 이어 붙는다.
     * 입력이 데이터가 아니라 "쿼리 구문"의 일부가 되어 버리는 것이 인젝션의 본질이다.
     *
     * 정상 입력  name = Alice
     *   -> SELECT ... WHERE name LIKE '%Alice%'
     *
     * 공격 입력  name = %' UNION SELECT id, email, password FROM user_info #
     *   -> SELECT ... WHERE name LIKE '%%' UNION SELECT id, email, password FROM user_info #%'
     *      ( # 뒤는 주석 처리되어 무력화되고, user_info 의 계정/해시가 함께 조회된다 )
     */
    public List<Map<String, Object>> searchVulnerable(String name) {
        String sql = buildVulnerableSql(name);
        return jdbcTemplate.queryForList(sql);
    }

    /**
     * 🟢 안전한 검색.
     *
     * 쿼리 구조는 고정하고, 사용자 입력은 '?' 자리에 "값(데이터)"으로만 전달한다.
     * 입력에 따옴표나 UNION 이 들어와도 구문이 아니라 검색 문자열로만 취급되어 인젝션이 성립하지 않는다.
     */
    public List<Map<String, Object>> searchSafe(String name) {
        String sql = "SELECT student_id, name, student_number FROM students WHERE name LIKE ?";
        return jdbcTemplate.queryForList(sql, "%" + name + "%");
    }

    /**
     * 교육용 : 실제로 DB 에 전달되는 "완성된 SQL 문자열"을 그대로 보여준다.
     * 학생이 자신의 입력이 어떻게 쿼리 구문으로 바뀌는지 눈으로 확인하는 용도.
     */
    public Map<String, Object> debugVulnerableSql(String name) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("입력값(name)", name);
        result.put("실행되는SQL", buildVulnerableSql(name));
        result.put("설명", "입력값이 따옴표를 닫고 SQL 구문의 일부가 되면 인젝션이 성립한다.");
        return result;
    }

    //취약 쿼리 생성 로직을 한 곳에 모아 두 메서드가 동일한 SQL 을 쓰도록 한다
    private String buildVulnerableSql(String name) {
        return "SELECT student_id, name, student_number FROM students "
                + "WHERE name LIKE '%" + name + "%'";
    }
}
