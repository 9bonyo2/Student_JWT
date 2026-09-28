package com.basic.myspringboot.vuln.sqli;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;

/**
 * [ 교육용 - JPA 네이티브 쿼리로도 SQL Injection 이 재현됨을 보이는 서비스 ]
 *
 * ⚠️ 경고 : 취약점을 "일부러" 만든 강의용 코드다. 실제 서비스에 사용 금지.
 *
 * 목적 : "JdbcTemplate 이라서 뚫린 게 아니라, 문자열을 결합해서 뚫린 것" 임을 증명한다.
 *   - 이 프로젝트의 정상 코드처럼 JPA 를 쓰더라도,
 *     EntityManager.createNativeQuery() 에 입력을 문자열로 결합하면 동일하게 취약하다.
 *   - 같은 네이티브 쿼리라도 setParameter() 로 바인딩하면 안전하다.
 *
 * 즉 취약/안전을 가르는 것은 "도구(JPA vs JdbcTemplate)"가 아니라
 * "문자열 결합 vs 파라미터 바인딩" 이라는 코딩 방식이다.
 */
@Service
public class JpaSqlInjectionDemoService {

    //EntityManager 는 생성자 주입 대신 @PersistenceContext 로 주입받는 것이 표준이다
    @PersistenceContext
    private EntityManager entityManager;

    /**
     * 🔴 취약 : JPA 네이티브 쿼리 + 문자열 결합.
     * @Query 애노테이션은 고정 문자열이라 이렇게 만들 수 없고,
     * 동적으로 쿼리를 조립하는 createNativeQuery() 에서 결합할 때 취약점이 생긴다.
     *
     * 공격 입력  name = %' UNION SELECT id, email, password FROM user_info #
     *   -> JdbcTemplate 데모와 완전히 동일하게 user_info 계정/해시가 탈취된다.
     */
    @Transactional(readOnly = true)
    public List<?> searchVulnerable(String name) {
        String sql = "SELECT student_id, name, student_number FROM students "
                + "WHERE name LIKE '%" + name + "%'";
        Query query = entityManager.createNativeQuery(sql);
        return toRows(query.getResultList());
    }

    /**
     * 🟢 안전 : 네이티브 쿼리라도 입력을 ':name' 자리에 "값"으로만 바인딩한다.
     * JPA 를 쓰든 JdbcTemplate 을 쓰든, 바인딩하면 인젝션이 성립하지 않는다.
     */
    @Transactional(readOnly = true)
    public List<?> searchSafe(String name) {
        String sql = "SELECT student_id, name, student_number FROM students WHERE name LIKE :name";
        Query query = entityManager.createNativeQuery(sql);
        query.setParameter("name", "%" + name + "%");
        return toRows(query.getResultList());
    }

    //네이티브 쿼리 결과(여러 컬럼이면 Object[])를 JSON 배열로 변환한다
    private List<?> toRows(List<?> rows) {
        return rows.stream()
                .map(r -> (r instanceof Object[]) ? Arrays.asList((Object[]) r) : List.of(r))
                .toList();
    }
}
