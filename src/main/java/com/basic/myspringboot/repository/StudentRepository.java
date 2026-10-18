package com.basic.myspringboot.repository;

import com.basic.myspringboot.entity.Student;
import com.basic.myspringboot.security.models.UserInfo;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/*
 * [ 페이징과 Fetch Join ]
 *
 *   @ManyToOne, @OneToOne 같은 ToOne 연관관계는 Fetch Join 을 해도 결과 행이 늘어나지 않으므로
 *   Pageable 과 함께 사용해도 안전하다. 데이터베이스가 LIMIT / OFFSET 으로 페이징한다.
 *
 *   반면 @OneToMany 컬렉션을 Fetch Join 하면 행이 늘어나기 때문에
 *   Pageable 과 함께 쓰면 Hibernate 가 전체를 읽어 메모리에서 페이징한다. ( 위험 )
 *
 *   [ countQuery ]
 *   생략하면 Spring Data 가 원본 쿼리에서 FETCH 를 떼어내 count 쿼리를 자동으로 만든다.
 *   자동 생성 SQL 이 직접 작성한 것과 같으면 지정하지 않고,
 *   불필요한 조인/그룹핑이 남는 경우에만 지정한다.
 *   예 ) WHERE s.department.id 조건 -> 자동 생성 count 쿼리에 departments 조인이 남는다
 */
@Repository
public interface StudentRepository extends JpaRepository<Student, Long> {

    //--------------------------------------------------------------------
    // 목록 조회 : 상세정보 + 학과를 함께 가져와 N+1 을 없앤다
    //--------------------------------------------------------------------

    @Query("SELECT s FROM Student s "
            + "LEFT JOIN FETCH s.studentDetail "
            + "LEFT JOIN FETCH s.department")
    List<Student> findAllWithDetails();

    @Query("SELECT s FROM Student s "
            + "LEFT JOIN FETCH s.studentDetail "
            + "LEFT JOIN FETCH s.department")
    Page<Student> findAllWithDetails(Pageable pageable);

    //--------------------------------------------------------------------
    // 단건 조회
    //--------------------------------------------------------------------

    //LEFT JOIN FETCH : API 는 상세정보를 필수로 받지만, DB 에 직접 들어간 데이터 등
    //                  상세정보가 없는 행이 있어도 학생 조회가 누락되지 않도록 외부 조인을 유지한다
    @Query("SELECT s FROM Student s LEFT JOIN FETCH s.studentDetail WHERE s.id = :id")
    Optional<Student> findByIdWithStudentDetail(@Param("id") Long id);

    @Query("SELECT s FROM Student s "
            + "LEFT JOIN FETCH s.studentDetail "
            + "LEFT JOIN FETCH s.department "
            + "WHERE s.id = :id")
    Optional<Student> findByIdWithAllDetails(@Param("id") Long id);

    //학번으로 조회할 때에도 상세정보/학과를 함께 가져와 쿼리 1번으로 처리한다
    @Query("SELECT s FROM Student s "
            + "LEFT JOIN FETCH s.studentDetail "
            + "LEFT JOIN FETCH s.department "
            + "WHERE s.studentNumber = :studentNumber")
    Optional<Student> findByStudentNumber(@Param("studentNumber") String studentNumber);

    //로그인한 사용자가 등록해 둔 학생이 있는지( "내 정보" ) 확인할 때 쓴다.
    //
    //Optional 이 아니라 List 로 받는 까닭 : 서버가 "한 사용자 = 학생 한 명" 을
    //강제하지 않아서( 등록 API 가 중복 등록을 막지 않는다 ), 두 번째 등록이
    //들어오면 Optional 반환 메서드는 "결과가 유일하지 않다" 는 예외를 던진다.
    //가장 먼저 등록한 것 하나만 쓰면 되므로 서비스에서 List 의 첫 번째 값을 꺼낸다.
    @Query("SELECT s FROM Student s "
            + "LEFT JOIN FETCH s.studentDetail "
            + "LEFT JOIN FETCH s.department "
            + "WHERE s.userInfo = :userInfo "
            + "ORDER BY s.id ASC")
    List<Student> findByUserInfo(@Param("userInfo") UserInfo userInfo);

    //--------------------------------------------------------------------
    // 학과별 조회
    //--------------------------------------------------------------------

    @Query("SELECT s FROM Student s "
            + "LEFT JOIN FETCH s.studentDetail "
            + "LEFT JOIN FETCH s.department "
            + "WHERE s.department.id = :departmentId")
    List<Student> findByDepartmentId(@Param("departmentId") Long departmentId);

    //WHERE 에 s.department 가 있어 자동 생성 count 쿼리에 departments 조인이 남으므로 직접 지정한다
    @Query(value = "SELECT s FROM Student s "
            + "LEFT JOIN FETCH s.studentDetail "
            + "LEFT JOIN FETCH s.department "
            + "WHERE s.department.id = :departmentId",
            countQuery = "SELECT COUNT(s) FROM Student s WHERE s.department.id = :departmentId")
    Page<Student> findByDepartmentId(@Param("departmentId") Long departmentId, Pageable pageable);

    //--------------------------------------------------------------------
    // 검색 ( 페이징 )
    //--------------------------------------------------------------------

    @Query("SELECT s FROM Student s "
            + "LEFT JOIN FETCH s.studentDetail "
            + "LEFT JOIN FETCH s.department "
            + "WHERE LOWER(s.name) LIKE LOWER(CONCAT('%', :name, '%'))")
    Page<Student> findByNameContainingIgnoreCase(@Param("name") String name, Pageable pageable);

    @Query("SELECT s FROM Student s "
            + "LEFT JOIN FETCH s.studentDetail "
            + "LEFT JOIN FETCH s.department "
            + "WHERE LOWER(s.studentNumber) LIKE LOWER(CONCAT('%', :studentNumber, '%'))")
    Page<Student> findByStudentNumberContainingIgnoreCase(@Param("studentNumber") String studentNumber,
                                                          Pageable pageable);

    //WHERE 에 s.department 가 있어 자동 생성 count 쿼리에 departments 조인이 남으므로 직접 지정한다
    @Query(value = "SELECT s FROM Student s "
            + "LEFT JOIN FETCH s.studentDetail "
            + "LEFT JOIN FETCH s.department "
            + "WHERE s.department.id = :departmentId "
            + "AND LOWER(s.name) LIKE LOWER(CONCAT('%', :name, '%'))",
            countQuery = "SELECT COUNT(s) FROM Student s "
                    + "WHERE s.department.id = :departmentId "
                    + "AND LOWER(s.name) LIKE LOWER(CONCAT('%', :name, '%'))")
    Page<Student> findByDepartmentIdAndNameContainingIgnoreCase(@Param("departmentId") Long departmentId,
                                                                @Param("name") String name,
                                                                Pageable pageable);

    //--------------------------------------------------------------------
    // 집계 / 존재 확인
    //--------------------------------------------------------------------

    //학과 하나의 학생 수 ( 학과 삭제 전 검사에 사용 )
    @Query("SELECT COUNT(s) FROM Student s WHERE s.department.id = :departmentId")
    Long countByDepartmentId(@Param("departmentId") Long departmentId);

    boolean existsByStudentNumber(String studentNumber);
}
