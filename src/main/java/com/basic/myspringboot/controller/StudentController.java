package com.basic.myspringboot.controller;

import com.basic.myspringboot.controller.dto.StudentDTO;
import com.basic.myspringboot.security.annotation.CurrentUser;
import com.basic.myspringboot.security.models.UserInfo;
import com.basic.myspringboot.service.StudentService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/*
 * [ 권한 정책 ]
 *   목록 전체 조회(/paged, 전체목록) : ROLE_ADMIN           ( 일반 사용자의 전체 학생 열람 차단 )
 *   단건 조회(id, 학번)             : 본인 또는 ROLE_ADMIN   ( 클래스에 지정, Service 에서 소유권 검사, 타인 조회 시 403 )
 *   등록                         : ROLE_USER 또는 ROLE_ADMIN
 *   수정                         : ROLE_USER 또는 ROLE_ADMIN   ( 단, 본인이 등록한 학생만 - Service 에서 소유권 검사 )
 *   삭제                         : ROLE_ADMIN
 */
@RestController
@RequestMapping("/api/students")
@RequiredArgsConstructor
@PreAuthorize("hasAnyAuthority('ROLE_USER','ROLE_ADMIN')")
public class StudentController {

    private final StudentService studentService;

    // 페이징 처리된 학생 목록 조회 (전체 목록 열람이므로 관리자만 허용)
    @GetMapping("/paged")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Page<StudentDTO.Response>> getAllStudentsPaged(
            @PageableDefault(size = 10, sort = "id", direction = Sort.Direction.ASC)
            Pageable pageable) {
        Page<StudentDTO.Response> students = studentService.getAllStudents(pageable);
        return ResponseEntity.ok(students);
    }

    // 페이징 처리 없는 학생 목록 조회 (전체 목록 열람이므로 관리자만 허용)
    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<StudentDTO.Response>> getAllStudents() {
        List<StudentDTO.Response> students = studentService.getAllStudents();
        return ResponseEntity.ok(students);
    }

    // 로그인한 사용자 본인이 등록한 학생 정보를 조회한다( 없으면 404 ).
    // 프런트엔드가 로그인 직후 "학생 등록" 링크를 계속 보여줄지 판단할 때 쓴다.
    // "/{id}" 보다 먼저 선언해 둔다( Spring 이 리터럴을 변수보다 먼저 매칭하지만,
    // 이 파일만 보고도 순서가 뜻하는 바가 분명하도록 ).
    @GetMapping("/me")
    public ResponseEntity<StudentDTO.Response> getMyStudent(@CurrentUser UserInfo currentUser) {
        StudentDTO.Response student = studentService.getMyStudent(currentUser);
        return ResponseEntity.ok(student);
    }

    // 단건 조회는 본인 정보만 허용한다 ( Service 에서 소유권 검사, 타인 조회 시 403 )
    @GetMapping("/{id}")
    public ResponseEntity<StudentDTO.Response> getStudentById(@PathVariable Long id,
                                                               @CurrentUser UserInfo currentUser) {
        StudentDTO.Response student = studentService.getStudentById(id, currentUser);
        return ResponseEntity.ok(student);
    }

    @GetMapping("/number/{studentNumber}")
    public ResponseEntity<StudentDTO.Response> getStudentByStudentNumber(@PathVariable String studentNumber,
                                                                          @CurrentUser UserInfo currentUser) {
        StudentDTO.Response student = studentService.getStudentByStudentNumber(studentNumber, currentUser);
        return ResponseEntity.ok(student);
    }

    // 등록은 클래스 기본 정책(ROLE_USER 또는 ROLE_ADMIN)을 따른다
    @PostMapping
    public ResponseEntity<StudentDTO.Response> createStudent(
            @Valid @RequestBody StudentDTO.Request request,
            //@AuthenticationPrincipal(expression = "userInfo") UserInfo currentUser 를 감싼 애노테이션
            @CurrentUser UserInfo currentUser) {
        StudentDTO.Response createdStudent = studentService.createStudent(request, currentUser);
        return new ResponseEntity<>(createdStudent, HttpStatus.CREATED);
    }

    // 수정은 클래스 기본 정책(ROLE_USER 또는 ROLE_ADMIN)을 따르되,
    // ROLE_USER 는 본인이 등록한 학생만 수정할 수 있다 ( Service 에서 소유권 검사, 위반 시 403 )
    @PutMapping("/{id}")
    public ResponseEntity<StudentDTO.Response> updateStudent(
            @PathVariable Long id,
            @Valid @RequestBody StudentDTO.Request request,
            @CurrentUser UserInfo currentUser) {
        StudentDTO.Response updatedStudent = studentService.updateStudent(id, request, currentUser);
        return ResponseEntity.ok(updatedStudent);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Void> deleteStudent(@PathVariable Long id) {
        studentService.deleteStudent(id);
        return ResponseEntity.noContent().build();
    }
}