package com.basic.myspringboot.controller;

import com.basic.myspringboot.controller.dto.StudentDTO;
import com.basic.myspringboot.security.annotation.CurrentUser;
import com.basic.myspringboot.security.models.UserInfo;
import com.basic.myspringboot.service.StudentDetailService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/*
 * [ 권한 정책 ]
 *   목록 전체 조회         : ROLE_ADMIN           ( 상세정보(주소/전화번호/이메일) 포함이라 더 민감 → 일반 사용자 열람 차단 )
 *   단건 조회(id, 학번)    : 본인 또는 ROLE_ADMIN   ( 클래스에 지정, Service 에서 소유권 검사, 타인 조회 시 403 )
 *   등록                : ROLE_USER 또는 ROLE_ADMIN
 *   수정                : ROLE_USER 또는 ROLE_ADMIN   ( 단, 본인이 등록한 학생만 - Service 에서 소유권 검사 )
 *   삭제                : ROLE_ADMIN
 */
@RestController
@RequestMapping("/api/students/detail")
@RequiredArgsConstructor
@PreAuthorize("hasAnyAuthority('ROLE_USER','ROLE_ADMIN')")
public class StudentDetailController {

    private final StudentDetailService studentService;

    // 전체 목록 조회 (상세정보 포함이므로 관리자만 허용)
    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<StudentDTO.Response>> getAllStudents() {
        List<StudentDTO.Response> students = studentService.getAllStudents();
        return ResponseEntity.ok(students);
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
            @CurrentUser UserInfo currentUser) {
        StudentDTO.Response createdStudent = studentService.createStudent(request, currentUser);
        //HttpStatus.CREATED - 201
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