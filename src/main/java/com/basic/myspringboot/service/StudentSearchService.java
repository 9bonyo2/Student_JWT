package com.basic.myspringboot.service;

import com.basic.myspringboot.controller.dto.StudentDTO;
import com.basic.myspringboot.exception.BusinessException;
import com.basic.myspringboot.repository.StudentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class StudentSearchService {

    private final StudentRepository studentRepository;

    /**
     * 학생 검색 (이름 또는 학번으로)
     */
    public Page<StudentDTO.Response> searchStudents(String keyword, Pageable pageable) {
        // 검색어가 비어있다고 전체 학생 목록을 반환하면 안 된다.
        // ( 전체 목록 조회는 /api/students(/paged) 에서 관리자만 허용하는 정책을 검색 API로 우회하게 된다 )
        if (!StringUtils.hasText(keyword)) {
            throw new BusinessException("검색어를 입력하세요", HttpStatus.BAD_REQUEST);
        }

        // 학번으로 검색 시도
        if (keyword.matches("^[A-Z]+\\d+$")) {
            return studentRepository.findByStudentNumberContainingIgnoreCase(keyword, pageable)
                    .map(StudentDTO.Response::fromEntity);
        }

        // 이름으로 검색
        return studentRepository.findByNameContainingIgnoreCase(keyword, pageable)
                .map(StudentDTO.Response::fromEntity);
    }

    /**
     * 부서별 학생 검색
     */
    public Page<StudentDTO.Response> searchStudentsByDepartment(Long departmentId, String keyword, Pageable pageable) {
        // 검색어가 비어있다고 해당 학과 전체 학생 목록을 반환하면 안 된다.
        if (!StringUtils.hasText(keyword)) {
            throw new BusinessException("검색어를 입력하세요", HttpStatus.BAD_REQUEST);
        }

        return studentRepository.findByDepartmentIdAndNameContainingIgnoreCase(departmentId, keyword, pageable)
                .map(StudentDTO.Response::fromEntity);
    }

    /**
     * 이름으로 학생 검색
     */
    public Page<StudentDTO.Response> searchStudentsByName(String name, Pageable pageable) {
        if (!StringUtils.hasText(name)) {
            throw new BusinessException("검색어를 입력하세요", HttpStatus.BAD_REQUEST);
        }

        return studentRepository.findByNameContainingIgnoreCase(name, pageable)
                .map(StudentDTO.Response::fromEntity);
    }

    /**
     * 학번으로 학생 검색
     */
    public Page<StudentDTO.Response> searchStudentsByStudentNumber(String studentNumber, Pageable pageable) {
        if (!StringUtils.hasText(studentNumber)) {
            throw new BusinessException("검색어를 입력하세요", HttpStatus.BAD_REQUEST);
        }

        return studentRepository.findByStudentNumberContainingIgnoreCase(studentNumber, pageable)
                .map(StudentDTO.Response::fromEntity);
    }
}