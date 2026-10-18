package com.basic.myspringboot.service;

import com.basic.myspringboot.controller.dto.StudentDTO;
import com.basic.myspringboot.entity.Department;
import com.basic.myspringboot.entity.Student;
import com.basic.myspringboot.entity.StudentDetail;
import com.basic.myspringboot.exception.BusinessException;
import com.basic.myspringboot.exception.ErrorCode;
import com.basic.myspringboot.repository.DepartmentRepository;
import com.basic.myspringboot.repository.StudentDetailRepository;
import com.basic.myspringboot.repository.StudentRepository;
import com.basic.myspringboot.security.AccessControl;
import com.basic.myspringboot.security.models.UserInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class StudentService {

    private final StudentRepository studentRepository;
    private final StudentDetailRepository studentDetailRepository;
    private final DepartmentRepository departmentRepository;

    // 페이징 처리된 모든 학생 조회
    public Page<StudentDTO.Response> getAllStudents(Pageable pageable) {
        //findAll() 대신 Fetch Join 을 사용하여 N+1 문제를 해결한다
        Page<Student> students = studentRepository.findAllWithDetails(pageable);
        return students.map(StudentDTO.Response::fromEntity);
    }

    // 페이징 처리 없는 모든 학생 조회
    public List<StudentDTO.Response> getAllStudents() {
        //findAll() 대신 Fetch Join 을 사용하여 N+1 문제를 해결한다
        return studentRepository.findAllWithDetails()
                .stream()
                .map(StudentDTO.Response::fromEntity)
                .toList();
    }

    public StudentDTO.Response getStudentById(Long id, UserInfo currentUser) {
        Student student = studentRepository.findByIdWithAllDetails(id)
                .orElseThrow(() -> new BusinessException(ErrorCode.RESOURCE_NOT_FOUND,
                        "Student", "id", id));
        // 접근 제어(IDOR 방지) : 관리자가 아니라면 본인 정보만 조회할 수 있다.
        if (!currentUser.isAdmin() && !AccessControl.isOwner(student, currentUser)) {
            throw new AccessDeniedException("본인 정보만 조회할 수 있습니다");
        }
        return StudentDTO.Response.fromEntity(student);
    }

    public StudentDTO.Response getStudentByStudentNumber(String studentNumber, UserInfo currentUser) {
        Student student = studentRepository.findByStudentNumber(studentNumber)
                .orElseThrow(() -> new BusinessException(ErrorCode.RESOURCE_NOT_FOUND,
                        "Student", "student number", studentNumber));
        if (!currentUser.isAdmin() && !AccessControl.isOwner(student, currentUser)) {
            throw new AccessDeniedException("본인 정보만 조회할 수 있습니다");
        }
        return StudentDTO.Response.fromEntity(student);
    }

    // 로그인한 사용자 본인이 등록한 학생이 있는지 조회한다( 없으면 404 ).
    // 소유권 검사가 필요 없다 — 조회 조건 자체가 "내가 등록한 학생" 이다.
    public StudentDTO.Response getMyStudent(UserInfo currentUser) {
        List<Student> myStudents = studentRepository.findByUserInfo(currentUser);
        if (myStudents.isEmpty()) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND,
                    "Student", "user", currentUser.getEmail());
        }
        return StudentDTO.Response.fromEntity(myStudents.get(0));
    }

    // 페이징 처리된 특정 학과의 학생 조회
    public Page<StudentDTO.Response> getStudentsByDepartmentId(Long departmentId, Pageable pageable) {
        // Validate department exists
        if (!departmentRepository.existsById(departmentId)) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND,
                    "Department", "id", departmentId);
        }

        Page<Student> students = studentRepository.findByDepartmentId(departmentId, pageable);
        return students.map(StudentDTO.Response::fromEntity);
    }

    // 페이징 처리 없는 특정 학과의 학생 조회
    public List<StudentDTO.Response> getStudentsByDepartmentId(Long departmentId) {
        // Validate department exists
        if (!departmentRepository.existsById(departmentId)) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND,
                    "Department", "id", departmentId);
        }

        return studentRepository.findByDepartmentId(departmentId)
                .stream()
                .map(StudentDTO.Response::fromEntity)
                .toList();
    }

    @Transactional
    public StudentDTO.Response createStudent(StudentDTO.Request request, UserInfo currentUser) {
        // Validate department exists
        Department department = departmentRepository.findById(request.getDepartmentId())
                .orElseThrow(() -> new BusinessException(ErrorCode.RESOURCE_NOT_FOUND,
                        "Department", "id", request.getDepartmentId()));

        // Validate student number is not already in use
        if (studentRepository.existsByStudentNumber(request.getStudentNumber())) {
            throw new BusinessException(ErrorCode.STUDENT_NUMBER_DUPLICATE,
                    request.getStudentNumber());
        }

        // Validate email is not already in use (if provided)
        if (hasEmailAndExists(request.getDetailRequest())) {
            throw new BusinessException(ErrorCode.EMAIL_DUPLICATE,
                    request.getDetailRequest().getEmail());
        }

        // Validate phone number is not already in use
        if (hasDetailAndPhoneNumberExists(request.getDetailRequest())) {
            throw new BusinessException(ErrorCode.PHONE_NUMBER_DUPLICATE,
                    request.getDetailRequest().getPhoneNumber());
        }

        // Create student entity
        Student student = Student.builder()
                .name(request.getName())
                .studentNumber(request.getStudentNumber())
                //Student 와 Department 연관관계 저장
                .department(department)
                //학생을 등록한 사용자를 저장한다
                .userInfo(currentUser)
                .build();

        // Create student detail if provided
        if (request.getDetailRequest() != null) {
            StudentDetail studentDetail = StudentDetail.builder()
                    .address(request.getDetailRequest().getAddress())
                    .phoneNumber(request.getDetailRequest().getPhoneNumber())
                    .email(request.getDetailRequest().getEmail())
                    .dateOfBirth(request.getDetailRequest().getDateOfBirth())
                    //StudentDetail 과 Student 연관관계 저장
                    .student(student)
                    .build();

            //Student 와 StudentDetail 연관관계 저장
            student.setStudentDetail(studentDetail);
        }

        // Save and return the student
        Student savedStudent = studentRepository.save(student);
        return StudentDTO.Response.fromEntity(savedStudent);
    }

    @Transactional
    public StudentDTO.Response updateStudent(Long id, StudentDTO.Request request, UserInfo currentUser) {
        // Find the student
        Student student = studentRepository.findById(id)
                .orElseThrow(() -> new BusinessException(ErrorCode.RESOURCE_NOT_FOUND,
                        "Student", "id", id));

        // 접근 제어(IDOR 방지) : 관리자가 아니라면 본인이 등록한 학생만 수정할 수 있다.
        // {id} 값만 바꿔 남의 학생 정보를 수정하는 것을 막는다.
        if (!currentUser.isAdmin() && !AccessControl.isOwner(student, currentUser)) {
            throw new AccessDeniedException("본인이 등록한 학생 정보만 수정할 수 있습니다");
        }

        // Validate department exists (if changing)
        Department department = departmentRepository.findById(request.getDepartmentId())
                .orElseThrow(() -> new BusinessException(ErrorCode.RESOURCE_NOT_FOUND,
                        "Department", "id", request.getDepartmentId()));

        // Check if another student already has the student number
        if (!student.getStudentNumber().equals(request.getStudentNumber()) &&
                studentRepository.existsByStudentNumber(request.getStudentNumber())) {
            throw new BusinessException(ErrorCode.STUDENT_NUMBER_DUPLICATE,
                    request.getStudentNumber());
        }

        // Update student basic info
        student.setName(request.getName());
        student.setStudentNumber(request.getStudentNumber());
        student.setDepartment(department);

        // Update student detail if provided
        if (request.getDetailRequest() != null) {
            StudentDetail studentDetail = student.getStudentDetail();

            // 중복 검사를 먼저 수행한다.
            // 검사용 조회 쿼리가 실행되면 영속성 컨텍스트가 flush 되는데,
            // 값이 채워지지 않은 StudentDetail 을 먼저 연결해 두면
            // email, phoneNumber 등 NOT NULL 컬럼에 null 이 들어가 제약조건 위반이 발생한다.
            // Validate email is not already in use (if changing)
            if (isEmailChangingAndExists(studentDetail, request.getDetailRequest())) {
                throw new BusinessException(ErrorCode.EMAIL_DUPLICATE,
                        request.getDetailRequest().getEmail());
            }

            // Validate phone number is not already in use (if changing)
            if (isPhoneNumberChangingAndExists(studentDetail, request.getDetailRequest())) {
                throw new BusinessException(ErrorCode.PHONE_NUMBER_DUPLICATE,
                        request.getDetailRequest().getPhoneNumber());
            }

            // Create new detail if not exists
            // StudentDetail 가 없어서 새롭게 StudentDetail 를 저장하는 경우 
            if (studentDetail == null) {
                studentDetail = new StudentDetail();
                //양방향 연관관계 저장
                studentDetail.setStudent(student);
                student.setStudentDetail(studentDetail);
            }

            // StudentDetail 가 있고, StudentDetail 를 수정하는 경우 
            // Update detail fields
            studentDetail.setAddress(request.getDetailRequest().getAddress());
            studentDetail.setPhoneNumber(request.getDetailRequest().getPhoneNumber());
            studentDetail.setEmail(request.getDetailRequest().getEmail());
            studentDetail.setDateOfBirth(request.getDetailRequest().getDateOfBirth());
        }

        // Save and return updated student
        Student updatedStudent = studentRepository.save(student);
        return StudentDTO.Response.fromEntity(updatedStudent);
    }

    @Transactional
    public void deleteStudent(Long id) {
        if (!studentRepository.existsById(id)) {
            throw new BusinessException(ErrorCode.RESOURCE_NOT_FOUND,
                    "Student", "id", id);
        }
        studentRepository.deleteById(id);
    }

    // Helper methods to improve readability and reduce duplication

    private boolean hasEmailAndExists(StudentDTO.StudentDetailDTO detailRequest) {
        //email 은 @NotBlank 로 검증되므로 null / 빈 문자열 검사는 필요 없다
        return detailRequest != null &&
                studentDetailRepository.existsByEmail(detailRequest.getEmail());
    }

    private boolean hasDetailAndPhoneNumberExists(StudentDTO.StudentDetailDTO detailRequest) {
        return detailRequest != null &&
                studentDetailRepository.existsByPhoneNumber(detailRequest.getPhoneNumber());
    }

    private boolean isEmailChangingAndExists(StudentDetail currentDetail, StudentDTO.StudentDetailDTO newDetail) {
        //상세정보가 아직 없는 경우 currentDetail 은 null 이다
        String currentEmail = currentDetail == null ? null : currentDetail.getEmail();
        //email 은 @NotBlank 로 검증되므로 null / 빈 문자열 검사는 필요 없다
        //값이 실제로 바뀔 때만 중복을 검사한다 ( 자기 자신의 값은 중복이 아니다 )
        return !newDetail.getEmail().equals(currentEmail) &&
                studentDetailRepository.existsByEmail(newDetail.getEmail());
    }

    private boolean isPhoneNumberChangingAndExists(StudentDetail currentDetail, StudentDTO.StudentDetailDTO newDetail) {
        //상세정보가 아직 없는 경우 currentDetail 은 null 이다
        String currentPhone = currentDetail == null ? null : currentDetail.getPhoneNumber();
        //phoneNumber 는 @NotBlank 로 검증되므로 null 검사는 필요 없다
        //값이 실제로 바뀔 때만 중복을 검사한다 ( 자기 자신의 값은 중복이 아니다 )
        return !newDetail.getPhoneNumber().equals(currentPhone) &&
                studentDetailRepository.existsByPhoneNumber(newDetail.getPhoneNumber());
    }
}