//StudentService 클래스
package com.basic.myspringboot.service;

import com.basic.myspringboot.controller.dto.StudentDTO;
import com.basic.myspringboot.entity.Student;
import com.basic.myspringboot.entity.StudentDetail;
import com.basic.myspringboot.exception.BusinessException;
import com.basic.myspringboot.exception.ErrorCode;
import com.basic.myspringboot.repository.StudentDetailRepository;
import com.basic.myspringboot.repository.StudentRepository;
import com.basic.myspringboot.security.AccessControl;
import com.basic.myspringboot.security.models.UserInfo;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class StudentDetailService {

    private final StudentRepository studentRepository;
    private final StudentDetailRepository studentDetailRepository;

    public List<StudentDTO.Response> getAllStudents() {
        //findAll() 대신 Fetch Join 을 사용하여 N+1 문제를 해결한다
        return studentRepository.findAllWithDetails()
                .stream()
                .map(StudentDTO.Response::fromEntity)
                .toList();
                //.collect(Collectors.toList());
    }

    public StudentDTO.Response getStudentById(Long id, UserInfo currentUser) {
        Student student = studentRepository.findByIdWithStudentDetail(id)
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

    @Transactional
    public StudentDTO.Response createStudent(StudentDTO.Request request, UserInfo currentUser) {
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

        // Create student 엔티티 생성
        Student student = Student.builder()
                .name(request.getName())  //이름
                .studentNumber(request.getStudentNumber())  //학번
                //학생을 등록한 사용자를 저장한다
                .userInfo(currentUser)
                .build();

        // Create StudentDetail 엔티티 생성
        if (request.getDetailRequest() != null) {
            StudentDetail studentDetail = StudentDetail.builder()
                    .address(request.getDetailRequest().getAddress()) //주소
                    .phoneNumber(request.getDetailRequest().getPhoneNumber()) //전화번호
                    .email(request.getDetailRequest().getEmail()) //이메일
                    .dateOfBirth(request.getDetailRequest().getDateOfBirth()) //생년월일
                    //생성하는 StudentDetail과 연관된 Student 엔티티 객체를 저장
                    .student(student)
                    .build();
            //양방향 연관관계이므로 Student와 연관된 StduentDetail 엔티티 객체를 저장
            student.setStudentDetail(studentDetail);
        }

        // Student와 StudentDetail의 라이프사이클이 동일하므로 Student만 저장합
        Student savedStudent = studentRepository.save(student);
        // Student를 StudentDTO.Response 로 변환
        return StudentDTO.Response.fromEntity(savedStudent);
    }

    @Transactional
    public StudentDTO.Response updateStudent(Long id, StudentDTO.Request request, UserInfo currentUser) {
        // Find the student
        Student student = studentRepository.findById(id)
                .orElseThrow(() -> new BusinessException(ErrorCode.RESOURCE_NOT_FOUND,
                        "Student", "id", id));

        // 접근 제어(IDOR 방지) : 관리자가 아니라면 본인이 등록한 학생만 수정할 수 있다.
        if (!currentUser.isAdmin() && !AccessControl.isOwner(student, currentUser)) {
            throw new AccessDeniedException("본인이 등록한 학생 정보만 수정할 수 있습니다");
        }

        // 저장된 학번과 요청한 학번이 일치하지 않으면
        if (!student.getStudentNumber().equals(request.getStudentNumber()) &&
                //요청한 학번이 중복되는지 체크하기 위해서 해당학번으로 Student 조회
                studentRepository.existsByStudentNumber(request.getStudentNumber())) {
            throw new BusinessException(ErrorCode.STUDENT_NUMBER_DUPLICATE,
                    request.getStudentNumber());
        }

        // Update student basic info
        student.setName(request.getName());
        student.setStudentNumber(request.getStudentNumber());

        // Update student detail if provided
        if (request.getDetailRequest() != null) {
            //Student가 연관된 StudentDetail 객체를 가져오기
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

            // Create new detail if not exists ( 저장된 StudentDetail 정보가 없을 경우 )
            if (studentDetail == null) {
                // 새로운 StudentDetail 객체생성
                studentDetail = new StudentDetail();
                //연관된 Student 객체 저장
                studentDetail.setStudent(student);
                //연관된 StudenDetail 객체 저장
                student.setStudentDetail(studentDetail);
            }

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

    private boolean isEmailChangingAndExists(StudentDetail currentDetail,
                                             StudentDTO.StudentDetailDTO newDetail) {
        //상세정보가 아직 없는 경우 currentDetail 은 null 이다
        String currentEmail = currentDetail == null ? null : currentDetail.getEmail();
        //email 은 @NotBlank 로 검증되므로 null / 빈 문자열 검사는 필요 없다
        //값이 실제로 바뀔 때만 중복을 검사한다 ( 자기 자신의 값은 중복이 아니다 )
        return !newDetail.getEmail().equals(currentEmail) &&
                studentDetailRepository.existsByEmail(newDetail.getEmail());
    }

    private boolean isPhoneNumberChangingAndExists(StudentDetail currentDetail,
                                                   StudentDTO.StudentDetailDTO newDetail) {
        //상세정보가 아직 없는 경우 currentDetail 은 null 이다
        String currentPhone = currentDetail == null ? null : currentDetail.getPhoneNumber();
        //phoneNumber 는 @NotBlank 로 검증되므로 null 검사는 필요 없다
        //값이 실제로 바뀔 때만 중복을 검사한다 ( 자기 자신의 값은 중복이 아니다 )
        return !newDetail.getPhoneNumber().equals(currentPhone) &&
                studentDetailRepository.existsByPhoneNumber(newDetail.getPhoneNumber());
    }
}