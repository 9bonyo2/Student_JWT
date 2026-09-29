package com.basic.myspringboot.exception.advice;

import com.basic.myspringboot.exception.BusinessException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class DefaultExceptionAdvice {

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ErrorObject> handleResourceNotFoundException(BusinessException ex) {
        ErrorObject errorObject = new ErrorObject();
        errorObject.setStatusCode(ex.getHttpStatus().value());
        errorObject.setMessage(ex.getMessage());

        log.error(ex.getMessage(), ex);

        return new ResponseEntity<ErrorObject>(errorObject, HttpStatusCode.valueOf(ex.getHttpStatus().value()));
    }

    /*
        Spring6 버전에 추가된 ProblemDetail 객체에 에러정보를 담아서 리턴하는 방법
     */
//    @ExceptionHandler(BusinessException.class)
//    protected ProblemDetail handleException(BusinessException e) {
//        ProblemDetail problemDetail = ProblemDetail.forStatus(e.getHttpStatus());
//        problemDetail.setTitle("Not Found");
//        problemDetail.setDetail(e.getMessage());
//        problemDetail.setProperty("errorCategory", "Generic");
//        problemDetail.setProperty("timestamp", Instant.now());
//        return problemDetail;
//    }

    //숫자타입의 값에 문자열타입의 값을 입력으로 받았을때 발생하는 오류
    @ExceptionHandler(HttpMessageNotReadableException.class)
    protected ResponseEntity<Object> handleException(HttpMessageNotReadableException e) {
        log.error(e.getMessage(), e);

        Map<String, Object> result = new HashMap<String, Object>();
        result.put("message", e.getMessage());
        result.put("httpStatus", HttpStatus.BAD_REQUEST.value());

        return new ResponseEntity<>(result, HttpStatus.BAD_REQUEST);
    }

    //로그인 실패 ( 아이디/비밀번호 불일치 등 ) : 401
    @ExceptionHandler(AuthenticationException.class)
    protected ResponseEntity<ErrorObject> handleException(AuthenticationException e, HttpServletRequest request) {
        ErrorObject errorObject = new ErrorObject();
        errorObject.setStatusCode(HttpStatus.UNAUTHORIZED.value());
        errorObject.setMessage(e.getMessage());

        //[AUDIT] 인증 실패는 감사 대상 : 어떤 요청이 실패했는지 맥락을 함께 남긴다
        log.warn("[AUDIT] 인증 실패(401) - {} {} from {} : {}",
                request.getMethod(), request.getRequestURI(), clientIp(request), e.getMessage());

        return new ResponseEntity<>(errorObject, HttpStatus.UNAUTHORIZED);
    }

    //권한 부족 ( @PreAuthorize 통과 실패 ) : 403
    @ExceptionHandler(AccessDeniedException.class)
    protected ResponseEntity<ErrorObject> handleException(AccessDeniedException e, HttpServletRequest request) {
        ErrorObject errorObject = new ErrorObject();
        errorObject.setStatusCode(HttpStatus.FORBIDDEN.value());
        errorObject.setMessage(e.getMessage());

        //[AUDIT] 접근 거부(403)는 권한 상승 시도의 신호일 수 있어 반드시 기록한다
        log.warn("[AUDIT] 접근 거부(403) - {} {} from {} : {}",
                request.getMethod(), request.getRequestURI(), clientIp(request), e.getMessage());

        return new ResponseEntity<>(errorObject, HttpStatus.FORBIDDEN);
    }

    /**
     * 클라이언트 IP 추출. 프록시 뒤라면 X-Forwarded-For 의 첫 IP 를 사용한다.
     * ( 감사 로그에 출처를 남기기 위한 용도 )
     */
    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    @ExceptionHandler(RuntimeException.class)
    protected ResponseEntity<ErrorObject> handleException(RuntimeException e) {
        ErrorObject errorObject = new ErrorObject();
        errorObject.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
        errorObject.setMessage(e.getMessage());

        log.error(e.getMessage(), e);

        return new ResponseEntity<ErrorObject>(errorObject, HttpStatusCode.valueOf(500));
    }

    //입력항목 검증할때 오류 발생할때 동작하는 메서드
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ValidationErrorResponse> handleValidationExceptions(
            MethodArgumentNotValidException ex) {

        log.error(ex.getMessage(), ex);

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult()
                .getAllErrors()
                .forEach((error) -> {
                    String fieldName = ((FieldError) error).getField();
                    String errorMessage = error.getDefaultMessage();
                    errors.put(fieldName, errorMessage);
                });

        ValidationErrorResponse response =
                new ValidationErrorResponse(
                400,
                "입력항목 검증 오류",
                LocalDateTime.now(),
                errors
        );
        //badRequest() 400
        return ResponseEntity.badRequest().body(response);
    }

    @Getter
    @Setter
    @AllArgsConstructor
    public static class ValidationErrorResponse {
        private int status;
        private String message;
        private LocalDateTime timestamp;
        private Map<String, String> errors;
    }

}