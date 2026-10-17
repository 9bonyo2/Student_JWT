package com.basic.myspringboot.exception.advice;

import com.basic.myspringboot.exception.BusinessException;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor
public class DefaultExceptionAdvice {

    private final MeterRegistry meterRegistry;

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

    //요청 본문 파싱 실패(형식 오류 등) : 400
    //[#10 하드닝] 파서의 상세 메시지(내부 구조 노출 가능)를 그대로 내보내지 않고 일반화한다
    @ExceptionHandler(HttpMessageNotReadableException.class)
    protected ResponseEntity<Object> handleException(HttpMessageNotReadableException e, HttpServletRequest request) {
        String traceId = newTraceId();
        //상세 원인은 내부 로그에만 남긴다
        log.warn("[ERROR][{}] 요청 본문 파싱 실패 - {} {} : {}",
                traceId, request.getMethod(), request.getRequestURI(), e.getMessage());

        Map<String, Object> result = new HashMap<String, Object>();
        result.put("message", "요청 본문을 읽을 수 없습니다. 형식을 확인하세요. (traceId: " + traceId + ")");
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
    //( 이 403은 필터 체인이 아니라 컨트롤러 메서드 호출 시점(@PreAuthorize)에 발생하므로
    //  SecurityConfig 의 auditedAccessDeniedHandler() 는 호출되지 않는다. 같은 access.denied.events
    //  카운터를 chain=api-method 태그로 남겨, 어느 경로로 걸렸는지 구분해서 집계한다. )
    @ExceptionHandler(AccessDeniedException.class)
    protected ResponseEntity<ErrorObject> handleException(AccessDeniedException e, HttpServletRequest request) {
        ErrorObject errorObject = new ErrorObject();
        errorObject.setStatusCode(HttpStatus.FORBIDDEN.value());
        errorObject.setMessage(e.getMessage());

        //[AUDIT] 접근 거부(403)는 권한 상승 시도의 신호일 수 있어 반드시 기록한다
        log.warn("[AUDIT] 접근 거부(403) - {} {} from {} : {}",
                request.getMethod(), request.getRequestURI(), clientIp(request), e.getMessage());
        meterRegistry.counter("access.denied.events", "chain", "api-method").increment();

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

    //[#10 하드닝] 예상치 못한 500 오류 : 외부엔 일반 메시지+traceId, 내부 로그엔 상세
    @ExceptionHandler(RuntimeException.class)
    protected ResponseEntity<ErrorObject> handleException(RuntimeException e, HttpServletRequest request) {
        return internalError(e, request);
    }

    //[#10 하드닝] catch-all : 위에서 잡히지 않은 모든 예외(checked 포함)를 fail-closed 로 처리
    @ExceptionHandler(Exception.class)
    protected ResponseEntity<ErrorObject> handleUnexpected(Exception e, HttpServletRequest request) throws Exception {
        //Spring MVC 표준 예외(405 Method Not Allowed, 404, 415 등)는 자체 상태코드를 가진다.
        //이들까지 500 으로 바꾸면 안 되므로, 삼키지 말고 프레임워크 기본 처리기에 넘긴다.
        if (e instanceof org.springframework.web.ErrorResponse) {
            throw e;
        }
        return internalError(e, request);
    }

    /**
     * 500 공통 처리. 내부 정보(예외 메시지·스택트레이스)를 외부에 노출하지 않고(fail-closed),
     * 상관 ID(traceId)로 외부 응답과 내부 로그를 연결한다.
     */
    private ResponseEntity<ErrorObject> internalError(Exception e, HttpServletRequest request) {
        String traceId = newTraceId();
        //내부 로그에는 상세(예외·스택트레이스)를 traceId 와 함께 남긴다
        log.error("[ERROR][{}] {} {} : {}", traceId, request.getMethod(), request.getRequestURI(), e.getMessage(), e);

        ErrorObject errorObject = new ErrorObject();
        errorObject.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR.value());
        //외부에는 내부 메시지를 숨기고 일반 메시지 + traceId 만 제공한다
        errorObject.setMessage("서버 내부 오류가 발생했습니다. (traceId: " + traceId + ")");

        return new ResponseEntity<>(errorObject, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /** 오류 상관 ID : 외부 응답과 내부 로그를 잇는 짧은 식별자 */
    private String newTraceId() {
        return java.util.UUID.randomUUID().toString().substring(0, 8);
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