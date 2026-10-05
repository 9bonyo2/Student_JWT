package com.basic.myspringboot.vuln.deserialization;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * [ 교육용 - 역직렬화(Integrity Failures, OWASP #8) 시연 컨트롤러 ]
 *
 * ⚠️ 경고 : 역직렬화 무결성 실패를 "체험"하기 위한 강의용 엔드포인트다. 실제 서비스에 배포하지 말 것.
 *
 * 실습 편의를 위해 SecurityConfig 에서 /api/vuln/** 는 인증 없이 접근하도록 열어 두었다.
 *
 * 비교 실습 :
 *   POST /api/vuln/deserialize/issue          쿠폰 코드 → voucherToken 발급 (공통)
 *   POST /api/vuln/deserialize/apply          (🔴 취약 : 토큰 속 discountPercent 를 그대로 신뢰)
 *   POST /api/vuln/deserialize/apply-safe     (🟢 안전 : code 로 할인율을 서버에서 재조회)
 *   POST /api/vuln/deserialize/issue-signed   HMAC 서명이 붙은 voucherToken 발급 (§4-3)
 *   POST /api/vuln/deserialize/apply-signed   (🟢 안전 : 서명 검증 통과한 토큰만 필드를 신뢰 — JWT 와 동일 원리)
 */
@RestController
@RequestMapping("/api/vuln/deserialize")
@RequiredArgsConstructor
public class DeserializationDemoController {

    private final DeserializationDemoService deserializationDemoService;

    /** 공통 : 쿠폰 코드로 voucherToken 발급 */
    @PostMapping("/issue")
    public IssueResponse issue(@Valid @RequestBody IssueRequest request) {
        return deserializationDemoService.issue(request.code());
    }

    /** 🔴 취약 : voucherToken 을 역직렬화해서 그 안의 discountPercent 를 그대로 적용한다 */
    @PostMapping("/apply")
    public ApplyResponse applyVulnerable(@Valid @RequestBody ApplyRequest request) {
        return deserializationDemoService.applyVulnerable(request.voucherToken(), request.orderAmount());
    }

    /** 🟢 안전 : voucherToken 에서 code 만 꺼내고, discountPercent 는 서버 정책으로 재조회한다 */
    @PostMapping("/apply-safe")
    public ApplyResponse applySafe(@Valid @RequestBody ApplyRequest request) {
        return deserializationDemoService.applySafe(request.voucherToken(), request.orderAmount());
    }

    /** §4-3 : 쿠폰 코드로 HMAC 서명이 붙은 voucherToken 발급 */
    @PostMapping("/issue-signed")
    public IssueResponse issueSigned(@Valid @RequestBody IssueRequest request) {
        return deserializationDemoService.issueSigned(request.code());
    }

    /** 🟢 §4-3 안전 : 서명을 먼저 검증하고(불일치면 즉시 거부), 통과한 토큰만 discountPercent 를 신뢰한다 */
    @PostMapping("/apply-signed")
    public ApplyResponse applySigned(@Valid @RequestBody ApplyRequest request) {
        return deserializationDemoService.applySigned(request.voucherToken(), request.orderAmount());
    }
}
