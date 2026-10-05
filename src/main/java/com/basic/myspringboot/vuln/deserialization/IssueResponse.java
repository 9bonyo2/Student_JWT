package com.basic.myspringboot.vuln.deserialization;

/** 쿠폰 발급 응답 — voucherToken 은 Voucher 를 직렬화 + Base64 인코딩한 문자열이다 */
public record IssueResponse(String code, int discountPercent, String voucherToken) {
}
