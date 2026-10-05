package com.basic.myspringboot.vuln.deserialization;

/**
 * 쿠폰 적용 결과.
 * appliedDiscountPercent : 실제로 적용된 할인율 — 🔴 취약 쪽에선 토큰 안의 값(변조 가능),
 *                           🟢 안전 쪽에선 서버가 code 로 재조회한 값(변조 무의미).
 */
public record ApplyResponse(String code, int appliedDiscountPercent, long orderAmount, long finalAmount) {
}
