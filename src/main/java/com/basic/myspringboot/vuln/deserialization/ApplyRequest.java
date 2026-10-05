package com.basic.myspringboot.vuln.deserialization;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;

/** 쿠폰 적용 요청 — 발급받은(혹은 변조된) voucherToken 과 주문 금액 */
public record ApplyRequest(
        @NotBlank(message = "voucherToken 은 필수입니다") String voucherToken,
        @Positive(message = "orderAmount 는 양수여야 합니다") long orderAmount) {
}
