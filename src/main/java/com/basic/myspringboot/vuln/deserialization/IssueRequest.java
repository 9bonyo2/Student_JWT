package com.basic.myspringboot.vuln.deserialization;

import jakarta.validation.constraints.NotBlank;

/** 쿠폰 발급 요청 — 코드만 받는다 */
public record IssueRequest(@NotBlank(message = "code 는 필수입니다") String code) {
}
