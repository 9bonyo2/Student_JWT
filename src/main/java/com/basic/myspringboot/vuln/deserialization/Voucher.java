package com.basic.myspringboot.vuln.deserialization;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * [ 교육용 - 역직렬화(Integrity Failures, OWASP #8) 시연용 쿠폰 ]
 *
 * 서버가 발급 시 직렬화(Java Serialization) + Base64 로 클라이언트에 내려주고,
 * 클라이언트는 결제 확인(/apply) 시 이 토큰을 그대로 되돌려준다.
 *
 * ⚠️ discountPercent 는 int 라서 직렬화 스트림에 "고정 4바이트 빅엔디안"으로 그대로 박힌다.
 *    즉 Base64 를 디코딩한 뒤 그 4바이트만 바꿔치기해도 값이 바뀐다 — 서버가 이걸
 *    다시 검증하지 않으면(= 이 클래스의 /apply 처럼) 누구나 할인율을 조작할 수 있다.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class Voucher implements Serializable {

    private static final long serialVersionUID = 1L;

    /** 쿠폰 코드 (서버의 신뢰 가능한 유일한 입력 — discountPercent 는 이걸로 다시 조회해야 한다) */
    private String code;

    /** 할인율(%) — 토큰 안에 들어있다고 해서 믿으면 안 되는 값 */
    private int discountPercent;

    /** 쿠폰을 발급받은 사용자 식별자(데모 단순화를 위해 UUID 문자열, 실제 조회엔 사용하지 않음) */
    private String issuedToUuid;
}
