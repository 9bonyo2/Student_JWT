package com.basic.myspringboot.vuln.deserialization;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

/**
 * [ 교육용 - 역직렬화(Integrity Failures, OWASP #8) 시연 서비스 ]
 *
 * ⚠️ 경고 : 역직렬화 무결성 실패를 "체험"하기 위한 강의용 코드다. 실제 서비스에 배포하지 말 것.
 *
 * - issue           : 쿠폰 코드 → 할인율을 서버 정책에서 조회해 Voucher 를 만들고, Java 직렬화 + Base64 로 내려준다.
 * - applyVulnerable : 받은 토큰을 역직렬화해서 그 안의 discountPercent 를 그대로 믿는다 (🔴 변조 가능)
 * - applySafe       : 똑같이 역직렬화하지만 discountPercent 는 버리고, code 로 서버 정책을 다시 조회한다 (🟢 변조 무의미 — 재검증)
 * - issueSigned/applySigned : 토큰에 HMAC-SHA256 서명을 붙여, 4바이트라도 바뀌면 서명 검증에서 즉시 걸러낸다
 *                              (🟢 §4-3 — JWT 가 서명으로 payload 변조를 막는 것과 같은 원리)
 */
@Service
public class DeserializationDemoService {

    /** 쿠폰 코드 → 할인율(%) 정책. 서버만 아는 "진실의 원천"이다. */
    private static final Map<String, Integer> COUPON_POLICY = Map.of(
            "WELCOME10", 10,
            "FRIEND20", 20,
            "VIP50", 50
    );

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    /** 서명용 비밀 키. 실습용 기본값이며, 운영이라면 JWT_SECRET 과 마찬가지로 환경변수로 주입해야 한다. */
    private final SecretKeySpec hmacKey;

    public DeserializationDemoService(@Value("${voucher.hmac-secret}") String hmacSecret) {
        this.hmacKey = new SecretKeySpec(hmacSecret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
    }

    /** 코드가 정책에 없으면 할인 없음(0%)으로 발급한다 */
    public IssueResponse issue(String code) {
        int discountPercent = COUPON_POLICY.getOrDefault(code, 0);
        Voucher voucher = new Voucher(code, discountPercent, UUID.randomUUID().toString());
        String token = serialize(voucher);
        return new IssueResponse(code, discountPercent, token);
    }

    /** 🟢 §4-3 : issue 와 똑같이 발급하지만, 직렬화 바이트에 HMAC 서명을 붙여 내려준다 */
    public IssueResponse issueSigned(String code) {
        int discountPercent = COUPON_POLICY.getOrDefault(code, 0);
        Voucher voucher = new Voucher(code, discountPercent, UUID.randomUUID().toString());
        String token = serializeSigned(voucher);
        return new IssueResponse(code, discountPercent, token);
    }

    /** 🔴 취약 : 토큰 안의 discountPercent 를 재검증 없이 그대로 적용한다 */
    public ApplyResponse applyVulnerable(String voucherToken, long orderAmount) {
        Voucher voucher = deserialize(voucherToken);
        int discountPercent = voucher.getDiscountPercent();   // 변조된 값이라도 그대로 신뢰
        long finalAmount = applyDiscount(orderAmount, discountPercent);
        return new ApplyResponse(voucher.getCode(), discountPercent, orderAmount, finalAmount);
    }

    /** 🟢 안전 : 토큰에서 code 만 꺼내고, discountPercent 는 서버 정책으로 다시 조회한다 */
    public ApplyResponse applySafe(String voucherToken, long orderAmount) {
        Voucher voucher = deserialize(voucherToken);
        int trustedDiscountPercent = COUPON_POLICY.getOrDefault(voucher.getCode(), 0);   // 재검증
        long finalAmount = applyDiscount(orderAmount, trustedDiscountPercent);
        return new ApplyResponse(voucher.getCode(), trustedDiscountPercent, orderAmount, finalAmount);
    }

    /**
     * 🟢 §4-3 : 서명을 먼저 검증하고, 검증에 통과한 토큰만 그 안의 discountPercent 를 신뢰한다.
     * (JWT 와 동일한 원리 — "서명이 맞다 = payload 가 발급 당시 그대로다"가 보장되므로 필드를 믿어도 된다)
     */
    public ApplyResponse applySigned(String voucherToken, long orderAmount) {
        Voucher voucher = deserializeSigned(voucherToken);   // 서명 불일치면 여기서 즉시 거부
        int discountPercent = voucher.getDiscountPercent();  // 서명으로 보증됐으므로 그대로 신뢰해도 된다
        long finalAmount = applyDiscount(orderAmount, discountPercent);
        return new ApplyResponse(voucher.getCode(), discountPercent, orderAmount, finalAmount);
    }

    private long applyDiscount(long orderAmount, int discountPercent) {
        int clamped = Math.max(0, Math.min(100, discountPercent));
        return orderAmount - (orderAmount * clamped / 100);
    }

    private String serialize(Voucher voucher) {
        return Base64.getEncoder().encodeToString(serializeToBytes(voucher));
    }

    /** code.signature 형식 : code = base64(직렬화 바이트), signature = base64(HMAC-SHA256(code 의 원본 바이트)) */
    private String serializeSigned(Voucher voucher) {
        byte[] raw = serializeToBytes(voucher);
        String code = Base64.getEncoder().encodeToString(raw);
        String signature = Base64.getEncoder().encodeToString(hmac(raw));
        return code + "." + signature;
    }

    private byte[] serializeToBytes(Voucher voucher) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(voucher);
            return bos.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException("voucher 직렬화 실패", e);
        }
    }

    /**
     * ⚠️ 바로 이 메서드가 교육 대상이다 : 클라이언트가 보낸 바이트를 그대로 역직렬화한다.
     * (이 데모는 가젯체인 라이브러리를 쓰지 않으므로 RCE 는 발생하지 않는다 — 여기서 보여주는 건
     *  "역직렬화된 객체의 필드 값을 재검증 없이 신뢰하면 생기는 무결성 실패"다)
     */
    private Voucher deserialize(String voucherToken) {
        return deserializeFromBytes(Base64.getDecoder().decode(voucherToken));
    }

    /** 🟢 §4-3 : 서명을 먼저 검증한 뒤에만 역직렬화한다 — 변조된 토큰은 역직렬화 시도조차 하지 않는다 */
    private Voucher deserializeSigned(String voucherToken) {
        int dot = voucherToken.indexOf('.');
        if (dot < 0) {
            throw new IllegalArgumentException("voucherToken 형식이 올바르지 않습니다 (code.signature 아님)");
        }
        byte[] raw = Base64.getDecoder().decode(voucherToken.substring(0, dot));
        byte[] signature = Base64.getDecoder().decode(voucherToken.substring(dot + 1));
        byte[] expected = hmac(raw);
        if (!MessageDigest.isEqual(expected, signature)) {   // 타이밍 공격을 피하는 상수 시간 비교
            throw new IllegalArgumentException("서명이 유효하지 않습니다 — 토큰이 변조되었습니다");
        }
        return deserializeFromBytes(raw);
    }

    private Voucher deserializeFromBytes(byte[] bytes) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
             ObjectInputStream ois = new ObjectInputStream(bis)) {
            Object obj = ois.readObject();
            if (!(obj instanceof Voucher voucher)) {
                throw new IllegalArgumentException("voucherToken 이 Voucher 형식이 아닙니다");
            }
            return voucher;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("유효하지 않은 voucherToken 입니다", e);
        }
    }

    private byte[] hmac(byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(hmacKey);
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC 서명 계산 실패", e);
        }
    }
}
