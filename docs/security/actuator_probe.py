#!/usr/bin/env python3
"""
[교육용] 보안 설정 오류(OWASP #2) 시연 — Actuator 노출 점검.

/actuator/env 는 애플리케이션이 실제로 쓰고 있는 설정값(프로퍼티)을 그대로 보여준다.
노출 범위(management.endpoints.web.exposure.include)가 넓고 SecurityConfig 에
별도 인증 규칙이 없으면 누구나(인증 없이) 이 값을 조회할 수 있다. 게다가
show-values 가 Spring Boot 기본값(NEVER)이 아니라 always 로 바뀌어 있으면,
이름에 password/secret 같은 단어가 없어도 "******" 로 가려지지 않고 평문 그대로 나온다.

이 스크립트는 그 상태를 그대로 재현/점검한다 — 값을 변조하지 않고 "조회"만 한다.

사용법:
  python actuator_probe.py [base_url]

예:
  python actuator_probe.py                      (기본값 http://localhost:8080)
  python actuator_probe.py http://localhost:8080
"""
import json
import sys
import urllib.error
import urllib.request

sys.stdout.reconfigure(encoding="utf-8")  # Windows 콘솔 기본 코드페이지에서 한글이 깨지는 것을 방지

# 노출 여부를 확인할 대표 키 (평범한 이름 vs secret 이 포함된 이름을 대조한다)
WATCH_KEYS = ("partner.billing.code", "jwt.secret", "voucher.hmac-secret")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """302(로그인 페이지로 리다이렉트)를 따라가지 않고 그대로 보여준다 -
    따라가면 "차단됨"이 로그인 페이지 200 으로 둔갑해 버린다."""

    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect())


def _get(url: str):
    try:
        with _opener.open(url, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        return None, str(e).encode()


def probe_env(base_url: str) -> None:
    status, body = _get(base_url + "/actuator/env")
    print(f"GET /actuator/env -> {status}")
    if status != 200:
        print("  (차단되었거나 노출되지 않음 - 값 조회 불가)")
        return
    data = json.loads(body)
    found = {}
    for src in data.get("propertySources", []):
        for key, val in src.get("properties", {}).items():
            if key in WATCH_KEYS:
                found[key] = val.get("value")
    for key in WATCH_KEYS:
        print(f"  {key} = {found.get(key, '(not found)')}")


def probe_path(base_url: str, path: str) -> None:
    status, _ = _get(base_url + path)
    print(f"GET {path} -> {status}")


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    probe_env(base)
    probe_path(base, "/actuator/beans")
    probe_path(base, "/actuator/mappings")
    probe_path(base, "/actuator/health")
    probe_path(base, "/actuator/info")
