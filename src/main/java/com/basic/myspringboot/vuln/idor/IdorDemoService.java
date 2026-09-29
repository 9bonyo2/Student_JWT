package com.basic.myspringboot.vuln.idor;

import com.basic.myspringboot.security.models.UserInfo;
import com.basic.myspringboot.security.models.UserInfoRepository;
import com.basic.myspringboot.security.models.UserInfoUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * [ 교육용 - Insecure Direct Object Reference(IDOR) / 접근 제어 시연 서비스 ]
 *
 * ⚠️ 경고 : 취약점을 "일부러" 만든 강의용 코드다. 실제 서비스에 사용 금지.
 *
 * IDOR 는 인증은 되었지만( 로그인은 함 ), 요청한 리소스가 "내 것인지"를 검사하지 않아
 * 경로변수 {id} 만 바꾸면 남의 데이터에 접근되는 취약점이다.
 *
 *   - getProfileVulnerable() : 소유권 검사가 없다            -> 취약 (남의 프로필 조회 가능)
 *   - getProfileSecure()     : 본인 또는 관리자만 허용한다   -> 안전
 */
@Service
@RequiredArgsConstructor
public class IdorDemoService {

    private final UserInfoRepository userInfoRepository;

    /**
     * 🔴 취약 : 로그인만 되어 있으면 누구나 임의의 {id} 프로필을 조회한다.
     * 예) user@aa.com(id=2) 이 GET .../profiles/1 로 admin(id=1) 정보를 본다.
     */
    public ProfileResponse getProfileVulnerable(Long id) {
        UserInfo target = findOrThrow(id);
        return ProfileResponse.from(target);
    }

    /**
     * 🟢 안전 : 요청한 {id} 가 "본인" 이거나 요청자가 관리자일 때만 허용한다.
     * 그 외에는 AccessDeniedException 이 발생해 403 으로 응답한다.
     */
    public ProfileResponse getProfileSecure(Long id, UserInfoUserDetails me) {
        boolean isAdmin = me.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        boolean isOwner = id.equals(me.getUserInfo().getId());

        if (!isAdmin && !isOwner) {
            //소유권/권한 검사 실패 -> 403 ( DefaultExceptionAdvice 가 처리 )
            throw new AccessDeniedException("본인 또는 관리자만 조회할 수 있습니다");
        }
        return ProfileResponse.from(findOrThrow(id));
    }

    private UserInfo findOrThrow(Long id) {
        return userInfoRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "사용자를 찾을 수 없습니다 : " + id));
    }
}
