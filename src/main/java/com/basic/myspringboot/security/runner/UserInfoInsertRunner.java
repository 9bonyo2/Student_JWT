package com.basic.myspringboot.security.runner;

import com.basic.myspringboot.security.models.UserInfo;
import com.basic.myspringboot.security.models.UserInfoRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 실습용 계정을 만들어 두는 러너.
 *
 * 이미 계정이 있으면 건너뛴다. ( ddl-auto 가 update 인 환경에서 email UNIQUE 위반을 막는다 )
 */
@Order(1)
@Component
@RequiredArgsConstructor
@Slf4j
public class UserInfoInsertRunner implements ApplicationRunner {

    private final UserInfoRepository userInfoRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        if (userInfoRepository.count() > 0) {
            log.info("UserInfo 데이터가 이미 있어 초기화를 건너뜁니다");
            return;
        }

        UserInfo userInfo = new UserInfo();
        userInfo.setName("adminboot");
        userInfo.setPassword(passwordEncoder.encode("pwd1"));
        userInfo.setEmail("admin@aa.com");
        userInfo.setRoles("ROLE_ADMIN,ROLE_USER");

        UserInfo userInfo2 = new UserInfo();
        userInfo2.setName("userboot");
        userInfo2.setPassword(passwordEncoder.encode("pwd2"));
        userInfo2.setEmail("user@aa.com");
        userInfo2.setRoles("ROLE_USER");

        // 학생 단건 조회(IDOR 방지) 소유권 데모용 계정 : 학생 수만큼 생성해 DataInitRunner 가 학생과 1:1로 연결한다.
        // user@aa.com 은 의도적으로 제외해, "자신이 등록한 학생이 없는 일반 사용자" 역할(타인 조회 시 403)을 보여준다.
        List<UserInfo> studentOwners = List.of(
                createStudentOwner("alice", "cs001@aa.com"),
                createStudentOwner("bob", "cs002@aa.com"),
                createStudentOwner("charlie", "ee001@aa.com"),
                createStudentOwner("diana", "ee002@aa.com"),
                createStudentOwner("edward", "me001@aa.com"),
                createStudentOwner("fiona", "ba001@aa.com"),
                createStudentOwner("george", "ba002@aa.com"),
                createStudentOwner("helen", "cs003@aa.com")
        );

        userInfoRepository.saveAll(List.of(userInfo, userInfo2));
        userInfoRepository.saveAll(studentOwners);
        log.info("실습용 계정 2개(admin@aa.com / user@aa.com) + 학생 소유자 계정 {}개를 생성했습니다", studentOwners.size());
    }

    private UserInfo createStudentOwner(String name, String email) {
        UserInfo userInfo = new UserInfo();
        userInfo.setName(name);
        userInfo.setPassword(passwordEncoder.encode("pwd1234"));
        userInfo.setEmail(email);
        userInfo.setRoles("ROLE_USER");
        return userInfo;
    }
}
