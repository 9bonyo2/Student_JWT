package com.basic.myspringboot.security.models;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserInfoRepository extends JpaRepository<UserInfo, Long> {
    Optional<UserInfo> findByEmail(String username);

    //[JWT 하드닝] 토큰 subject(uuid) 로 사용자를 찾는다
    Optional<UserInfo> findByUuid(String uuid);
}