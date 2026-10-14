package com.basic.myspringboot.security;

import com.basic.myspringboot.entity.Student;
import com.basic.myspringboot.security.models.UserInfo;

/**
 * 여러 서비스에서 공통으로 쓰는 소유권 검사 유틸리티.
 */
public final class AccessControl {

    private AccessControl() {
    }

    // 학생을 등록한 사용자(student.userInfo) 와 현재 로그인한 사용자가 같은지 확인한다
    public static boolean isOwner(Student student, UserInfo user) {
        return student.getUserInfo() != null
                && student.getUserInfo().getId().equals(user.getId());
    }
}
