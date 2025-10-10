package com.hooby.token.domain.user.entity;

import com.hooby.token.common.auditor.TimeBaseEntity;
import com.hooby.token.domain.user.dto.UserDto;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.util.Locale;

@SuperBuilder
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(name = "USER_USERNAME", columnNames = "username"),
        @UniqueConstraint(name = "USER_NICKNAME", columnNames = "nickname"),
        @UniqueConstraint(name = "USER_EMAIL", columnNames = "email")
})
public class User extends TimeBaseEntity {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, updatable = false)
    private String username;

    @Column(nullable = false)
    private String nickname;

    @Column // OAuth2의 경우라면 password가 nullable -> 그리고 이걸 RequestDTO에서 NotBlank로 설정하면 Login API 우회 불가
    private String password;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private Role role = Role.USER;

    private String profileImage;

    // @Version private Long version; -> JPA에서 자동 관리해주는 Optimistic Lock 인데 (단, 재시도 로직 등 AOP 고려), 추후 고려

    /*
     * Annotations -> @PrePersist, @PreUpdate: Jpa Entity Lifecycle event callback
     * entityManager.persist(user) 또는 entityManager.merge(user)가 호출되어 flush 되는 순간,
     * JPA가 내부적으로 이 메서드를 먼저 실행하고, 그 이후에 SQL을 생성해서 DB에 반영
     *
     * email toLowerCase: Why? 이메일은 표준적으로 대소문자 구별 X, But DB Unique 제약은 기본적으로 대소문자 구별
     */
    @PrePersist // INSERT 되기 전 실행 (새로운 User 저장 시)
    @PreUpdate  // UPDATE 되기 전 실행 (기존 User 수정 시)
    private void normalize() {
        if (this.nickname != null) this.nickname = this.nickname.trim(); // "hades " 같은 공백 포함 문자열 방지
        if (this.email != null) this.email = this.email.trim().toLowerCase(Locale.ROOT);
        if (this.profileImage != null) this.profileImage = this.profileImage.trim();
    }

    // JPA Dirty Checking
    public void update(UserDto.UserUpdateRequest userUpdateRequest) {
        if (userUpdateRequest == null) return;

        this.nickname = nonBlankOrDefault(userUpdateRequest.getNickname(), this.nickname);
        this.password = nonBlankOrDefault(userUpdateRequest.getPassword(), this.password); // encoded password
        this.email = nonBlankOrDefault(userUpdateRequest.getEmail(), this.email);
        this.profileImage = nonBlankOrDefault(userUpdateRequest.getProfileImage(), this.profileImage);
    }

    // OAuth2 사용자 정보 업데이트
    public void updateOAuth2Info(String nickname, String email) {
        this.nickname = nonBlankOrDefault(nickname, this.nickname);
        this.email = nonBlankOrDefault(email, this.email);
    }

    private <T> T nonBlankOrDefault(T newValue, T currentValue) {
        return newValue != null ? newValue : currentValue;
    }
}

