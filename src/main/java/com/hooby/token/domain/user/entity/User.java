package com.hooby.token.domain.user.entity;

import com.hooby.token.common.auditor.TimeBaseEntity;
import com.hooby.token.domain.user.dto.UserDto;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Table(name = "users")
public class User extends TimeBaseEntity {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String name;

    @Column // OAuth2의 경우라면 password가 nullable -> 그리고 이걸 RequestDTO에서 NotBlank로 설정하면 Login API 우회 불가
    private String password;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private Role role = Role.USER;

    private String profileImage;

    // JPA Dirty Checking
    public void update(UserDto.UserUpdateRequest userUpdateRequest) {
        if (userUpdateRequest == null) return;

        this.name = getOrDefault(userUpdateRequest.getName(), this.name);
        this.password = getOrDefault(userUpdateRequest.getPassword(), this.password);
        this.email = getOrDefault(userUpdateRequest.getEmail(), this.email);
        this.email = getOrDefault(userUpdateRequest.getEmail(), this.email);
        this.profileImage = getOrDefault(userUpdateRequest.getProfileImage(), this.profileImage);
    }

    // OAuth2 사용자 정보 업데이트
    public void updateOAuth2Info(String name, String email) {
        this.name = getOrDefault(name, this.name);
        this.email = getOrDefault(email, this.email);
    }

    private <T> T getOrDefault(T newValue, T currentValue) {
        return newValue != null ? newValue : currentValue;
    }
}

