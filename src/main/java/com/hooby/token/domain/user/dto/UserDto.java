package com.hooby.token.domain.user.dto;

import com.hooby.token.domain.user.entity.Role;
import com.hooby.token.domain.user.entity.User;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

public class UserDto {
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserResponse {
        private Long id;
        private String email;
        private String username;
        private Role role;
        private String name;
        private String profileImage;

        public static UserResponse from(User user) {
            return UserResponse.builder()
                    .id(user.getId())
                    .email(user.getEmail())
                    .username(user.getUsername())
                    .role(user.getRole())
                    .name(user.getName())
                    .profileImage(user.getProfileImage())
                    .build();
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserUpdateRequest {
        @Email(message = "올바른 이메일 형식이 아닙니다.") // Validation Dependency 필요
        private String email;

        @Pattern(regexp = "(?=.*[0-9])(?=.*[a-zA-Z]).{8,}", message = "비밀번호 조건에 충족되지 않습니다.")
        private String password;

        private String name;
        private String profileImage;
    }
}
