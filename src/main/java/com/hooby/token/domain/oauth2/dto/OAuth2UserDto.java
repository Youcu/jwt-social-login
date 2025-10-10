package com.hooby.token.domain.oauth2.dto;

import com.hooby.token.domain.user.entity.enums.Role;
import com.hooby.token.domain.user.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder @NoArgsConstructor @AllArgsConstructor @Data
public class OAuth2UserDto {
    private Long userId;
    private Role role;
    private String nickname;
    private String username;
    private String email;

    public static OAuth2UserDto of(Role role, OAuth2Response oAuth2Response) {
        return OAuth2UserDto.builder()
                .userId(null) // OAuth2Response 엔 userId가 없음 -> user 등록 하고 해당 DTO update 해야 함.
                .role(role)
                .nickname(suggestNickname(oAuth2Response))
                .username(generateUsername(oAuth2Response))
                .email(oAuth2Response.getEmail())
                .build();
    }

    public static OAuth2UserDto from(User user) {
        return OAuth2UserDto.builder()
                .userId(user.getId()) // user 등록된 이후 DTO Update 됨
                .role(user.getRole())
                .nickname(user.getNickname())
                .username(user.getUsername())
                .email(user.getEmail())
                .build();
    }

    public User toUser() {
        return User.builder()
                .role(this.role)
                .nickname(this.nickname)
                .username(this.username)
                .email(this.email)
                .build();
    }

    private static String generateUsername(OAuth2Response oAuth2Response) {
        return oAuth2Response.getProvider()+"_"+oAuth2Response.getProviderId();
    }

    private static String suggestNickname(OAuth2Response oAuth2Response) {
        // 닉네임 null/blank 시 대체. 유니크 제약이 있으므로 충돌 나면 suffix 증가 등으로 보완
        String nickname = oAuth2Response.getNickname();

        if (!nickname.isEmpty()) return nickname;

        return "user_" + oAuth2Response.getProvider() + "_" +
                oAuth2Response.getProviderId().substring(0, Math.min(6, oAuth2Response.getProviderId().length()));
    }
}
