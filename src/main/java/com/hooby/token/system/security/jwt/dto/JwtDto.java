package com.hooby.token.system.security.jwt.dto;

import com.hooby.token.domain.user.entity.Role;
import com.hooby.token.system.security.jwt.entity.TokenType;
import lombok.*;

import java.time.LocalDateTime;

public class JwtDto {
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    @Getter
    public static class TokenData {
        // 프론트엔드에서 expiration을 Token String을 풀어서 아는 것보다는, 직접 알게 하는게 나을 것 같아서 만듦
        private String token; // returned by Jwts.buidler()
        private LocalDateTime expiredAt;
    }

    @Builder @AllArgsConstructor @NoArgsConstructor @Getter
    public static class TokenPair {
        JwtDto.TokenData refreshToken;
        JwtDto.TokenData accessToken;

        public static TokenPair of(JwtDto.TokenData refreshToken, JwtDto.TokenData accessToken) {
            return TokenPair.builder()
                    .refreshToken(refreshToken)
                    .accessToken(accessToken)
                    .build();
        }
    }

    @Builder @AllArgsConstructor @NoArgsConstructor @Getter
    public static class TokenPayload {
        private LocalDateTime expiredAt;
        private String subject;
        private Role role;
        private TokenType tokenType;
        private String refreshUuid;
    }

    @Builder @AllArgsConstructor @NoArgsConstructor @Getter
    public static class TokenInfo {
        private String accessToken;
        private String refreshToken;
        private LocalDateTime accessTokenExpiresAt;
        private LocalDateTime refreshTokenExpiresAt;

        public static TokenInfo of(JwtDto.TokenPair tokenPair) {
            return TokenInfo.builder()
                    .accessToken(tokenPair.getAccessToken().getToken())
                    .refreshToken(tokenPair.getRefreshToken().getToken())
                    .accessTokenExpiresAt(tokenPair.getAccessToken().getExpiredAt())
                    .refreshTokenExpiresAt(tokenPair.getRefreshToken().getExpiredAt())
                    .build();
        }
    }

    @Builder @AllArgsConstructor @NoArgsConstructor @Getter
    public static class RefreshToken {
        private String tokenUuid; // Random
        private LocalDateTime issuedAt;
        private LocalDateTime expiredAt;
    }
}

