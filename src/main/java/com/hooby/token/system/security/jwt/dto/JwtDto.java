package com.hooby.token.system.security.jwt.dto;

import com.hooby.token.domain.user.entity.enums.Role;
import com.hooby.token.system.security.jwt.entity.TokenType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.time.LocalDateTime;

public class JwtDto {
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    @Getter
    public static class TokenData {
        private String token; // returned by Jwts.buidler()
        private LocalDateTime expiredAt;
        private String jti;
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
        private String jti;
    }

    @Builder @AllArgsConstructor @NoArgsConstructor @Getter
    @Schema(description = "토큰 정보 발행 DTO")
    public static class TokenInfo {
        @Schema(description = "Access Token", example = "accessTokenContent")
        private String accessToken;
        @Schema(description = "Refresh Token", example = "refreshTokenContent")
        private String refreshToken;
        @Schema(description = "Access Token 만료 시간", example = "ISO DateTime")
        private LocalDateTime accessTokenExpiresAt;
        @Schema(description = "Refresh Token 만료 시간", example = "ISO DateTime")
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
    @Schema(description = "토큰 재발행 DTO", requiredProperties = {"refreshToken"})
    public static class ReissueRequest {
        @NotBlank(message = "Refresh Token을 입력해주세요.")
        @Schema(description = "재발행할 Refresh Token", example = "refreshTokenString")
        private String refreshToken;
    }

    @Builder @AllArgsConstructor @NoArgsConstructor @Getter
    @Schema(description = "토큰 만료시간 정보 발행 DTO")
    public static class TokenExpiresInfo {
        @Schema(description = "Access Token 만료 시간", example = "ISO DateTime")
        private LocalDateTime accessTokenExpiresAt;
        @Schema(description = "Refresh Token 만료 시간", example = "ISO DateTime")
        private LocalDateTime refreshTokenExpiresAt;

        public static TokenExpiresInfo of(JwtDto.TokenInfo tokenInfo) {
            return TokenExpiresInfo.builder()
                    .accessTokenExpiresAt(tokenInfo.getAccessTokenExpiresAt())
                    .refreshTokenExpiresAt(tokenInfo.getRefreshTokenExpiresAt())
                    .build();
        }
    }
}

