package com.hooby.token.domain.oauth2.handler;

import com.hooby.token.domain.oauth2.entity.CustomOAuth2User;
import com.hooby.token.system.security.jwt.dto.JwtDto;
import com.hooby.token.system.security.jwt.service.TokenService;
import com.hooby.token.system.security.model.UserPrincipal;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Iterator;

@Component
@RequiredArgsConstructor
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final TokenService tokenService;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        Object principal = authentication.getPrincipal();
        if (!(principal instanceof CustomOAuth2User oauth2)) {
            getRedirectStrategy().sendRedirect(request, response, "/"); // fallback: 기본 유저 처리 or 에러
            return;
        }

        // 1) PK/Role 기반 UserPrincipal 구성 (패스워드는 null)
        UserPrincipal userPrincipal = UserPrincipal.toOAuth2(oauth2);

        // 2) TokenService로 토큰 페어 발급(+Redis 화이트리스트 등록)
        JwtDto.TokenInfo tokenInfo = tokenService.issueTokens(userPrincipal);

        // 3) 보안 쿠키 설정
        addAccessTokenCookie(response, tokenInfo.getAccessToken(), tokenInfo.getAccessTokenExpiresAt());
        addRefreshTokenCookie(response, tokenInfo.getRefreshToken(), tokenInfo.getRefreshTokenExpiresAt());

        // 4) FE로 리다이렉트 (토큰은 쿠키로 전달되므로 URL 노출 없음)
        getRedirectStrategy().sendRedirect(request, response, "http://localhost:3000/");
    }

    private void addAccessTokenCookie(HttpServletResponse res, String token, LocalDateTime exp) {
        addCookie(res, "AT", token, exp, "/"); // 보호 API 전역
    }

    private void addRefreshTokenCookie(HttpServletResponse res, String token, LocalDateTime exp) {
        addCookie(res, "RT", token, exp, "/api/v1/auth/refresh"); // RTK는 회전 엔드포인트 전용
    }

    private void addCookie(HttpServletResponse res, String name, String value, LocalDateTime exp, String path) {
        long maxAge = Math.max(0, Duration.between(LocalDateTime.now(), exp).getSeconds());

        // Spring 6: ResponseCookie 사용 권장 (SameSite 지원)
        var cookie = ResponseCookie.from(name, value)
                .httpOnly(true)
                // .secure(true)                // HTTPS 전제
                .sameSite("None")            // 크로스 도메인 (FE: http://localhost:3000)
                .path(path)
                .maxAge(maxAge)
                .build();
        res.addHeader("Set-Cookie", cookie.toString());
    }
}

