package com.hooby.token.domain.oauth2.handler;

import com.hooby.token.domain.oauth2.entity.CustomOAuth2User;
import com.hooby.token.system.security.jwt.dto.JwtDto;
import com.hooby.token.system.security.jwt.service.TokenService;
import com.hooby.token.system.security.model.UserPrincipal;
import com.hooby.token.system.security.util.CookieUtils;
import com.hooby.token.system.security.util.OriginUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final TokenService tokenService;
    private final CookieUtils cookieUtils;
    private final OriginUtils originUtils;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException, ServletException {

        log.info("✅ CustomSuccessHandler invoked for OAuth2 success");

        Object principal = authentication.getPrincipal();
        if (!(principal instanceof CustomOAuth2User oauth2)) {
            log.info("✅ CustomSuccessHandler principal not instance of CustomOAuth2User: {}", principal.getClass());
            getRedirectStrategy().sendRedirect(request, response, "/"); // fallback: 기본 유저 처리 or 에러
            return;
        }

        // 1) PK/Role 기반 UserPrincipal 구성 (패스워드는 null)
        UserPrincipal userPrincipal = UserPrincipal.toOAuth2(oauth2);

        // 2) TokenService로 토큰 페어 발급(+Redis 화이트리스트 등록)
        JwtDto.TokenInfo tokenInfo = tokenService.issueTokens(userPrincipal);

        log.info("🟢 Issued Tokens - ATK: {}, RTK: {}", tokenInfo.getAccessToken(), tokenInfo.getRefreshToken());

        // 3) 보안 쿠키 설정
        cookieUtils.addAccessTokenCookie(response, tokenInfo.getAccessToken(), tokenInfo.getAccessTokenExpiresAt());
        cookieUtils.addRefreshTokenCookie(response, tokenInfo.getRefreshToken(), tokenInfo.getRefreshTokenExpiresAt());

        // 4) FE로 리다이렉트 (요청 Origin에 맞춰 동적으로 결정)
        String redirectUri = originUtils.getOAuth2RedirectUri(request);
        getRedirectStrategy().sendRedirect(request, response, redirectUri);
    }
}