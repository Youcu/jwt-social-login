package com.hooby.token.system.security.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import java.time.Duration;
import java.time.LocalDateTime;

@Component
public class CookieUtils {

    @Value("${app.cookie.cookie-atk}") private String cookieAtkKey;
    @Value("${app.cookie.cookie-rtk}") private String cookieRtkKey;
    @Value("${app.cookie.secure}") private boolean cookieSecureOnHttps;
    @Value("${app.cookie.same-site}") private String cookieSameSite;
    @Value("${app.cookie.atk-apply-path}") private String cookieAtkApplyPath;
    @Value("${app.cookie.rtk-apply-path}") private String cookieRtkApplyPath;

    public void addCookie(
            HttpServletResponse res,
            String cookieKey,
            String token,
            LocalDateTime expiresAt,
            String path
    ) {
        var cookie = ResponseCookie.from(cookieKey, token)
                .httpOnly(true)
                .secure(cookieSecureOnHttps)
                .sameSite(cookieSameSite)
                .path(path)
                .maxAge(Duration.between(java.time.LocalDateTime.now(), expiresAt))
                .build();

        res.addHeader("Set-Cookie", cookie.toString());
    }

    public void clearCookie(
            HttpServletResponse res,
            String cookieKey,
            String path
    ) {
        var cookie = ResponseCookie.from(cookieKey, "")
                .httpOnly(true)
                .secure(cookieSecureOnHttps)
                .sameSite(cookieSameSite)
                .path(path)
                .maxAge(0) // 핵심: maxAge=0 → 즉시 삭제
                .build();

        res.addHeader("Set-Cookie", cookie.toString());
    }

    public void addAccessTokenCookie(HttpServletResponse res, String token, LocalDateTime exp) {
        addCookie(res, cookieAtkKey, token, exp, cookieAtkApplyPath); // 모든 API 요청에 자동으로 ATK 쿠키 설정
    }

    public void addRefreshTokenCookie(HttpServletResponse res, String token, LocalDateTime exp) {
        addCookie(res, cookieRtkKey, token, exp, cookieRtkApplyPath); // RTK는 회전 엔드포인트 전용
    }

    // HttpServletRequest 에서 쿠키 value 읽기
    public String getCookieValue(HttpServletRequest req, String name) {
        var cookie = WebUtils.getCookie(req, name);
        return cookie != null ? cookie.getValue() : null;
    }
}