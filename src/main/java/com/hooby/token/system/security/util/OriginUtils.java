package com.hooby.token.system.security.util;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

@Slf4j
@Component
public class OriginUtils {
    @Value("${app.allowed-origins}") private String allowedOrigins;
    @Value("${app.front-redirect-uri}") private String frontRedirectUri;

    public String determineBaseUrl(HttpServletRequest request) {
        String clientOrigin = getClientOriginByRequest(request);
        validateOrigin(clientOrigin);

        return clientOrigin;
    }

    public String getOAuth2RedirectUri(HttpServletRequest request) {
        return determineBaseUrl(request) + frontRedirectUri;
    }

    // Helper Method
    public List<String> originListParser(String allowedOrigins) {
        return Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(o -> !o.isEmpty())
                .toList();
    }

    private void validateOrigin(String clientOrigin) {
        if (clientOrigin == null) {
            throw new IllegalArgumentException("🔴 Origin 헤더가 없습니다.");
        }

        List<String> allowedOriginList = originListParser(allowedOrigins); // 허용된 Origin 목록 파싱
        if (!allowedOriginList.contains(clientOrigin)) {
            throw new IllegalArgumentException("🔴 허용되지 않은 Origin: " + clientOrigin);
        }
    }

    private String getClientOriginByRequest(HttpServletRequest request) {
        String clientOrigin = request.getHeader("Origin");
        if (clientOrigin == null) {
            String referer = request.getHeader("Referer"); // Origin 헤더가 없으면 Referer에서 추출 시도
            if (referer != null) {
                try {
                    URI uri = URI.create(referer);
                    clientOrigin = uri.getScheme() + "://" + uri.getAuthority();
                } catch (Exception e) {
                    log.warn("Referer에서 Origin 추출 실패: {}", referer);
                }
            }
        }
        return clientOrigin;
    }
}
