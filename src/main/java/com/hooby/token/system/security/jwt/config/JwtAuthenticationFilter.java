package com.hooby.token.system.security.jwt.config;

import com.hooby.token.system.security.jwt.dto.JwtDto;
import com.hooby.token.system.security.jwt.exception.JwtInvalidException;
import com.hooby.token.system.security.jwt.exception.JwtMissingException;
import com.hooby.token.system.security.jwt.util.JwtTokenResolver;
import com.hooby.token.system.security.jwt.util.JwtTokenValidator;
import com.hooby.token.system.security.model.UserPrincipal;
import com.hooby.token.system.security.util.UserLoadService;
import java.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenResolver jwtTokenResolver;
    private final UserLoadService userLoadService;
    private final JwtTokenValidator jwtTokenValidator;
    // TODO : Blacklist Validation Logic

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        try {
            // Parse Token From Request
            String token = jwtTokenResolver.parseTokenFromRequest(request)
                    .orElseThrow(JwtMissingException::new);

            // TODO: Token Validation -> Expiration, Validation, Blacklist

            // Extract JWT Payload
            JwtDto.TokenPayload payload = jwtTokenResolver.resolveToken(token);

            // Define UserPrincipal
            UserPrincipal userPrincipal = userLoadService.loadUserById(Long.valueOf(payload.getSubject()))
                    .orElseThrow(JwtInvalidException::new);

            // Create Authentication Instance
            Authentication authentication = createAuthentication(userPrincipal);

            // Register Authentication to SecurityContextHolder
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.debug("JWT authentication successful for user: {}", userPrincipal.getUsername());
        } catch (JwtInvalidException e) {
            log.error("JWT authentication failed", e);
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private Authentication createAuthentication(UserPrincipal userPrincipal) {
        List<SimpleGrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority(userPrincipal.getRole().toString())
        );

        return new UsernamePasswordAuthenticationToken(
                userPrincipal,
                null, // OAuth2 사용자는 패스워드 없음
                authorities
        );
    }
}
