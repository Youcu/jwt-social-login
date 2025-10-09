package com.hooby.token.system.security.jwt.config;

import com.hooby.token.system.security.jwt.dto.JwtDto;
import com.hooby.token.system.security.jwt.entity.TokenType;
import com.hooby.token.system.security.jwt.exception.JwtBlacklistException;
import com.hooby.token.system.security.jwt.exception.JwtInvalidException;
import com.hooby.token.system.security.jwt.exception.JwtMissingException;
import com.hooby.token.system.security.jwt.repository.TokenRedisRepository;
import com.hooby.token.system.security.jwt.util.JwtTokenResolver;
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
    private final TokenRedisRepository tokenRedisRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        try {
            // Parse Token From Request
            String token = jwtTokenResolver.parseTokenFromRequest(request).orElseThrow(JwtMissingException::new);

            // Extract JWT Payload with Validation (Token 자체의 유효성 검증)
            JwtDto.TokenPayload payload = jwtTokenResolver.resolveToken(token);

            // ATK Validation: isAtk? isValidJti? isBlacklist? (사용 목적에 따른 유효성 검증)
            if (payload.getTokenType() != TokenType.ACCESS) throw new JwtInvalidException();
            if (payload.getJti() == null) throw new JwtInvalidException();
            if (tokenRedisRepository.isAtkBlacklisted(payload.getJti())) throw new JwtBlacklistException();

            // Define UserPrincipal
            UserPrincipal userPrincipal = userLoadService.loadUserById(Long.valueOf(payload.getSubject()))
                    .orElseThrow(JwtInvalidException::new);

            // Create Authentication Instance
            Authentication authentication = createAuthentication(userPrincipal);

            // Register Authentication to SecurityContextHolder
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.debug("🟢 JWT authentication successful for user: {}", userPrincipal.getUsername());
        } catch (JwtInvalidException e) {
            log.error("⚠️ JWT authentication failed", e);
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private Authentication createAuthentication(UserPrincipal userPrincipal) {
        List<SimpleGrantedAuthority> authorities =
                List.of(new SimpleGrantedAuthority(userPrincipal.getRole().name()));

        return new UsernamePasswordAuthenticationToken(userPrincipal, null, authorities);
    }
}
