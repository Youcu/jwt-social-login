package com.hooby.token.domain.auth.service;

import com.hooby.token.domain.auth.dto.AuthDto;
import com.hooby.token.domain.user.dto.UserDto;
import com.hooby.token.domain.user.entity.User;
import com.hooby.token.domain.user.repository.UserRepository;
import com.hooby.token.system.exception.model.RestException;
import com.hooby.token.system.exception.model.ErrorCode;
import com.hooby.token.system.security.jwt.dto.JwtDto;
import com.hooby.token.system.security.jwt.service.TokenService;
import com.hooby.token.system.security.jwt.util.JwtTokenResolver;
import com.hooby.token.system.security.model.UserPrincipal;
import com.hooby.token.system.security.util.CookieUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final JwtTokenResolver jwtTokenResolver;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final CookieUtils cookieUtils;

    @Transactional
    public UserDto.UserResponse signUp(AuthDto.SignUpRequest request) {
        validateAlreadyUser(request);
        User savedUser = userRepository.save(request.toEntity(passwordEncoder));
        return UserDto.UserResponse.from(savedUser);
    }

    @Transactional
    public AuthDto.LoginResponse login(AuthDto.LoginRequest request, HttpServletResponse response) {
        User validatedUser = getValidatedLoginUser(request, passwordEncoder);
        JwtDto.TokenInfo tokenInfo = tokenService.issueTokens(UserPrincipal.from(validatedUser));

        // 이전 path의 쿠키 삭제 (path 변경 시 이전 쿠키 제거)
        cookieUtils.clearRtkCookiesByPaths(response);

        // Cookie Setup
        cookieUtils.addAccessTokenCookie(response, tokenInfo.getAccessToken(), tokenInfo.getAccessTokenExpiresAt());
        cookieUtils.addRefreshTokenCookie(response, tokenInfo.getRefreshToken(), tokenInfo.getRefreshTokenExpiresAt());

        return AuthDto.LoginResponse.of(
            UserDto.UserResponse.from(validatedUser),
            JwtDto.TokenExpiresInfo.of(tokenInfo)
        );
    }

    @Transactional
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        String accessToken = jwtTokenResolver.parseTokenFromRequest(request)
                .orElseThrow(() -> new RestException(ErrorCode.JWT_MISSING));

        String refreshToken = jwtTokenResolver.parseRefreshTokenFromRequest(request)
                .orElseThrow(() -> new RestException(ErrorCode.JWT_MISSING));

        // 1) 서버 측 토큰(ATK/RTK) 무효화 (예: Redis blacklist)
        tokenService.logoutByAtkWithValidation(accessToken, refreshToken);

        // 2) 브라우저 쿠키 제거 (same name, same path, domain 등으로)
        cookieUtils.clearAccessTokenCookie(response);
        cookieUtils.clearRefreshTokenCookie(response);
    }

    @Transactional(readOnly = true)
    public AuthDto.ExistResponse checkEmailExist(String email) {
        boolean exists = userRepository.existsByEmail(email);
        return AuthDto.ExistResponse.ofEmail(exists, email);
    }

    @Transactional(readOnly = true)
    public AuthDto.ExistResponse checkNicknameExist(String nickname) {
        boolean exists = userRepository.existsByNickname(nickname);
        return AuthDto.ExistResponse.ofNickname(exists, nickname);
    }

    @Transactional(readOnly = true)
    public AuthDto.ExistResponse checkUsernameExist(String username) {
        boolean exists = userRepository.existsByUsername(username);
        return AuthDto.ExistResponse.ofUsername(exists, username);
    }

    @Transactional
    public JwtDto.TokenExpiresInfo refreshTokens(HttpServletRequest request, HttpServletResponse response) {
        JwtDto.TokenInfo tokenInfo = tokenService.rotateByRtkWithValidation(request, response);
        return JwtDto.TokenExpiresInfo.of(tokenInfo);
    }

    private void validateAlreadyUser(AuthDto.SignUpRequest request) {
        boolean isAlreadyUser = userRepository.existsByUsername(request.getUsername());
        if (isAlreadyUser) throw new RestException(ErrorCode.USER_USERNAME_ALREADY_EXISTS);
    }

    private User getValidatedLoginUser(AuthDto.LoginRequest request, PasswordEncoder passwordEncoder) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RestException(ErrorCode.AUTH_USER_NOT_FOUND));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RestException(ErrorCode.AUTH_PASSWORD_NOT_MATCH);
        }

        return user;
    }

}
