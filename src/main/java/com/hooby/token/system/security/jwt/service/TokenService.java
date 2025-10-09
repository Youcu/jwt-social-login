package com.hooby.token.system.security.jwt.service;

import com.hooby.token.system.exception.model.BaseException;
import com.hooby.token.system.exception.model.ErrorCode;
import com.hooby.token.system.security.jwt.dto.JwtDto;
import com.hooby.token.system.security.jwt.entity.TokenType;
import com.hooby.token.system.security.jwt.exception.JwtInvalidException;
import com.hooby.token.system.security.jwt.repository.TokenRedisRepository;
import com.hooby.token.system.security.jwt.util.JwtTokenProvider;
import com.hooby.token.system.security.jwt.util.JwtTokenResolver;
import com.hooby.token.system.security.jwt.util.JwtTokenValidator;
import com.hooby.token.system.security.model.UserPrincipal;
import com.hooby.token.system.security.util.UserLoadService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;

/**
 * JWT의 발급, 재발급(회전), 폐기 등 토큰의 생명주기를 관리하는 서비스 클래스입니다.
 * Redis를 사용하여 Refresh Token의 상태를 관리합니다.
 *
 * @see JwtTokenProvider
 * @see JwtTokenResolver
 * @see TokenRedisRepository
 * @see UserLoadService
 */
@Service
@RequiredArgsConstructor
public class TokenService {
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtTokenResolver jwtTokenResolver;
    private final TokenRedisRepository tokenRedisRepository;
    private final UserLoadService userLoadService;
    private final JwtTokenValidator jwtTokenValidator;

    /**
     * <h4>Description</h4>
     * 사용자가 최초 인증에 성공했을 때 Access Token과 Refresh Token을 발급합니다.<br>
     * 발급된 Refresh Token은 Redis에 등록되어 추후 재발급 요청에 사용됩니다.<br><br>
     *
     * <h4>Main Logic</h4><ol>
     * <li>RTK 발급: JwtTokenProvier로 TokenPair 생성 </li>
     * <li>Redis에 RTK 등록: subject, RTK TTL를 활용해서 TokenRedisRepository로 RTK 등록</li>
     * <li>Client에 Token 반환: JwtDto.TokenInfo</li></ol><br>
     *
     * <h4>Details</h4><ul>
     * <li>2-1. subject: UserPrincipal로 생성. 이때 일반 유저면 userId를, OAuth2 유저면 username을 이용</li>
     * <li>2-2. RTK TTL: 현재와 RTK의 expiredAt 값 사이의 시간을 설정</li></ul><br>
     *
     * @param userPrincipal 인증된 사용자의 정보를 담은 UserPrincipal 객체
     * @return 발급된 Access Token과 Refresh Token 정보를 담은 DTO
     * @see UserPrincipal
     * @see JwtDto.TokenPair
     */
    public JwtDto.TokenInfo issueTokens(UserPrincipal userPrincipal) {
        JwtDto.TokenPair tokenPair = jwtTokenProvider.createTokenPair(userPrincipal);
        String subject = userPrincipal.getUserId() != null
                ? userPrincipal.getUserId().toString()
                : userPrincipal.getUsername();

        Duration rtTtl = Duration.between(LocalDateTime.now(), tokenPair.getRefreshToken().getExpiredAt());
        tokenRedisRepository.allowRtk(subject, extractRefreshUuid(tokenPair), rtTtl); // TODO : 추후 구현
        return JwtDto.TokenInfo.of(tokenPair);
    }

    /**
     * <h4>Description</h4>
     * 유효한 Refresh Token을 사용하여 새로운 Access Token과 Refresh Token을 재발급(회전)합니다.<br>
     * 보안을 위해 기존 Refresh Token은 블랙리스트에 등록하고, 새로운 Refresh Token을 Redis에 등록합니다.<br><br>
     *
     * <h4>Logic</h4><ol>
     * <li>Client 와 Server(Redis) RTK 비교 및 검증: payload, subject, submittedUuid, TokenRedisRepository 사용</li>
     * <li>Origin RTK Blacklist 처리: 잔여 TTL만큼 Redis에 Origin RTK를 Blacklist로 등록</li>
     * <li>New RTK 발급 후 Redis에 등록: JwtTokenProvider로 TokenPair 생성 후 TokenRedisRepository로 RTK 등록</li>
     * <li>Client에 Token 반환: JwtDto.TokenInfo</li></ol><br>
     *
     * <h4>Details</h4><ul>
     * <li>1-1. 비교 검증: Redis RTK의 null 여부, 제공받은 RTK와 일치 여부, 블랙리스트 여부</li></ul><br>
     *
     * @param request 클라이언트로부터 전달받은 Refresh Token 문자열을 포함한 Authorization Header
     * @return 새로 발급된 Access Token과 Refresh Token 정보를 담은 DTO
     * @throws JwtInvalidException 전달된 토큰이 유효하지 않거나, 허용된 Refresh Token이 아닐 경우 발생
     * @see TokenService#resolveUser(String)
     * @see JwtTokenValidator
     */
    public JwtDto.TokenInfo rotateByRtk(JwtDto.ReissueRequest reissueRequest) {
        String refreshToken = reissueRequest.getRefreshToken();

        var payload = jwtTokenResolver.resolveToken(refreshToken);
        jwtTokenValidator.validateRtk(payload);

        String subject = payload.getSubject();
        String submittedUuid = payload.getRefreshUuid();

        // AllowedRtk 와 SubmittedRtk Validation
        jwtTokenValidator.validateSubmittedRtk(payload);

        UserPrincipal userPrincipal = resolveUser(subject);
        JwtDto.TokenPair tokenPair = jwtTokenProvider.createTokenPair(userPrincipal);

        Duration oldRtTtl = Duration.between(LocalDateTime.now(), payload.getExpiredAt());
        tokenRedisRepository.setBlacklistRtk(submittedUuid, oldRtTtl);

        Duration newRtTtl = Duration.between(LocalDateTime.now(), tokenPair.getRefreshToken().getExpiredAt());
        tokenRedisRepository.allowRtk(subject, extractRefreshUuid(tokenPair), newRtTtl);

        return JwtDto.TokenInfo.of(tokenPair);
    }

    /**
     * <h4>Description</h4>
     * 사용자의 로그아웃 요청을 처리합니다.<br>
     * 전달받은 Access Token을 블랙리스트에 등록하여 더 이상 사용할 수 없게 만들고,<br>
     * 해당 사용자의 현재 유효한 Refresh Token 또한 폐기하여 세션을 완전히 종료시킵니다.<br><br>
     *
     * <h4>Main logic</h4><ul>
     * <li>ATK Blacklist 등록: Payload 에서 jti, ttl 추출 후 TokenRedisRepository 로 블랙리스트 등록</li>
     * <li>RTK Blacklist 등록: Payload 에서 Subject 추출 후 TokenRedisRepository 로 블랙리스트 등록</li>
     * <li>Origin ATK 해제: Subject 값과 함께 TokenRedisRepository 로 해제</li>
     * </ul>
     *
     * @param accessToken 로그아웃을 요청한 사용자의 Access Token 문자열
     * @throws JwtInvalidException 전달된 토큰이 유효한 Access Token이 아닐 경우 발생
     */
    public void logoutByAtk(String accessToken) {
        var payload = jwtTokenResolver.resolveToken(accessToken);
        if (payload.getTokenType() != TokenType.ACCESS) throw new JwtInvalidException();

        Duration atTtl = Duration.between(LocalDateTime.now(), payload.getExpiredAt());
        tokenRedisRepository.setBlacklistAtkJti(payload.getJti(), atTtl);

        String subject = payload.getSubject();
        String cur = tokenRedisRepository.getAllowedRtk(subject);
        if (cur != null) tokenRedisRepository.setBlacklistRtk(cur, atTtl);
        tokenRedisRepository.clearAllowedRtk(subject);
    }

    /**
     * <h4>Description</h4>
     * 토큰의 subject 클레임을 사용하여 사용자 정보를 조회하는 내부 헬퍼 메서드입니다.<br>
     * subject는 사용자의 ID 또는 username일 수 있습니다.<br><br>
     *
     * <h4>Main Logic</h4><ul>
     * <li>UserPrincipal 반환: subject(id || username)를 UserLoadService 에 넣어 생성</li></ul><br>
     *
     * @param subject JWT payload의 subject 클레임 값
     * @return 조회된 사용자 정보를 담은 UserPrincipal 객체
     * @throws JwtInvalidException subject에 해당하는 사용자를 찾을 수 없을 경우 발생
     * @see UserLoadService
     */
    private UserPrincipal resolveUser(String subject) {
        try {
            Long id = Long.valueOf(subject);
            return userLoadService.loadUserById(id).orElseThrow(JwtInvalidException::new);
        } catch (NumberFormatException nfe) {
            return userLoadService.loadUserByUsername(subject).orElseThrow(JwtInvalidException::new);
        }
    }

    /**
     * <h4>Description</h4>
     * Refresh Token에서 고유 식별자인 UUID를 추출하는 내부 헬퍼 메서드입니다.<br><br>
     *
     * @param tokenPair Access/Refresh 토큰 쌍 DTO
     * @return 추출된 Refresh Token의 UUID 문자열
     */
    private String extractRefreshUuid(JwtDto.TokenPair tokenPair) {
        var payload = jwtTokenResolver.resolveToken(tokenPair.getRefreshToken().getToken());
        return payload.getRefreshUuid();
    }
}
