package com.hooby.token.system.security.jwt.util;

import com.hooby.token.system.security.jwt.dto.JwtDto;
import com.hooby.token.system.security.jwt.entity.TokenType;
import com.hooby.token.system.security.jwt.exception.JwtBlacklistException;
import com.hooby.token.system.security.jwt.exception.JwtExpiredException;
import com.hooby.token.system.security.jwt.exception.JwtInvalidException;
import com.hooby.token.system.security.jwt.exception.JwtMalformedException;
import com.hooby.token.system.security.jwt.repository.TokenRedisRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SecurityException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.time.Duration;

@Slf4j
@RequiredArgsConstructor
public class JwtTokenValidator {
    private final TokenRedisRepository tokenRedisRepository;
    private final SecretKey secretKey;

    public void validateRtk(JwtDto.TokenPayload payload) {
        if (payload.getTokenType() != TokenType.REFRESH) {
            log.error("❌ RTK 검증 실패: TokenType이 REFRESH가 아닙니다. type: {}", payload.getTokenType());
            throw new JwtInvalidException();
        }
        if (payload.getSubject() == null || payload.getSubject().isEmpty()) {
            log.error("❌ RTK 검증 실패: Subject가 null이거나 비어있습니다.");
            throw new JwtInvalidException();
        }
        if (payload.getRefreshUuid() == null || payload.getRefreshUuid().isEmpty()) {
            log.error("❌ RTK 검증 실패: RefreshUuid가 null이거나 비어있습니다.");
            throw new JwtInvalidException();
        }

        String submittedUuid = payload.getRefreshUuid();
        String subject = payload.getSubject();
        
        // 블랙리스트 체크를 먼저 수행 (이미 무효화된 토큰은 즉시 거부)
        if (tokenRedisRepository.isRtkBlacklisted(submittedUuid)) {
            log.error("❌ RTK 검증 실패: RTK가 블랙리스트에 등록되어 있습니다. UUID: {}", submittedUuid);
            throw new JwtInvalidException();
        }
        
        String allowedRtk = tokenRedisRepository.getAllowedRtk(subject);

        log.info("🔍 RTK 검증 - Subject: {}, Submitted UUID: {}, Allowed UUID: {}", 
                subject, submittedUuid, allowedRtk);

        if (allowedRtk == null) {
            log.error("❌ RTK 검증 실패: Redis에서 허용된 RTK를 찾을 수 없습니다. Subject: {}", subject);
            throw new JwtInvalidException();
        }
        if (!allowedRtk.equals(submittedUuid)) {
            log.error("❌ RTK 검증 실패: 제출된 UUID와 허용된 UUID가 일치하지 않습니다. Submitted: {}, Allowed: {}", 
                    submittedUuid, allowedRtk);
            // 이전 RTK를 블랙리스트에 추가 (새 로그인 후 이전 RTK 사용 방지)
            log.info("🔒 이전 RTK를 블랙리스트에 등록 - UUID: {}", submittedUuid);
            tokenRedisRepository.setBlacklistRtk(submittedUuid, Duration.ofHours(1));
            throw new JwtInvalidException();
        }
        
        log.info("✅ RTK 검증 성공 - Subject: {}, UUID: {}", subject, submittedUuid);
    }

    public void validateAtk(JwtDto.TokenPayload payload) {
        if (payload.getTokenType() != TokenType.ACCESS) throw new JwtInvalidException();
        if (payload.getJti() == null) throw new JwtInvalidException();
        if (tokenRedisRepository.isAtkBlacklisted(payload.getJti())) throw new JwtBlacklistException();
    }

    public Jws<Claims> parseClaimsWithValidation(String token) {
        try {
            return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
        } catch (SecurityException | UnsupportedJwtException | IllegalArgumentException e) {
            throw new JwtInvalidException(e);
        } catch (MalformedJwtException e) {
            throw new JwtMalformedException(e);
        } catch (ExpiredJwtException e) {
            throw new JwtExpiredException(e);
        }
    }
}