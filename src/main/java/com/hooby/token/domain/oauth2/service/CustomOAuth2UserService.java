package com.hooby.token.domain.oauth2.service;

import com.hooby.token.domain.oauth2.dto.*;
import com.hooby.token.domain.oauth2.entity.CustomOAuth2User;
import com.hooby.token.domain.user.entity.User;
import com.hooby.token.domain.user.entity.enums.Role;
import com.hooby.token.domain.user.repository.UserRepository;
import com.hooby.token.system.security.util.HmacUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;
    private final HmacUtil hmacUtil;

    @Transactional
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        // Request 기반으로 OAuth2User 정의
        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("🟢 OAuth2 User: {}",oAuth2User.getAttributes());

        // OAuth2User + Request 기반으로 Response 생성
        OAuth2Response oAuth2Response = getOAuth2Response(userRequest, oAuth2User);

        // Response 할 DTO
        final OAuth2UserDto oAuth2UserDto = OAuth2UserDto.of(Role.USER, oAuth2Response, hmacUtil);

        // 기존 OAuth2 유저 있으면 사용, 없으면 생성 -> 기존 회원이거나 새로 등록된 회원
        User user = userRepository.findByUsername(oAuth2UserDto.getUsername())
                .orElseGet(() -> {
                    try { // 동시성 이슈 대응
                        return userRepository.save(oAuth2UserDto.toUser());
                    } catch (DataIntegrityViolationException e) { // 유니크 충돌 시 재조회로 수습
                        return userRepository.findByUsername(oAuth2UserDto.getUsername()).orElseThrow(() -> e);
                    }
                });


        // 불러온 회원 정보로 Response DTO 업데이트 후 내보냄 (PK 가 있어야 Audit 이든 UserPrincipal 이든 뭐든 될 것이기 때문)

        return new CustomOAuth2User(OAuth2UserDto.from(user));
    }

    private static OAuth2Response getOAuth2Response(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = null;

        switch (registrationId) {
            case "google" -> oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
            case "naver" -> oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
            case "kakao" -> oAuth2Response = new KaKaoResponse(oAuth2User.getAttributes());
            default -> throw new OAuth2AuthenticationException("Invalid OAuth2 Provider");
        }
        return oAuth2Response;
    }
}
