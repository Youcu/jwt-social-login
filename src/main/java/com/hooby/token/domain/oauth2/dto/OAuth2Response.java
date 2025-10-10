package com.hooby.token.domain.oauth2.dto;

public interface OAuth2Response {
    String getProvider();
    String getProviderId();
    String getEmail();
    String getNickname();
}
