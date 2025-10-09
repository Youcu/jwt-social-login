package com.hooby.token.system.security.jwt;

import com.hooby.token.system.security.jwt.dto.JwtDto;
import com.hooby.token.system.security.jwt.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class TokenController {
    private final TokenService tokenService;

    @PostMapping("/refresh")
    public ResponseEntity<JwtDto.TokenInfo> refresh(@RequestBody @Valid JwtDto.ReissueRequest reissueRequest) {
        return ResponseEntity.ok(tokenService.rotateByRtk(reissueRequest));
    }
}