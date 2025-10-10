package com.hooby.token.domain.auth.controller;

import com.hooby.token.domain.auth.dto.AuthDto;
import com.hooby.token.domain.auth.service.AuthService;
import com.hooby.token.domain.user.dto.UserDto;
import com.hooby.token.system.security.util.QueryParamValidator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
@Tag(name = "Auth", description = "인증/인가 API")
public class AuthController {
    // NO AUTH
    private final AuthService authService;
    @PostMapping("/register")
    @Operation(summary = "회원가입", description = "새로운 사용자를 등록합니다.")
    @ApiResponse(responseCode = "200", description = "회원가입 성공")
    public UserDto.UserResponse signUp(@RequestBody @Valid AuthDto.SignUpRequest request) {
        return authService.signUp(request);

        // TODO : Multipart 도입할 때는 @RequestBody -> @ModelAttribute 로 둔다.
    }

    // NO AUTH
    @PostMapping("/login")
    @Operation(summary = "로그인", description = "사용자 아이디와 비밀번호로 로그인하여 JWT 토큰을 발급받습니다.")
    @ApiResponse(responseCode = "200", description = "로그인 성공")
    public AuthDto.LoginResponse login(@RequestBody @Valid AuthDto.LoginRequest request) {
        return authService.login(request);
    }

    // NO AUTH
    @GetMapping("/email-exist")
    @Operation(summary = "이메일 중복 확인", description = "입력된 이메일의 사용 가능 여부를 확인합니다.")
    @ApiResponse(responseCode = "200", description = "이메일 확인 성공")
    public AuthDto.ExistResponse checkEmail(@RequestParam("email") String email)
    {
        QueryParamValidator.validateEmail(email);
        return authService.checkEmailExist(email);
    }

    // NO AUTH
    @GetMapping("/nickname-exist")
    @Operation(summary = "닉네임 중복 확인", description = "입력된 닉네임의 사용 가능 여부를 확인합니다.")
    @ApiResponse(responseCode = "200", description = "닉네임 확인 성공")
    public AuthDto.ExistResponse checkNickname(@RequestParam("nickname") String nickname) {
        QueryParamValidator.validateNickname(nickname);
        return authService.checkNicknameExist(nickname);
    }

    // NO AUTH
    @GetMapping("/username-exist")
    @Operation(summary = "사용자 아이디 중복 확인", description = "입력된 사용자 아이디의 사용 가능 여부를 확인합니다.")
    @ApiResponse(responseCode = "200", description = "사용자 아이디 확인 성공")
    public AuthDto.ExistResponse checkUsername(@RequestParam("username") String username) {
        QueryParamValidator.validateUsername(username);
        return authService.checkUsernameExist(username);
    }

    @PostMapping("/logout")
    @Operation(summary = "로그아웃", description = "로그아웃 처리합니다.")
    @ApiResponse(
        responseCode = "200", description = "로그아웃 성공",
        content = @Content(mediaType = "text/plain", examples = @ExampleObject(value = "Logout Successful"))
    )
    public ResponseEntity<String> logout(HttpServletRequest request) {
        authService.logout(request);
        return ResponseEntity.ok("Logout Successful");
    }
}
