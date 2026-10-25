package com.vaultix.authorization.controller.pub;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.LoginRequest;
import com.vaultix.authorization.dto.RefreshTokenRequest;
import com.vaultix.authorization.dto.RegisterRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.dto.mfa.MfaLoginRequest;
import com.vaultix.authorization.dto.mfa.SendLoginSmsOtpRequest;
import com.vaultix.authorization.security.AuthCookieHelper;
import com.vaultix.authorization.service.AuthService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.util.ClientContextUtil;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Validated
@RestController
@RequestMapping("/public")
@RequiredArgsConstructor
public class PublicAuthController {

    private final AuthService authService;
    private final AuthCookieHelper authCookieHelper;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserProfileDto>> register(
            @Valid @RequestBody RegisterRequest request) {

        UserProfileDto profile = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("User registered successfully", profile));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        ClientContext clientContext = ClientContextUtil.extract(httpRequest);
        AuthResponse authResponse = authService.login(request, clientContext);

        if (Boolean.TRUE.equals(authResponse.mfaRequired())) {
            return ResponseEntity.ok(ApiResponse.success("MFA verification required. Please provide your TOTP or recovery code.", authResponse));
        }

        ResponseCookie refreshCookie = authCookieHelper.createRefreshTokenCookie(authResponse.refreshToken(), httpRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(ApiResponse.success("Authentication successful", authResponse));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(
            @CookieValue(name = "refresh_token", required = false)
            @Size(max = RefreshTokenRequest.MAX_LENGTH, message = "Refresh token cannot exceed " + RefreshTokenRequest.MAX_LENGTH + " characters") String cookieRefreshToken,
            @Valid @RequestBody(required = false) RefreshTokenRequest requestBody,
            HttpServletRequest httpRequest) {

        String token = (cookieRefreshToken != null && !cookieRefreshToken.isBlank())
                ? cookieRefreshToken
                : (requestBody != null ? requestBody.refreshToken() : null);

        if (token == null || token.isBlank()) {
            throw new BadCredentialsException("Refresh token is required");
        }

        ClientContext clientContext = ClientContextUtil.extract(httpRequest);
        AuthResponse authResponse = authService.refreshToken(token.strip(), clientContext);
        ResponseCookie refreshCookie = authCookieHelper.createRefreshTokenCookie(authResponse.refreshToken(), httpRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(ApiResponse.success("Token refreshed successfully", authResponse));
    }

    @PostMapping({"/login/mfa", "/login/verify-mfa", "/mfa/verify"})
    public ResponseEntity<ApiResponse<AuthResponse>> loginWithMfa(
            @Valid @RequestBody MfaLoginRequest request,
            HttpServletRequest httpRequest) {

        ClientContext clientContext = ClientContextUtil.extract(httpRequest);
        AuthResponse authResponse = authService.loginWithMfa(request, clientContext);
        ResponseCookie refreshCookie = authCookieHelper.createRefreshTokenCookie(authResponse.refreshToken(), httpRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(ApiResponse.success("Authentication successful", authResponse));
    }

    @PostMapping({"/login/mfa/sms/send-otp", "/login/mfa/sms/send", "/mfa/sms/send-login-otp"})
    public ResponseEntity<ApiResponse<Void>> sendLoginSmsOtp(
            @Valid @RequestBody SendLoginSmsOtpRequest request) {

        authService.sendLoginSmsOtp(request.mfaToken());
        return ResponseEntity.ok(ApiResponse.success("SMS verification code sent successfully."));
    }
}
