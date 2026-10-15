package com.vaultix.authorization.controller;

import java.util.Map;
import java.util.UUID;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.LoginRequest;
import com.vaultix.authorization.dto.RefreshTokenRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.security.AuthCookieHelper;
import com.vaultix.authorization.service.AuthService;
import com.vaultix.authorization.service.SigningKeyService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.util.ClientContextUtil;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final SigningKeyService signingKeyService;
    private final AuthCookieHelper authCookieHelper;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        ClientContext clientContext = ClientContextUtil.extract(httpRequest);
        AuthResponse authResponse = authService.login(request, clientContext.deviceInfo(), clientContext.ip());
        ResponseCookie refreshCookie = authCookieHelper.createRefreshTokenCookie(authResponse.refreshToken(), httpRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(ApiResponse.success("Authentication successful", authResponse));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(
            @CookieValue(name = "refresh_token", required = false) String cookieRefreshToken,
            @Valid @RequestBody(required = false) RefreshTokenRequest requestBody,
            HttpServletRequest httpRequest) {

        String token = (cookieRefreshToken != null && !cookieRefreshToken.isBlank())
                ? cookieRefreshToken
                : (requestBody != null ? requestBody.refreshToken() : null);

        if (token == null || token.isBlank()) {
            throw new BadCredentialsException("Refresh token is required");
        }

        if (token.length() > RefreshTokenRequest.MAX_LENGTH) {
            throw new BadCredentialsException("Refresh token exceeds maximum allowed length");
        }

        ClientContext clientContext = ClientContextUtil.extract(httpRequest);
        AuthResponse authResponse = authService.refreshToken(token, clientContext.deviceInfo(), clientContext.ip());
        ResponseCookie refreshCookie = authCookieHelper.createRefreshTokenCookie(authResponse.refreshToken(), httpRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(ApiResponse.success("Token refreshed successfully", authResponse));
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> getJwks() {
        return signingKeyService.getJwkSetAsMap();
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest httpRequest) {

        if (jwt != null && jwt.getId() != null) {
            authService.logout(jwt.getId());
        }

        ResponseCookie cleanCookie = authCookieHelper.createCleanCookie(httpRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                .body(ApiResponse.success("Logged out successfully"));
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserProfileDto>> getMe(@AuthenticationPrincipal Jwt jwt) {
        if (jwt == null || jwt.getSubject() == null) {
            throw new BadCredentialsException("Invalid or missing authentication token");
        }
        UUID userId = UUID.fromString(jwt.getSubject());
        UserProfileDto profile = authService.getProfile(userId);
        return ResponseEntity.ok(ApiResponse.success("Current user profile", profile));
    }
}
