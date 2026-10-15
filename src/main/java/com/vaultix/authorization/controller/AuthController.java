package com.vaultix.authorization.controller;

import java.util.Map;

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

import com.vaultix.authorization.config.properties.JwtProperties;
import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.LoginRequest;
import com.vaultix.authorization.dto.RefreshTokenRequest;
import com.vaultix.authorization.service.AuthService;
import com.vaultix.authorization.service.SigningKeyService;
import com.vaultix.common.dto.ApiResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final SigningKeyService signingKeyService;
    private final JwtProperties jwtProperties;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        AuthResponse authResponse = authService.login(request, "Unknown", "Unknown");
        ResponseCookie refreshCookie = createRefreshTokenCookie(authResponse.refreshToken(), httpRequest);

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

        AuthResponse authResponse = authService.refreshToken(token, "Unknown", "Unknown");
        ResponseCookie refreshCookie = createRefreshTokenCookie(authResponse.refreshToken(), httpRequest);

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

        ResponseCookie cleanCookie = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(httpRequest.isSecure() || "https".equalsIgnoreCase(httpRequest.getHeader("X-Forwarded-Proto")))
                .sameSite("Strict")
                .path("/api/v1/auth/refresh")
                .maxAge(0)
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cleanCookie.toString())
                .body(ApiResponse.success("Logged out successfully"));
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<Map<String, Object>>> getMe(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(ApiResponse.success("Current user profile", jwt.getClaims()));
    }

    private ResponseCookie createRefreshTokenCookie(String refreshToken, HttpServletRequest httpRequest) {
        return ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)
                .secure(httpRequest.isSecure() || "https".equalsIgnoreCase(httpRequest.getHeader("X-Forwarded-Proto")))
                .sameSite("Strict")
                .path("/api/v1/auth/refresh")
                .maxAge(jwtProperties.refreshTokenExpiration())
                .build();
    }
}
