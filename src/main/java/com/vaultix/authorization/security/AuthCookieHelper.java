package com.vaultix.authorization.security;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.JwtProperties;
import com.vaultix.authorization.dto.RefreshTokenRequest;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;

@Component
@Validated
@RequiredArgsConstructor
public class AuthCookieHelper {

    public static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";
    public static final String REFRESH_COOKIE_PATH = "/api/v1/auth/public/refresh";

    private final JwtProperties jwtProperties;

    /**
     * Builds a secure HTTP-only cookie carrying the refresh token.
     *
     * @param refreshToken the raw refresh token string
     * @param request the HTTP servlet request used to check secure/TLS context
     * @return the configured ResponseCookie
     */
    public ResponseCookie createRefreshTokenCookie(
            @NotBlank(message = "Refresh token is required")
            @Size(max = RefreshTokenRequest.MAX_LENGTH, message = "Refresh token cannot exceed " + RefreshTokenRequest.MAX_LENGTH + " characters") String refreshToken,
            @NotNull(message = "HTTP request cannot be null") HttpServletRequest request) {

        return ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, refreshToken.strip())
                .httpOnly(true)
                .secure(isSecure(request))
                .sameSite("Strict")
                .path(REFRESH_COOKIE_PATH)
                .maxAge(jwtProperties.refreshTokenExpiration())
                .build();
    }

    /**
     * Builds an expired HTTP-only cookie to clear the refresh token on logout.
     *
     * @param request the HTTP servlet request used to check secure/TLS context
     * @return the configured ResponseCookie with maxAge 0
     */
    public ResponseCookie createCleanCookie(
            @NotNull(message = "HTTP request cannot be null") HttpServletRequest request) {

        return ResponseCookie.from(REFRESH_TOKEN_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(isSecure(request))
                .sameSite("Strict")
                .path(REFRESH_COOKIE_PATH)
                .maxAge(0)
                .build();
    }

    private boolean isSecure(HttpServletRequest request) {
        return request.isSecure() || "https".equalsIgnoreCase(request.getHeader("X-Forwarded-Proto"));
    }
}
