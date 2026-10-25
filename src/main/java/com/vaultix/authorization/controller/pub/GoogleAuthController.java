package com.vaultix.authorization.controller.pub;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.oauth2.GoogleLoginRequest;
import com.vaultix.authorization.security.AuthCookieHelper;
import com.vaultix.authorization.service.GoogleAuthService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.util.ClientContextUtil;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Validated
@RestController
@RequestMapping("/public")
@RequiredArgsConstructor
public class GoogleAuthController {

    private final GoogleAuthService googleAuthService;
    private final AuthCookieHelper authCookieHelper;

    @PostMapping({"/login/google", "/oauth2/google"})
    public ResponseEntity<ApiResponse<AuthResponse>> loginWithGoogle(
            @Valid @RequestBody GoogleLoginRequest request,
            HttpServletRequest httpRequest) {

        ClientContext clientContext = ClientContextUtil.extract(httpRequest);
        AuthResponse authResponse = googleAuthService.loginWithGoogle(request, clientContext);

        if (Boolean.TRUE.equals(authResponse.mfaRequired())) {
            return ResponseEntity.ok(ApiResponse.success(
                    "MFA verification required. Please provide your TOTP or recovery code.",
                    authResponse));
        }

        ResponseCookie refreshCookie = authCookieHelper.createRefreshTokenCookie(authResponse.refreshToken(), httpRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(ApiResponse.success("Google authentication successful", authResponse));
    }
}
