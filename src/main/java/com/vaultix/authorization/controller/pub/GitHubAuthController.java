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
import com.vaultix.authorization.dto.oauth2.GitHubLoginRequest;
import com.vaultix.authorization.security.AuthCookieHelper;
import com.vaultix.authorization.service.GitHubAuthService;
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
public class GitHubAuthController {

    private final GitHubAuthService gitHubAuthService;
    private final AuthCookieHelper authCookieHelper;

    @PostMapping({"/login/github", "/oauth2/github"})
    public ResponseEntity<ApiResponse<AuthResponse>> loginWithGitHub(
            @Valid @RequestBody GitHubLoginRequest request,
            HttpServletRequest httpRequest) {

        ClientContext clientContext = ClientContextUtil.extract(httpRequest);
        AuthResponse authResponse = gitHubAuthService.loginWithGitHub(request, clientContext);

        if (Boolean.TRUE.equals(authResponse.mfaRequired())) {
            return ResponseEntity.ok(ApiResponse.success(
                    "MFA verification required. Please provide your TOTP or recovery code.",
                    authResponse));
        }

        ResponseCookie refreshCookie = authCookieHelper.createRefreshTokenCookie(authResponse.refreshToken(), httpRequest);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(ApiResponse.success("GitHub authentication successful", authResponse));
    }
}
