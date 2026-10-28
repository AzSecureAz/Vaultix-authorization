package com.vaultix.authorization.security.webauthn;

import java.io.IOException;
import java.time.Instant;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.security.AuthCookieHelper;
import com.vaultix.authorization.security.CustomUserDetails;
import com.vaultix.authorization.security.CustomUserDetailsService;
import com.vaultix.authorization.service.TokenService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.util.ClientContextUtil;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import tools.jackson.databind.ObjectMapper;

@Slf4j
@Component
@RequiredArgsConstructor
public class WebAuthnAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final CustomUserDetailsService userDetailsService;
    private final TokenService tokenService;
    private final AuthCookieHelper authCookieHelper;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    @Override
    @Transactional
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        String username = authentication.getName();
        CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(username);

        User user = userRepository.findById(userDetails.getId()).orElse(null);
        if (user == null || user.getStatus() != UserStatus.ACTIVE) {
            SecurityContextHolder.clearContext();
            String errorMsg;
            if (user == null || user.getStatus() == UserStatus.DELETED) {
                errorMsg = "Account not found or has been deleted.";
            } else if (user.getStatus() == UserStatus.DISABLED) {
                errorMsg = "Account is disabled. Please contact support.";
            } else if (user.getStatus() == UserStatus.LOCKED) {
                errorMsg = "Account is temporarily locked due to multiple failed login attempts. Please try again later.";
            } else {
                errorMsg = "Account is not active. Please contact support.";
            }

            log.warn("Passkey login rejected for user '{}' (status: {})", username, user != null ? user.getStatus() : "NOT_FOUND");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");
            ApiResponse<Void> apiResponse = ApiResponse.error(errorMsg);
            objectMapper.writeValue(response.getWriter(), apiResponse);
            return;
        }

        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setLastLoginAt(Instant.now());
        userRepository.save(user);

        ClientContext clientContext = ClientContextUtil.extract(request);
        AuthResponse authResponse = tokenService.issueTokens(userDetails, ClientContext.ofNullable(clientContext));

        ResponseCookie refreshCookie = authCookieHelper.createRefreshTokenCookie(authResponse.refreshToken(), request);
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        ApiResponse<AuthResponse> apiResponse = ApiResponse.success("Authentication successful", authResponse);
        objectMapper.writeValue(response.getWriter(), apiResponse);

        log.info("User '{}' successfully authenticated via Passkey", username);
    }
}
