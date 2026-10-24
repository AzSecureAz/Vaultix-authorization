package com.vaultix.authorization.security.webauthn;

import java.io.IOException;
import java.time.Instant;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.security.AuthCookieHelper;
import com.vaultix.authorization.security.CustomUserDetails;
import com.vaultix.authorization.security.CustomUserDetailsService;
import com.vaultix.authorization.service.TokenService;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.exception.BadRequestException;
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

        userRepository.findById(userDetails.getId()).ifPresent(user -> {
            if (user.getStatus() != UserStatus.ACTIVE) {
                log.warn("Passkey login rejected for non-active user '{}' (status: {})", user.getUsername(), user.getStatus());
                throw new BadRequestException("Account is not active. Status: " + user.getStatus());
            }

            user.setFailedLoginAttempts(0);
            user.setLockedUntil(null);
            user.setLastLoginAt(Instant.now());
            userRepository.save(user);
        });

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
