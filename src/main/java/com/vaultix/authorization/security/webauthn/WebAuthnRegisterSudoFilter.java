package com.vaultix.authorization.security.webauthn;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vaultix.common.dto.ApiResponse;
import com.vaultix.common.security.SecurityUtil;
import com.vaultix.common.security.SudoService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Enforces Sudo Mode elevation for WebAuthn passkey registration endpoints
 * (options generation and credential attestation) handled by Spring Security
 * filters.
 */
@Slf4j
@RequiredArgsConstructor
public class WebAuthnRegisterSudoFilter extends OncePerRequestFilter {

    private final SudoService sudoService;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if (!isRegistrationRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        Jwt jwt = extractJwt(auth);
        if (jwt == null) {
            filterChain.doFilter(request, response);
            return;
        }

        UUID sessionId = SecurityUtil.extractSessionId(jwt);
        if (sessionId == null || !sudoService.isSudoActive(sessionId)) {
            log.warn("Sudo verification required for passkey registration endpoint: {}", request.getRequestURI());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setHeader("X-Sudo-Required", "true");
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("UTF-8");

            ApiResponse<Void> errorResponse = ApiResponse.error(
                    "Sudo mode elevation is required to register a new passkey",
                    Map.of("code", "SUDO_REQUIRED")
            );
            objectMapper.writeValue(response.getOutputStream(), errorResponse);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean isRegistrationRequest(HttpServletRequest request) {
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            return false;
        }
        String servletPath = request.getServletPath();
        if (servletPath != null && servletPath.startsWith("/webauthn/register")) {
            return true;
        }
        String uri = request.getRequestURI();
        return uri != null && uri.contains("/webauthn/register");
    }

    private Jwt extractJwt(Authentication authentication) {
        if (authentication == null) {
            return null;
        }
        if (authentication.getPrincipal() instanceof Jwt principalJwt) {
            return principalJwt;
        }
        if (authentication instanceof JwtAuthenticationToken jwtAuthToken) {
            return jwtAuthToken.getToken();
        }
        return null;
    }
}
