package com.vaultix.authorization.service.impl;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.LoginRequest;
import com.vaultix.authorization.security.CustomUserDetails;
import com.vaultix.authorization.service.AuthService;
import com.vaultix.authorization.service.TokenService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    @Override
    public AuthResponse login(LoginRequest request, String deviceInfo, String ipAddress) {
        log.info("Attempting authentication for identifier: {}", request.identifier());

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.identifier(), request.password())
        );

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        log.info("Authentication successful for user: {}", userDetails.getUsername());

        return tokenService.issueTokens(userDetails, deviceInfo, ipAddress);
    }

    @Override
    public AuthResponse refreshToken(String rawRefreshToken, String deviceInfo, String ipAddress) {
        log.info("Processing token refresh request");
        return tokenService.refreshTokens(rawRefreshToken, deviceInfo, ipAddress);
    }
}
