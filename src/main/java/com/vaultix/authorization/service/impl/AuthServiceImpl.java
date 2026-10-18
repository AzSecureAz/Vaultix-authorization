package com.vaultix.authorization.service.impl;

import java.util.Locale;
import java.util.UUID;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.LoginRequest;
import com.vaultix.authorization.dto.RefreshTokenRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.security.CustomUserDetails;
import com.vaultix.authorization.service.AuthService;
import com.vaultix.authorization.service.TokenService;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final UserRepository userRepository;

    @Override
    public AuthResponse login(LoginRequest request, ClientContext clientContext) {
        if (request == null || request.identifier() == null || request.identifier().isBlank()) {
            throw new BadCredentialsException("Identifier cannot be null or blank");
        }
        if (request.password() == null || request.password().isBlank()) {
            throw new BadCredentialsException("Password cannot be null or blank");
        }

        ClientContext context = ClientContext.ofNullable(clientContext);

        String identifier = request.identifier().strip().toLowerCase(Locale.ROOT);
        log.info("Attempting authentication for identifier: {}", identifier);

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(identifier, request.password())
        );

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        log.info("Authentication successful for user: {}", userDetails.getUsername());

        return tokenService.issueTokens(userDetails, context);
    }

    @Override
    public AuthResponse refreshToken(String rawRefreshToken, ClientContext clientContext) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw new BadCredentialsException("Refresh token is required");
        }

        String token = rawRefreshToken.strip();
        if (token.length() > RefreshTokenRequest.MAX_LENGTH) {
            throw new BadCredentialsException("Refresh token cannot exceed " + RefreshTokenRequest.MAX_LENGTH + " characters");
        }

        log.info("Processing token refresh request");
        return tokenService.refreshTokens(token, ClientContext.ofNullable(clientContext));
    }

    @Override
    public void logout(String accessTokenJti) {
        if (accessTokenJti == null || accessTokenJti.isBlank()) {
            return;
        }

        String cleanedJti = accessTokenJti.strip();
        log.info("Processing logout request for accessTokenJti: {}", cleanedJti);
        tokenService.logout(cleanedJti);
    }

    @Override
    @Transactional(readOnly = true)
    public UserProfileDto getProfile(UUID userId) {
        if (userId == null) {
            throw new BadCredentialsException("User ID cannot be null");
        }

        log.info("Fetching profile for user ID: {}", userId);
        User user = userRepository.findWithRolesAndPermissionsById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with ID: " + userId));

        return UserProfileDto.fromEntity(user);
    }
}
