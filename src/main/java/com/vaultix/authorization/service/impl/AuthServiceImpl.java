package com.vaultix.authorization.service.impl;

import java.util.UUID;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.LoginRequest;
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
        log.info("Attempting authentication for identifier: {}", request.identifier());

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.identifier(), request.password())
        );

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        log.info("Authentication successful for user: {}", userDetails.getUsername());

        return tokenService.issueTokens(userDetails, clientContext);
    }

    @Override
    public AuthResponse refreshToken(String rawRefreshToken, ClientContext clientContext) {
        log.info("Processing token refresh request");
        return tokenService.refreshTokens(rawRefreshToken, clientContext);
    }

    @Override
    public void logout(String accessTokenJti) {
        log.info("Processing logout request for accessTokenJti: {}", accessTokenJti);
        tokenService.logout(accessTokenJti);
    }

    @Override
    @Transactional(readOnly = true)
    public UserProfileDto getProfile(UUID userId) {
        log.info("Fetching profile for user ID: {}", userId);
        User user = userRepository.findWithRolesAndPermissionsById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with ID: " + userId));

        return UserProfileDto.from(user);
    }
}
