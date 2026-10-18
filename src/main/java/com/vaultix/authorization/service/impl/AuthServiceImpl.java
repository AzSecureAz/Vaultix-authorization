package com.vaultix.authorization.service.impl;

import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.vaultix.authorization.config.properties.LockoutProperties;
import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.LoginRequest;
import com.vaultix.authorization.dto.RefreshTokenRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.UserStatus;
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
    private final LockoutProperties lockoutProperties;

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

        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(identifier, request.password())
            );
        } catch (BadCredentialsException e) {
            handleFailedLogin(identifier);
            throw new BadCredentialsException("Invalid identifier or password");
        } catch (LockedException e) {
            log.warn("Login attempt for locked account: {}", identifier);
            throw new LockedException("Account is temporarily locked due to multiple failed login attempts. Please try again later.");
        } catch (DisabledException e) {
            log.warn("Login attempt for disabled account: {}", identifier);
            throw new DisabledException("Account is disabled. Please contact support.");
        }

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        log.info("Authentication successful for user: {}", userDetails.getUsername());

        handleSuccessfulLogin(userDetails.getId());

        return tokenService.issueTokens(userDetails, context);
    }

    private void handleFailedLogin(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            return;
        }

        userRepository.findByUsernameOrEmail(identifier, identifier).ifPresent(user -> {
            Instant now = Instant.now();

            if (user.getStatus() == UserStatus.LOCKED && user.getLockedUntil() != null && user.getLockedUntil().isAfter(now)) {
                return;
            }

            int currentAttempts = user.getFailedLoginAttempts();
            if (user.getStatus() == UserStatus.LOCKED && user.getLockedUntil() != null && user.getLockedUntil().isBefore(now)) {
                currentAttempts = 0;
                user.setStatus(UserStatus.ACTIVE);
                user.setLockedUntil(null);
            }

            int newAttempts = currentAttempts + 1;
            user.setFailedLoginAttempts(newAttempts);

            if (newAttempts >= lockoutProperties.maxFailedAttempts()) {
                user.setStatus(UserStatus.LOCKED);
                user.setLockedUntil(now.plus(lockoutProperties.duration()));
                log.warn("User '{}' (ID: {}) exceeded maximum failed login attempts ({}/{}). Account is LOCKED until {}",
                        user.getUsername(), user.getId(), newAttempts, lockoutProperties.maxFailedAttempts(), user.getLockedUntil());
            } else {
                log.warn("Failed login attempt {}/{} for user '{}' (ID: {})",
                        newAttempts, lockoutProperties.maxFailedAttempts(), user.getUsername(), user.getId());
            }

            userRepository.save(user);
        });
    }

    private void handleSuccessfulLogin(UUID userId) {
        if (userId == null) {
            return;
        }

        userRepository.findById(userId).ifPresent(user -> {
            Instant now = Instant.now();

            if (user.getFailedLoginAttempts() > 0) {
                user.setFailedLoginAttempts(0);
            }
            if (user.getStatus() == UserStatus.LOCKED && user.getLockedUntil() != null && user.getLockedUntil().isBefore(now)) {
                user.setStatus(UserStatus.ACTIVE);
                user.setLockedUntil(null);
            }
            user.setLastLoginAt(now);
            userRepository.save(user);
            log.debug("Updated login metadata for user ID: {}", userId);
        });
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
