package com.vaultix.authorization.service.impl;

import java.time.Instant;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.AuthMessagingProperties;
import com.vaultix.authorization.config.properties.LockoutProperties;
import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.LoginRequest;
import com.vaultix.authorization.dto.RefreshTokenRequest;
import com.vaultix.authorization.dto.RegisterRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.security.CustomUserDetails;
import com.vaultix.authorization.service.AuthService;
import com.vaultix.authorization.service.TokenService;
import com.vaultix.common.dto.notification.NotificationChannel;
import com.vaultix.common.dto.notification.NotificationEvent;
import com.vaultix.common.exception.ResourceConflictException;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final UserRepository userRepository;
    private final LockoutProperties lockoutProperties;
    private final PasswordEncoder passwordEncoder;
    private final RabbitTemplate rabbitTemplate;
    private final AuthMessagingProperties messagingProperties;
    private final StringRedisTemplate stringRedisTemplate;

    @Override
    @Transactional
    public UserProfileDto register(
            @NotNull(message = "Register request cannot be null")
            @Valid RegisterRequest request) {

        String cleanUsername = request.username().strip().toLowerCase(Locale.ROOT);
        String cleanEmail = request.email().strip().toLowerCase(Locale.ROOT);
        String cleanFullName = (request.fullName() != null && !request.fullName().isBlank())
                ? request.fullName().strip()
                : null;
        String cleanPhoneNumber = (request.phoneNumber() != null && !request.phoneNumber().isBlank())
                ? request.phoneNumber().strip()
                : null;

        log.info("Processing user registration for username: '{}', email: '{}'", cleanUsername, cleanEmail);

        if (userRepository.existsByUsername(cleanUsername)) {
            throw new ResourceConflictException("User already exists with username: " + cleanUsername);
        }

        if (userRepository.existsByEmail(cleanEmail)) {
            throw new ResourceConflictException("User already exists with email: " + cleanEmail);
        }

        String reservedKey = "auth:reserved-email:" + cleanEmail;
        if (Boolean.TRUE.equals(stringRedisTemplate.hasKey(reservedKey))) {
            log.warn("Registration rejected: email '{}' is in a cooling-off reservation period", cleanEmail);
            throw new ResourceConflictException("Email '" + cleanEmail + "' is currently in a cooling-off reservation period and cannot be registered");
        }

        User newUser = User.builder()
                .username(cleanUsername)
                .email(cleanEmail)
                .passwordHash(passwordEncoder.encode(request.password()))
                .fullName(cleanFullName)
                .phoneNumber(cleanPhoneNumber)
                .status(UserStatus.ACTIVE)
                .emailVerified(false)
                .roles(new HashSet<>())
                .build();

        User savedUser = userRepository.save(newUser);
        log.info("User '{}' ({}) registered successfully with ID: {}", cleanUsername, cleanEmail, savedUser.getId());

        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    NotificationEvent welcomeEvent = NotificationEvent.builder()
                            .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                            .templateCode("auth.welcome")
                            .channel(NotificationChannel.EMAIL)
                            .recipient(savedUser.getEmail())
                            .recipientName(savedUser.getFullName() != null && !savedUser.getFullName().isBlank()
                                    ? savedUser.getFullName()
                                    : savedUser.getUsername())
                            .subject("Welcome to Vaultix!")
                            .params(Map.of(
                                    "username", savedUser.getUsername(),
                                    "email", savedUser.getEmail()
                            ))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.welcomeRoutingKey(),
                            welcomeEvent);
                    log.info("Dispatched welcome notification event to exchange '{}' with routing key '{}' for user: {}",
                            messagingProperties.exchange(), messagingProperties.welcomeRoutingKey(), savedUser.getUsername());
                } catch (Exception ex) {
                    log.warn("Failed to dispatch welcome notification event to '{}': {}", cleanEmail, ex.getMessage());
                }
            }
        });

        return UserProfileDto.fromEntity(savedUser);
    }

    @Override
    public AuthResponse login(
            @NotNull(message = "Login request cannot be null")
            @Valid LoginRequest request,
            ClientContext clientContext) {

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

        return tokenService.issueTokens(userDetails, ClientContext.ofNullable(clientContext));
    }

    private void handleFailedLogin(String identifier) {
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
    public AuthResponse refreshToken(
            @NotBlank(message = "Refresh token is required")
            @Size(max = RefreshTokenRequest.MAX_LENGTH, message = "Refresh token cannot exceed " + RefreshTokenRequest.MAX_LENGTH + " characters") String rawRefreshToken,
            ClientContext clientContext) {

        log.info("Processing token refresh request");
        return tokenService.refreshTokens(rawRefreshToken.strip(), ClientContext.ofNullable(clientContext));
    }

    @Override
    public void logout(
            @NotBlank(message = "Access token JTI is required")
            @Size(max = 64, message = "Access token JTI cannot exceed 64 characters") String accessTokenJti) {

        String cleanedJti = accessTokenJti.strip();
        log.info("Processing logout request for accessTokenJti: {}", cleanedJti);
        tokenService.logout(cleanedJti);
    }

    @Override
    @Transactional
    public int logoutAll(@NotNull(message = "User ID cannot be null") UUID userId) {
        log.info("Processing logout all sessions for user ID: {}", userId);
        return tokenService.revokeAllUserTokens(userId);
    }
}
