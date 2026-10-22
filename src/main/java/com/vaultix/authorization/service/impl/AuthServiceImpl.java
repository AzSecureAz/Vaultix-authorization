package com.vaultix.authorization.service.impl;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.AuthMessagingProperties;
import com.vaultix.authorization.config.properties.LockoutProperties;
import com.vaultix.authorization.config.properties.OtpProperties;
import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.ChangePasswordRequest;
import com.vaultix.authorization.dto.LoginRequest;
import com.vaultix.authorization.dto.PasswordResetConfirmRequest;
import com.vaultix.authorization.dto.PasswordResetRequest;
import com.vaultix.authorization.dto.RefreshTokenRequest;
import com.vaultix.authorization.dto.RegisterRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.dto.VerifyEmailRequest;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.security.CustomUserDetails;
import com.vaultix.authorization.service.AuthService;
import com.vaultix.authorization.service.OtpService;
import com.vaultix.authorization.service.TokenService;
import com.vaultix.common.dto.notification.NotificationChannel;
import com.vaultix.common.dto.notification.NotificationEvent;
import com.vaultix.common.exception.BadRequestException;
import com.vaultix.common.exception.ResourceConflictException;
import com.vaultix.common.exception.ResourceNotFoundException;
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

    private static final String REDIS_COOLDOWN_EMAIL_VERIFICATION_PREFIX = "auth:cooldown:email-verification:";
    private static final Duration EMAIL_VERIFICATION_COOLDOWN_DURATION = Duration.ofSeconds(60);

    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;
    private final UserRepository userRepository;
    private final LockoutProperties lockoutProperties;
    private final PasswordEncoder passwordEncoder;
    private final OtpService otpService;
    private final OtpProperties otpProperties;
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

    @Override
    @Transactional(readOnly = true)
    public UserProfileDto getProfile(@NotNull(message = "User ID cannot be null") UUID userId) {
        log.info("Fetching profile for user ID: {}", userId);
        User user = userRepository.findWithRolesAndPermissionsById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with ID: " + userId));

        return UserProfileDto.fromEntity(user);
    }

    @Override
    public void requestPasswordReset(
            @NotNull(message = "Password reset request cannot be null")
            @Valid PasswordResetRequest request) {

        String identifier = request.identifier().strip().toLowerCase(Locale.ROOT);
        log.info("Processing password reset request for identifier: {}", identifier);

        userRepository.findByUsernameOrEmail(identifier, identifier).ifPresentOrElse(user -> {
            if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
                log.warn("Password reset ignored for {} user: {}", user.getStatus(), user.getUsername());
                return;
            }

            String otp = otpService.generateOtp("password-reset", user.getId().toString());
            log.info("Generated password reset OTP for user: {}", user.getUsername());

            NotificationEvent event = NotificationEvent.builder()
                    .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                    .templateCode("auth.password-reset")
                    .channel(NotificationChannel.EMAIL)
                    .recipient(user.getEmail())
                    .recipientName(user.getFullName() != null && !user.getFullName().isBlank() ? user.getFullName() : user.getUsername())
                    .subject("Vaultix - Password Reset Code")
                    .params(Map.of(
                            "otp", otp,
                            "expiresInMinutes", otpProperties.defaultTtl().toMinutes()
                    ))
                    .createdAt(Instant.now())
                    .build();

            rabbitTemplate.convertAndSend(
                    messagingProperties.exchange(),
                    messagingProperties.passwordResetRoutingKey(),
                    event);
            log.info("Dispatched password reset notification event to exchange '{}' with routing key '{}' for user: {}",
                    messagingProperties.exchange(), messagingProperties.passwordResetRoutingKey(), user.getUsername());
        }, () -> {
            log.warn("Password reset requested for nonexistent identifier: {}", identifier);
        });
    }

    @Override
    @Transactional
    public void confirmPasswordReset(
            @NotNull(message = "Password reset confirmation request cannot be null")
            @Valid PasswordResetConfirmRequest request) {

        String identifier = request.identifier().strip().toLowerCase(Locale.ROOT);
        log.info("Processing password reset confirmation for identifier: {}", identifier);

        User user = userRepository.findByUsernameOrEmail(identifier, identifier)
                .orElseThrow(() -> new BadRequestException("Invalid or expired OTP code"));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Password reset rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is disabled or deleted. Please contact support.");
        }

        boolean isValid = otpService.verifyOtp("password-reset", user.getId().toString(), request.otp().strip());
        if (!isValid) {
            log.warn("Invalid or expired OTP supplied for user: {}", user.getUsername());
            throw new BadRequestException("Invalid or expired OTP code");
        }

        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        user.setFailedLoginAttempts(0);
        if (user.getStatus() == UserStatus.LOCKED) {
            user.setStatus(UserStatus.ACTIVE);
            user.setLockedUntil(null);
        }
        userRepository.save(user);

        int revokedCount = tokenService.revokeAllUserTokens(user.getId());
        log.info("Password successfully reset for user: {}. Revoked {} active sessions.",
                user.getUsername(), revokedCount);
    }

    @Override
    public void sendEmailVerification(@NotNull(message = "User ID cannot be null") UUID userId) {
        log.info("Processing email verification request for user id: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Email verification request rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        if (user.isEmailVerified()) {
            log.info("Email verification requested for already verified user: {}", user.getUsername());
            throw new BadRequestException("Email is already verified");
        }

        String cooldownKey = REDIS_COOLDOWN_EMAIL_VERIFICATION_PREFIX + user.getId();
        Boolean hasCooldown = stringRedisTemplate.hasKey(cooldownKey);
        if (Boolean.TRUE.equals(hasCooldown)) {
            Long remainingTtl = stringRedisTemplate.getExpire(cooldownKey, TimeUnit.SECONDS);
            long waitSeconds = (remainingTtl != null && remainingTtl > 0) ? remainingTtl : EMAIL_VERIFICATION_COOLDOWN_DURATION.toSeconds();
            log.warn("Email verification rate-limited for user: {}. Wait time: {}s", user.getUsername(), waitSeconds);
            throw new BadRequestException("Please wait " + waitSeconds + " seconds before requesting another verification code");
        }

        String otp = otpService.generateOtp("email-verification", user.getId().toString());
        stringRedisTemplate.opsForValue().set(cooldownKey, "1", EMAIL_VERIFICATION_COOLDOWN_DURATION);
        log.info("Generated email verification OTP for user: {}", user.getUsername());

        NotificationEvent event = NotificationEvent.builder()
                .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                .templateCode("auth.email-verification")
                .channel(NotificationChannel.EMAIL)
                .recipient(user.getEmail())
                .recipientName(user.getFullName() != null && !user.getFullName().isBlank() ? user.getFullName() : user.getUsername())
                .subject("Vaultix - Verify Your Email Address")
                .params(Map.of(
                        "otp", otp,
                        "expiresInMinutes", otpProperties.defaultTtl().toMinutes()
                ))
                .createdAt(Instant.now())
                .build();

        rabbitTemplate.convertAndSend(
                messagingProperties.exchange(),
                messagingProperties.emailVerificationRoutingKey(),
                event);
        log.info("Dispatched email verification notification event to exchange '{}' with routing key '{}' for user: {}",
                messagingProperties.exchange(), messagingProperties.emailVerificationRoutingKey(), user.getUsername());
    }

    @Override
    @Transactional
    public void verifyEmail(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Verification request cannot be null")
            @Valid VerifyEmailRequest request) {

        log.info("Processing email verification for user id: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Email verification rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        if (user.isEmailVerified()) {
            log.info("User {} is already verified, returning success", user.getUsername());
            return;
        }

        boolean isValid = otpService.verifyOtp("email-verification", user.getId().toString(), request.otp().strip());
        if (!isValid) {
            log.warn("Invalid or expired email verification OTP supplied for user: {}", user.getUsername());
            throw new BadRequestException("Invalid or expired verification code");
        }

        user.setEmailVerified(true);
        user.setUpdatedBy(userId);
        userRepository.save(user);

        String cooldownKey = REDIS_COOLDOWN_EMAIL_VERIFICATION_PREFIX + user.getId();
        stringRedisTemplate.delete(cooldownKey);

        log.info("Email successfully verified for user: {}", user.getUsername());
    }

    @Override
    @Transactional
    public void changePassword(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Change password request cannot be null")
            @Valid ChangePasswordRequest request) {

        log.info("Processing password change for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Password change rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        if (user.getPasswordHash() == null || user.getPasswordHash().isBlank()) {
            log.warn("Password change attempted on account without password: {}", user.getUsername());
            throw new BadRequestException("No password is set for this account. Please use password reset to establish a password.");
        }

        if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
            log.warn("Password change failed: incorrect current password supplied for user: {}", user.getUsername());
            throw new BadRequestException("Current password is incorrect");
        }

        if (passwordEncoder.matches(request.newPassword(), user.getPasswordHash())) {
            log.warn("Password change failed: new password identical to current password for user: {}", user.getUsername());
            throw new BadRequestException("New password cannot be the same as your current password");
        }

        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        user.setFailedLoginAttempts(0);
        if (user.getStatus() == UserStatus.LOCKED) {
            user.setStatus(UserStatus.ACTIVE);
            user.setLockedUntil(null);
        }
        user.setUpdatedBy(userId);
        userRepository.save(user);

        int revokedCount = tokenService.revokeAllUserTokens(user.getId());
        log.info("Password successfully changed for user: {}. Revoked {} active sessions.",
                user.getUsername(), revokedCount);

        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    NotificationEvent event = NotificationEvent.builder()
                            .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                            .templateCode("auth.password-changed")
                            .channel(NotificationChannel.EMAIL)
                            .recipient(user.getEmail())
                            .recipientName(user.getFullName() != null && !user.getFullName().isBlank() ? user.getFullName() : user.getUsername())
                            .subject("Vaultix - Security Alert: Password Changed")
                            .params(Map.of(
                                    "username", user.getUsername(),
                                    "email", user.getEmail()
                            ))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.passwordChangedRoutingKey(),
                            event);
                    log.info("Dispatched password changed security notification to exchange '{}' with routing key '{}' for user: {}",
                            messagingProperties.exchange(), messagingProperties.passwordChangedRoutingKey(), user.getUsername());
                } catch (Exception ex) {
                    log.warn("Failed to dispatch password changed notification for user '{}': {}", user.getUsername(), ex.getMessage());
                }
            }
        });
    }
}
