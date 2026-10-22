package com.vaultix.authorization.service.impl;

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.AuthMessagingProperties;
import com.vaultix.authorization.config.properties.OtpProperties;
import com.vaultix.authorization.dto.ChangePasswordRequest;
import com.vaultix.authorization.dto.ChangeUsernameRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.dto.VerifyEmailRequest;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.service.AccountService;
import com.vaultix.authorization.service.OtpService;
import com.vaultix.authorization.service.TokenService;
import com.vaultix.common.dto.notification.NotificationChannel;
import com.vaultix.common.dto.notification.NotificationEvent;
import com.vaultix.common.exception.BadRequestException;
import com.vaultix.common.exception.ResourceConflictException;
import com.vaultix.common.exception.ResourceNotFoundException;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
@RequiredArgsConstructor
public class AccountServiceImpl implements AccountService {

    private static final String REDIS_COOLDOWN_EMAIL_VERIFICATION_PREFIX = "auth:cooldown:email-verification:";
    private static final Duration EMAIL_VERIFICATION_COOLDOWN_DURATION = Duration.ofSeconds(60);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final OtpService otpService;
    private final OtpProperties otpProperties;
    private final StringRedisTemplate stringRedisTemplate;
    private final RabbitTemplate rabbitTemplate;
    private final AuthMessagingProperties messagingProperties;

    @Override
    @Transactional(readOnly = true)
    public UserProfileDto getProfile(@NotNull(message = "User ID cannot be null") UUID userId) {
        log.info("Fetching profile for user ID: {}", userId);
        User user = userRepository.findWithRolesAndPermissionsById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with ID: " + userId));

        return UserProfileDto.fromEntity(user);
    }

    @Override
    @Transactional
    public void changeUsername(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Change username request cannot be null")
            @Valid ChangeUsernameRequest request) {

        log.info("Processing username change request for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Username change rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        String cleanNewUsername = request.username().strip().toLowerCase(Locale.ROOT);

        if (cleanNewUsername.equals(user.getUsername().toLowerCase(Locale.ROOT))) {
            log.warn("Username change rejected: identical username supplied by user ID: {}", userId);
            throw new BadRequestException("New username cannot be the same as your current username");
        }

        if (userRepository.existsByUsername(cleanNewUsername)) {
            log.warn("Username change rejected: username '{}' already taken", cleanNewUsername);
            throw new ResourceConflictException("Username '" + cleanNewUsername + "' is already taken");
        }

        String oldUsername = user.getUsername();
        user.setUsername(cleanNewUsername);
        user.setUpdatedBy(userId);
        userRepository.save(user);

        log.info("Username successfully changed from '{}' to '{}' for user ID: {}",
                oldUsername, cleanNewUsername, userId);
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
}
