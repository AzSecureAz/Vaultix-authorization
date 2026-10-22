package com.vaultix.authorization.service.impl;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.AuthMessagingProperties;
import com.vaultix.authorization.config.properties.OtpProperties;
import com.vaultix.authorization.dto.PasswordResetConfirmRequest;
import com.vaultix.authorization.dto.PasswordResetRequest;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.service.OtpService;
import com.vaultix.authorization.service.PasswordResetService;
import com.vaultix.authorization.service.TokenService;
import com.vaultix.common.dto.notification.NotificationChannel;
import com.vaultix.common.dto.notification.NotificationEvent;
import com.vaultix.common.exception.BadRequestException;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
@RequiredArgsConstructor
public class PasswordResetServiceImpl implements PasswordResetService {

    private final UserRepository userRepository;
    private final OtpService otpService;
    private final OtpProperties otpProperties;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final RabbitTemplate rabbitTemplate;
    private final AuthMessagingProperties messagingProperties;

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
}
