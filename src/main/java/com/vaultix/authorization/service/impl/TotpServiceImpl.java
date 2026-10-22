package com.vaultix.authorization.service.impl;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.AuthMessagingProperties;
import com.vaultix.authorization.config.properties.KekProperties;
import com.vaultix.authorization.dto.mfa.TotpSetupResponse;
import com.vaultix.authorization.dto.mfa.VerifyTotpRequest;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.UserTotp;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.repository.UserTotpRepository;
import com.vaultix.authorization.service.TotpService;
import com.vaultix.common.crypto.AesGcmCryptoUtil;
import com.vaultix.common.crypto.TotpUtil;
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
public class TotpServiceImpl implements TotpService {

    private static final String TOTP_ISSUER = "Vaultix";

    private final UserRepository userRepository;
    private final UserTotpRepository userTotpRepository;
    private final KekProperties kekProperties;
    private final RabbitTemplate rabbitTemplate;
    private final AuthMessagingProperties messagingProperties;

    @Override
    @Transactional
    public TotpSetupResponse initiateSetup(@NotNull(message = "User ID cannot be null") UUID userId) {
        log.info("Initiating TOTP 2FA setup for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("TOTP setup rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        Optional<UserTotp> existingTotpOpt = userTotpRepository.findByUserId(userId);
        if (existingTotpOpt.isPresent() && existingTotpOpt.get().isVerified()) {
            log.warn("TOTP setup rejected: User ID {} already has an active, verified TOTP authenticator", userId);
            throw new ResourceConflictException("TOTP two-factor authentication is already enabled and verified on this account");
        }

        String base32Secret = TotpUtil.generateSecret();
        String encryptedSecret = AesGcmCryptoUtil.encrypt(base32Secret, kekProperties.masterKey());

        UserTotp totp = existingTotpOpt.orElseGet(() -> UserTotp.builder()
                .user(user)
                .digits(TotpUtil.DEFAULT_DIGITS)
                .period(TotpUtil.DEFAULT_PERIOD_SECONDS)
                .algorithm("SHA1")
                .build());

        totp.setEncryptedSecret(encryptedSecret);
        totp.setVerified(false);
        userTotpRepository.save(totp);

        String otpauthUrl = TotpUtil.generateOtpAuthUri(TOTP_ISSUER, user.getEmail(), base32Secret);

        log.info("Successfully generated unverified TOTP setup for user ID: {}", userId);
        return new TotpSetupResponse(base32Secret, otpauthUrl);
    }

    @Override
    @Transactional
    public void activateTotp(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @Valid @NotNull(message = "Verification request cannot be null") VerifyTotpRequest request) {

        log.info("Attempting to activate TOTP 2FA for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("TOTP activation rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        UserTotp totp = userTotpRepository.findByUserId(userId)
                .orElseThrow(() -> new BadRequestException("No TOTP configuration found. Please initiate TOTP setup first."));

        if (totp.isVerified()) {
            log.warn("TOTP activation rejected: User ID {} already has active verified TOTP", userId);
            throw new ResourceConflictException("TOTP two-factor authentication is already activated on this account");
        }

        String base32Secret = AesGcmCryptoUtil.decrypt(totp.getEncryptedSecret(), kekProperties.masterKey());

        long currentStep = TotpUtil.calculateStep(Instant.now(), totp.getPeriod());
        OptionalLong matchedStepOpt = TotpUtil.verifyCodeAndGetStep(
                base32Secret,
                request.code(),
                currentStep,
                TotpUtil.DEFAULT_WINDOW,
                totp.getDigits(),
                totp.getPeriod(),
                TotpUtil.DEFAULT_HMAC_ALGORITHM);

        if (matchedStepOpt.isEmpty()) {
            log.warn("TOTP activation rejected: Invalid TOTP verification code for user ID: {}", userId);
            throw new BadRequestException("Invalid verification code. Please check your authenticator app and try again.");
        }

        long matchedStep = matchedStepOpt.getAsLong();
        if (totp.getLastUsedStep() != null && matchedStep <= totp.getLastUsedStep()) {
            log.warn("TOTP activation rejected: Code replay detected for user ID: {}", userId);
            throw new BadRequestException("This verification code has already been used. Please wait for a new code.");
        }

        Instant now = Instant.now();
        totp.setVerified(true);
        totp.setLastUsedStep(matchedStep);
        totp.setLastUsedAt(now);
        userTotpRepository.save(totp);

        user.setMfaEnabled(true);
        user.setUpdatedBy(userId);
        userRepository.save(user);

        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    NotificationEvent event = NotificationEvent.builder()
                            .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                            .templateCode("auth.mfa-enabled")
                            .channel(NotificationChannel.EMAIL)
                            .recipient(user.getEmail())
                            .recipientName(user.getFullName() != null && !user.getFullName().isBlank() ? user.getFullName() : user.getUsername())
                            .subject("Vaultix - Security Alert: Two-Factor Authentication Enabled")
                            .params(Map.of(
                                    "username", user.getUsername(),
                                    "email", user.getEmail()
                            ))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.mfaEnabledRoutingKey(),
                            event);
                    log.info("Dispatched MFA enabled notification to exchange '{}' with routing key '{}' for user: {}",
                            messagingProperties.exchange(), messagingProperties.mfaEnabledRoutingKey(), user.getUsername());
                } catch (Exception ex) {
                    log.warn("Failed to dispatch MFA enabled notification for user '{}': {}", user.getUsername(), ex.getMessage());
                }
            }
        });

        log.info("Successfully activated TOTP two-factor authentication for user ID: {}", userId);
    }
}
