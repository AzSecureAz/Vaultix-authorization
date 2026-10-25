package com.vaultix.authorization.service.impl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.AuthMessagingProperties;
import com.vaultix.authorization.dto.mfa.SmsMfaActivationResponse;
import com.vaultix.authorization.dto.mfa.VerifySmsMfaRequest;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.UserRecoveryCode;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.UserRecoveryCodeRepository;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.service.OtpService;
import com.vaultix.authorization.service.SmsMfaService;
import com.vaultix.common.crypto.RecoveryCodeUtil;
import com.vaultix.common.dto.notification.NotificationChannel;
import com.vaultix.common.dto.notification.NotificationEvent;
import com.vaultix.common.exception.BadRequestException;
import com.vaultix.common.exception.ResourceConflictException;
import com.vaultix.common.exception.ResourceNotFoundException;
import com.vaultix.common.util.MaskUtil;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
@RequiredArgsConstructor
public class SmsMfaServiceImpl implements SmsMfaService {

    private static final String REDIS_COOLDOWN_SMS_MFA_SETUP_PREFIX = "auth:cooldown:sms-mfa-setup:";
    private static final String REDIS_COOLDOWN_LOGIN_SMS_MFA_PREFIX = "auth:cooldown:login-sms-mfa:";
    private static final Duration SMS_MFA_COOLDOWN_DURATION = Duration.ofSeconds(60);
    private static final Duration SMS_MFA_OTP_TTL = Duration.ofMinutes(5);

    private final UserRepository userRepository;
    private final UserRecoveryCodeRepository userRecoveryCodeRepository;
    private final OtpService otpService;
    private final StringRedisTemplate stringRedisTemplate;
    private final RabbitTemplate rabbitTemplate;
    private final AuthMessagingProperties messagingProperties;

    @Override
    public void sendSetupOtp(@NotNull(message = "User ID cannot be null") UUID userId) {
        log.info("Processing SMS MFA setup OTP request for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        validateUserActive(user);

        if (user.getPhoneNumber() == null || user.getPhoneNumber().isBlank()) {
            log.warn("SMS MFA setup rejected: No phone number registered for user ID: {}", userId);
            throw new BadRequestException("No phone number registered for this account. Please add a phone number first.");
        }

        if (!user.isPhoneNumberVerified()) {
            log.warn("SMS MFA setup rejected: Phone number not verified for user ID: {}", userId);
            throw new BadRequestException("Phone number is not verified. Please verify your phone number first.");
        }

        if (user.isSmsMfaEnabled()) {
            log.warn("SMS MFA setup rejected: Already enabled for user ID: {}", userId);
            throw new ResourceConflictException("SMS two-factor authentication is already enabled on this account");
        }

        String cooldownKey = REDIS_COOLDOWN_SMS_MFA_SETUP_PREFIX + user.getId();
        Boolean hasCooldown = stringRedisTemplate.hasKey(cooldownKey);
        if (Boolean.TRUE.equals(hasCooldown)) {
            Long remainingTtl = stringRedisTemplate.getExpire(cooldownKey, TimeUnit.SECONDS);
            long waitSeconds = (remainingTtl != null && remainingTtl > 0) ? remainingTtl : SMS_MFA_COOLDOWN_DURATION.toSeconds();
            log.warn("SMS MFA setup rate-limited for user ID: {}. Wait time: {}s", userId, waitSeconds);
            throw new BadRequestException("Please wait " + waitSeconds + " seconds before requesting another verification code");
        }

        String otp = otpService.generateOtp("sms-mfa-setup", user.getId().toString(), SMS_MFA_OTP_TTL);
        stringRedisTemplate.opsForValue().set(cooldownKey, "1", SMS_MFA_COOLDOWN_DURATION);

        log.info("Generated SMS MFA setup OTP for user: {}", user.getUsername());

        NotificationEvent event = NotificationEvent.builder()
                .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                .templateCode("auth.sms-mfa-setup")
                .channel(NotificationChannel.SMS)
                .recipient(user.getPhoneNumber())
                .recipientName(user.getFullName() != null && !user.getFullName().isBlank() ? user.getFullName() : user.getUsername())
                .subject("Vaultix - Two-Factor Authentication Setup Code")
                .params(Map.of(
                        "otp", otp,
                        "expiresInMinutes", SMS_MFA_OTP_TTL.toMinutes()
                ))
                .createdAt(Instant.now())
                .build();

        rabbitTemplate.convertAndSend(
                messagingProperties.exchange(),
                messagingProperties.phoneVerificationRoutingKey(),
                event);

        log.info("Dispatched SMS MFA setup verification OTP to phone '{}' for user: {}",
                MaskUtil.maskPhone(user.getPhoneNumber()), user.getUsername());
    }

    @Override
    @Transactional
    public SmsMfaActivationResponse enableSmsMfa(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @Valid @NotNull(message = "Verification request cannot be null") VerifySmsMfaRequest request) {

        log.info("Attempting to activate SMS MFA for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        validateUserActive(user);

        if (user.getPhoneNumber() == null || user.getPhoneNumber().isBlank()) {
            throw new BadRequestException("No phone number registered for this account. Please add a phone number first.");
        }

        if (!user.isPhoneNumberVerified()) {
            throw new BadRequestException("Phone number is not verified. Please verify your phone number first.");
        }

        if (user.isSmsMfaEnabled()) {
            throw new ResourceConflictException("SMS two-factor authentication is already enabled on this account");
        }

        boolean isValid = otpService.verifyOtp("sms-mfa-setup", user.getId().toString(), request.code().strip());
        if (!isValid) {
            log.warn("Invalid or expired SMS MFA setup OTP supplied for user: {}", user.getUsername());
            throw new BadRequestException("Invalid or expired verification code. Please request a new code and try again.");
        }

        user.setSmsMfaEnabled(true);
        user.setUpdatedBy(userId);
        userRepository.save(user);

        stringRedisTemplate.delete(REDIS_COOLDOWN_SMS_MFA_SETUP_PREFIX + user.getId());

        /* Generate recovery codes if the user does not currently have active recovery codes */
        List<String> recoveryCodes = List.of();
        boolean hasExistingRecoveryCodes = userRecoveryCodeRepository.existsByUserIdAndUsedFalse(userId);
        if (!hasExistingRecoveryCodes) {
            recoveryCodes = RecoveryCodeUtil.generateCodes();
            userRecoveryCodeRepository.deleteByUserId(userId);

            List<UserRecoveryCode> recoveryCodeEntities = recoveryCodes.stream()
                    .map(code -> UserRecoveryCode.builder()
                            .user(user)
                            .codeHash(hashRecoveryCode(code))
                            .used(false)
                            .build())
                    .toList();
            userRecoveryCodeRepository.saveAll(recoveryCodeEntities);
            log.info("Generated {} emergency recovery codes for user ID: {}", recoveryCodes.size(), userId);
        }

        final List<String> finalRecoveryCodes = recoveryCodes;

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
                                    "email", user.getEmail(),
                                    "factor", "SMS"
                            ))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.mfaEnabledRoutingKey(),
                            event);
                    log.info("Dispatched MFA enabled security notification for user: {}", user.getUsername());
                } catch (Exception ex) {
                    log.warn("Failed to dispatch MFA enabled notification for user '{}': {}", user.getUsername(), ex.getMessage());
                }
            }
        });

        log.info("Successfully enabled SMS MFA for user ID: {}", userId);
        return new SmsMfaActivationResponse(finalRecoveryCodes);
    }

    @Override
    @Transactional
    public void disableSmsMfa(@NotNull(message = "User ID cannot be null") UUID userId) {
        log.info("Attempting to disable SMS MFA for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        validateUserActive(user);

        if (!user.isSmsMfaEnabled()) {
            log.warn("SMS MFA disable rejected: Not currently enabled for user ID: {}", userId);
            throw new BadRequestException("SMS two-factor authentication is not currently enabled on this account");
        }

        user.setSmsMfaEnabled(false);
        user.setUpdatedBy(userId);
        userRepository.save(user);

        /* Clean up recovery codes only if no other MFA factor remains active */
        if (!user.isMfaEnabled()) {
            userRecoveryCodeRepository.deleteByUserId(userId);
            log.info("Removed emergency recovery codes for user ID: {} as no active MFA factors remain", userId);
        }

        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    NotificationEvent event = NotificationEvent.builder()
                            .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                            .templateCode("auth.mfa-disabled")
                            .channel(NotificationChannel.EMAIL)
                            .recipient(user.getEmail())
                            .recipientName(user.getFullName() != null && !user.getFullName().isBlank() ? user.getFullName() : user.getUsername())
                            .subject("Vaultix - Security Alert: Two-Factor Authentication Disabled")
                            .params(Map.of(
                                    "username", user.getUsername(),
                                    "email", user.getEmail(),
                                    "factor", "SMS"
                            ))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.mfaDisabledRoutingKey(),
                            event);
                    log.info("Dispatched MFA disabled security notification for user: {}", user.getUsername());
                } catch (Exception ex) {
                    log.warn("Failed to dispatch MFA disabled notification for user '{}': {}", user.getUsername(), ex.getMessage());
                }
            }
        });

        log.info("Successfully disabled SMS MFA for user ID: {}", userId);
    }

    @Override
    public void sendLoginSmsOtp(@NotNull(message = "User ID cannot be null") UUID userId) {
        log.info("Processing login SMS OTP dispatch request for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        validateUserActive(user);

        if (!user.isSmsMfaEnabled()) {
            log.warn("Login SMS OTP rejected: SMS MFA not enabled for user ID: {}", userId);
            throw new BadRequestException("SMS two-factor authentication is not enabled for this account");
        }

        if (user.getPhoneNumber() == null || user.getPhoneNumber().isBlank()) {
            log.warn("Login SMS OTP rejected: No phone number registered for user ID: {}", userId);
            throw new BadRequestException("No registered phone number found for SMS authentication");
        }

        String cooldownKey = REDIS_COOLDOWN_LOGIN_SMS_MFA_PREFIX + user.getId();
        Boolean hasCooldown = stringRedisTemplate.hasKey(cooldownKey);
        if (Boolean.TRUE.equals(hasCooldown)) {
            Long remainingTtl = stringRedisTemplate.getExpire(cooldownKey, TimeUnit.SECONDS);
            long waitSeconds = (remainingTtl != null && remainingTtl > 0) ? remainingTtl : SMS_MFA_COOLDOWN_DURATION.toSeconds();
            log.warn("Login SMS OTP rate-limited for user ID: {}. Wait time: {}s", userId, waitSeconds);
            throw new BadRequestException("Please wait " + waitSeconds + " seconds before requesting another SMS code");
        }

        String otp = otpService.generateOtp("login-sms-mfa", user.getId().toString(), SMS_MFA_OTP_TTL);
        stringRedisTemplate.opsForValue().set(cooldownKey, "1", SMS_MFA_COOLDOWN_DURATION);

        NotificationEvent event = NotificationEvent.builder()
                .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                .templateCode("auth.sms-mfa-login")
                .channel(NotificationChannel.SMS)
                .recipient(user.getPhoneNumber())
                .recipientName(user.getFullName() != null && !user.getFullName().isBlank() ? user.getFullName() : user.getUsername())
                .subject("Vaultix - Login Verification Code")
                .params(Map.of(
                        "otp", otp,
                        "expiresInMinutes", SMS_MFA_OTP_TTL.toMinutes()
                ))
                .createdAt(Instant.now())
                .build();

        rabbitTemplate.convertAndSend(
                messagingProperties.exchange(),
                messagingProperties.phoneVerificationRoutingKey(),
                event);

        log.info("Dispatched login SMS OTP to phone '{}' for user: {}",
                MaskUtil.maskPhone(user.getPhoneNumber()), user.getUsername());
    }

    private void validateUserActive(User user) {
        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("SMS MFA operation rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }
    }

    private String hashRecoveryCode(String rawCode) {
        String normalized = RecoveryCodeUtil.normalizeCode(rawCode);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(normalized.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 message digest algorithm not available", e);
        }
    }
}
