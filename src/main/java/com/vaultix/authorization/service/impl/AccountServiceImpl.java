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
import com.vaultix.authorization.config.properties.FrontendProperties;
import com.vaultix.authorization.config.properties.OtpProperties;
import com.vaultix.authorization.dto.ChangePasswordRequest;
import com.vaultix.authorization.dto.ChangeUsernameRequest;
import com.vaultix.authorization.dto.ConfirmEmailChangeRequest;
import com.vaultix.authorization.dto.ConfirmPhoneNumberChangeRequest;
import com.vaultix.authorization.dto.RequestEmailChangeRequest;
import com.vaultix.authorization.dto.RequestPhoneNumberChangeRequest;
import com.vaultix.authorization.dto.RevertEmailRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.dto.VerifyEmailRequest;
import com.vaultix.authorization.dto.VerifyPhoneNumberRequest;
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
import com.vaultix.common.util.MaskUtil;

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
    private static final String REDIS_COOLDOWN_PHONE_VERIFICATION_PREFIX = "auth:cooldown:phone-verification:";
    private static final Duration PHONE_VERIFICATION_COOLDOWN_DURATION = Duration.ofSeconds(60);
    private static final String REDIS_COOLDOWN_EMAIL_CHANGE_PREFIX = "auth:cooldown:email-change:";
    private static final String REDIS_PENDING_EMAIL_CHANGE_PREFIX = "auth:pending:email-change:";
    private static final Duration EMAIL_CHANGE_COOLDOWN_DURATION = Duration.ofSeconds(60);
    private static final String REDIS_COOLDOWN_PHONE_CHANGE_PREFIX = "auth:cooldown:phone-change:";
    private static final String REDIS_PENDING_PHONE_CHANGE_PREFIX = "auth:pending:phone-change:";
    private static final Duration PHONE_CHANGE_COOLDOWN_DURATION = Duration.ofSeconds(60);
    private static final String REDIS_REVERT_EMAIL_PREFIX = "auth:revert-email:";
    public static final String REDIS_RESERVED_EMAIL_PREFIX = "auth:reserved-email:";
    private static final Duration EMAIL_REVERT_WINDOW = Duration.ofDays(7);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final OtpService otpService;
    private final OtpProperties otpProperties;
    private final StringRedisTemplate stringRedisTemplate;
    private final RabbitTemplate rabbitTemplate;
    private final AuthMessagingProperties messagingProperties;
    private final FrontendProperties frontendProperties;

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

        if (user.getPasswordHash() != null && passwordEncoder.matches(request.newPassword(), user.getPasswordHash())) {
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

    @Override
    public void sendPhoneNumberVerification(@NotNull(message = "User ID cannot be null") UUID userId) {
        log.info("Processing phone verification request for user id: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Phone verification request rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        if (user.getPhoneNumber() == null || user.getPhoneNumber().isBlank()) {
            log.warn("Phone verification requested for user without phone number: {}", user.getUsername());
            throw new BadRequestException("No phone number registered for this account");
        }

        if (user.isPhoneNumberVerified()) {
            log.info("Phone verification requested for already verified user: {}", user.getUsername());
            throw new BadRequestException("Phone number is already verified");
        }

        String cooldownKey = REDIS_COOLDOWN_PHONE_VERIFICATION_PREFIX + user.getId();
        Boolean hasCooldown = stringRedisTemplate.hasKey(cooldownKey);
        if (Boolean.TRUE.equals(hasCooldown)) {
            Long remainingTtl = stringRedisTemplate.getExpire(cooldownKey, TimeUnit.SECONDS);
            long waitSeconds = (remainingTtl != null && remainingTtl > 0) ? remainingTtl : PHONE_VERIFICATION_COOLDOWN_DURATION.toSeconds();
            log.warn("Phone verification rate-limited for user: {}. Wait time: {}s", user.getUsername(), waitSeconds);
            throw new BadRequestException("Please wait " + waitSeconds + " seconds before requesting another verification code");
        }

        String otp = otpService.generateOtp("phone-verification", user.getId().toString());
        stringRedisTemplate.opsForValue().set(cooldownKey, "1", PHONE_VERIFICATION_COOLDOWN_DURATION);
        log.info("Generated phone verification OTP for user: {}", user.getUsername());

        NotificationEvent event = NotificationEvent.builder()
                .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                .templateCode("auth.phone-verification")
                .channel(NotificationChannel.SMS)
                .recipient(user.getPhoneNumber())
                .recipientName(user.getFullName() != null && !user.getFullName().isBlank() ? user.getFullName() : user.getUsername())
                .subject("Vaultix - Phone Verification Code")
                .params(Map.of(
                        "otp", otp,
                        "expiresInMinutes", otpProperties.defaultTtl().toMinutes()
                ))
                .createdAt(Instant.now())
                .build();

        rabbitTemplate.convertAndSend(
                messagingProperties.exchange(),
                messagingProperties.phoneVerificationRoutingKey(),
                event);
        log.info("Dispatched phone verification notification event to exchange '{}' with routing key '{}' for user: {}",
                messagingProperties.exchange(), messagingProperties.phoneVerificationRoutingKey(), user.getUsername());
    }

    @Override
    @Transactional
    public void verifyPhoneNumber(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Verification request cannot be null")
            @Valid VerifyPhoneNumberRequest request) {

        log.info("Processing phone verification for user id: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Phone verification rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        if (user.getPhoneNumber() == null || user.getPhoneNumber().isBlank()) {
            log.warn("Phone verification attempted for user without phone number: {}", user.getUsername());
            throw new BadRequestException("No phone number registered for this account");
        }

        if (user.isPhoneNumberVerified()) {
            log.info("User {} phone number is already verified, returning success", user.getUsername());
            return;
        }

        boolean isValid = otpService.verifyOtp("phone-verification", user.getId().toString(), request.otp().strip());
        if (!isValid) {
            log.warn("Invalid or expired phone verification OTP supplied for user: {}", user.getUsername());
            throw new BadRequestException("Invalid or expired verification code");
        }

        user.setPhoneNumberVerified(true);
        user.setUpdatedBy(userId);
        userRepository.save(user);

        String cooldownKey = REDIS_COOLDOWN_PHONE_VERIFICATION_PREFIX + user.getId();
        stringRedisTemplate.delete(cooldownKey);

        log.info("Phone number successfully verified for user: {}", user.getUsername());
    }

    @Override
    public void requestEmailChange(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Request email change request cannot be null")
            @Valid RequestEmailChangeRequest request) {

        log.info("Processing email change request for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Email change rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        String cleanNewEmail = request.newEmail().strip().toLowerCase(Locale.ROOT);

        if (cleanNewEmail.equals(user.getEmail().toLowerCase(Locale.ROOT))) {
            log.warn("Email change rejected: identical email supplied by user ID: {}", userId);
            throw new BadRequestException("New email cannot be the same as your current email");
        }

        if (userRepository.existsByEmail(cleanNewEmail)) {
            log.warn("Email change rejected: email '{}' already taken", cleanNewEmail);
            throw new ResourceConflictException("Email '" + cleanNewEmail + "' is already registered to another account");
        }

        String reservedKey = REDIS_RESERVED_EMAIL_PREFIX + cleanNewEmail;
        String reservedByUserId = stringRedisTemplate.opsForValue().get(reservedKey);
        if (reservedByUserId != null && !reservedByUserId.equals(user.getId().toString())) {
            log.warn("Email change rejected: email '{}' is in a cooling-off reservation period", cleanNewEmail);
            throw new ResourceConflictException("Email '" + cleanNewEmail + "' is currently in a cooling-off reservation period and cannot be claimed");
        }

        String cooldownKey = REDIS_COOLDOWN_EMAIL_CHANGE_PREFIX + user.getId();
        Boolean hasCooldown = stringRedisTemplate.hasKey(cooldownKey);
        if (Boolean.TRUE.equals(hasCooldown)) {
            Long remainingTtl = stringRedisTemplate.getExpire(cooldownKey, TimeUnit.SECONDS);
            long waitSeconds = (remainingTtl != null && remainingTtl > 0) ? remainingTtl : EMAIL_CHANGE_COOLDOWN_DURATION.toSeconds();
            log.warn("Email change rate-limited for user: {}. Wait time: {}s", user.getUsername(), waitSeconds);
            throw new BadRequestException("Please wait " + waitSeconds + " seconds before requesting another verification code");
        }

        Duration pendingTtl = otpProperties.defaultTtl();
        String pendingEmailKey = REDIS_PENDING_EMAIL_CHANGE_PREFIX + user.getId();
        stringRedisTemplate.opsForValue().set(pendingEmailKey, cleanNewEmail, pendingTtl);

        String otp = otpService.generateOtp("email-change", user.getId().toString(), pendingTtl);
        stringRedisTemplate.opsForValue().set(cooldownKey, "1", EMAIL_CHANGE_COOLDOWN_DURATION);

        log.info("Generated email change verification OTP for user: {} for new email: {}", user.getUsername(), cleanNewEmail);

        NotificationEvent event = NotificationEvent.builder()
                .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                .templateCode("auth.email-verification")
                .channel(NotificationChannel.EMAIL)
                .recipient(cleanNewEmail)
                .recipientName(user.getFullName() != null && !user.getFullName().isBlank() ? user.getFullName() : user.getUsername())
                .subject("Vaultix - Verify Your New Email Address")
                .params(Map.of(
                        "otp", otp,
                        "expiresInMinutes", pendingTtl.toMinutes()
                ))
                .createdAt(Instant.now())
                .build();

        rabbitTemplate.convertAndSend(
                messagingProperties.exchange(),
                messagingProperties.emailVerificationRoutingKey(),
                event);
        log.info("Dispatched email change verification notification to exchange '{}' with routing key '{}' for user: {}",
                messagingProperties.exchange(), messagingProperties.emailVerificationRoutingKey(), user.getUsername());
    }

    @Override
    @Transactional
    public void confirmEmailChange(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Confirm email change request cannot be null")
            @Valid ConfirmEmailChangeRequest request) {

        log.info("Processing email change confirmation for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Email change confirmation rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        String pendingEmailKey = REDIS_PENDING_EMAIL_CHANGE_PREFIX + user.getId();
        String pendingEmail = stringRedisTemplate.opsForValue().get(pendingEmailKey);

        if (pendingEmail == null || pendingEmail.isBlank()) {
            log.warn("Email change confirmation failed: no pending email change found for user: {}", user.getUsername());
            throw new BadRequestException("No pending email change request found or the verification code has expired");
        }

        boolean isValid = otpService.verifyOtp("email-change", user.getId().toString(), request.otp().strip());
        if (!isValid) {
            log.warn("Invalid or expired email change OTP supplied for user: {}", user.getUsername());
            throw new BadRequestException("Invalid or expired verification code");
        }

        String cleanPendingEmail = pendingEmail.strip().toLowerCase(Locale.ROOT);
        if (userRepository.existsByEmail(cleanPendingEmail)) {
            log.warn("Email change confirmation failed: target email '{}' was claimed by another account", cleanPendingEmail);
            stringRedisTemplate.delete(pendingEmailKey);
            otpService.clearOtp("email-change", user.getId().toString());
            throw new ResourceConflictException("Email '" + cleanPendingEmail + "' is already registered to another account");
        }

        String oldEmail = user.getEmail();
        user.setEmail(cleanPendingEmail);
        user.setEmailVerified(true);
        user.setUpdatedBy(userId);
        userRepository.save(user);

        stringRedisTemplate.delete(pendingEmailKey);
        stringRedisTemplate.delete(REDIS_COOLDOWN_EMAIL_CHANGE_PREFIX + user.getId());
        otpService.clearOtp("email-change", user.getId().toString());

        String revertToken = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
        stringRedisTemplate.opsForValue().set(REDIS_REVERT_EMAIL_PREFIX + revertToken, user.getId().toString() + ":" + oldEmail, EMAIL_REVERT_WINDOW);
        stringRedisTemplate.opsForValue().set(REDIS_RESERVED_EMAIL_PREFIX + oldEmail, user.getId().toString(), EMAIL_REVERT_WINDOW);

        log.info("Email successfully changed from '{}' to '{}' for user: {}",
                oldEmail, cleanPendingEmail, user.getUsername());

        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    String recipientName = user.getFullName() != null && !user.getFullName().isBlank()
                            ? user.getFullName()
                            : user.getUsername();

                    String revertUrl = buildFrontendUrl("/email-revert?token=" + revertToken);

                    NotificationEvent oldEmailAlert = NotificationEvent.builder()
                            .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                            .templateCode("auth.email-changed")
                            .channel(NotificationChannel.EMAIL)
                            .recipient(oldEmail)
                            .recipientName(recipientName)
                            .subject("Vaultix - Security Alert: Email Address Changed")
                            .params(Map.of(
                                    "username", user.getUsername(),
                                    "oldEmail", oldEmail,
                                    "newEmail", cleanPendingEmail,
                                    "revertToken", revertToken,
                                    "revertUrl", revertUrl
                            ))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.emailChangedRoutingKey(),
                            oldEmailAlert);
                    log.info("Dispatched email changed security alert with revert link to old email '{}' for user: {}", oldEmail, user.getUsername());

                    NotificationEvent newEmailConfirmation = NotificationEvent.builder()
                            .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                            .templateCode("auth.email-changed")
                            .channel(NotificationChannel.EMAIL)
                            .recipient(cleanPendingEmail)
                            .recipientName(recipientName)
                            .subject("Vaultix - Your Email Address Has Been Updated")
                            .params(Map.of(
                                    "username", user.getUsername(),
                                    "oldEmail", oldEmail,
                                    "newEmail", cleanPendingEmail
                            ))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.emailChangedRoutingKey(),
                            newEmailConfirmation);
                    log.info("Dispatched email changed confirmation to new email '{}' for user: {}", cleanPendingEmail, user.getUsername());
                } catch (Exception ex) {
                    log.warn("Failed to dispatch email changed notifications for user '{}': {}", user.getUsername(), ex.getMessage());
                }
            }
        });
    }

    @Override
    public void requestPhoneNumberChange(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Request phone number change request cannot be null")
            @Valid RequestPhoneNumberChangeRequest request) {

        log.info("Processing phone number change request for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Phone number change rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        String cleanNewPhone = request.newPhoneNumber().strip();

        if (cleanNewPhone.equals(user.getPhoneNumber())) {
            log.warn("Phone number change rejected: identical phone number supplied by user ID: {}", userId);
            throw new BadRequestException("New phone number cannot be the same as your current phone number");
        }

        if (userRepository.existsByPhoneNumber(cleanNewPhone)) {
            log.warn("Phone number change rejected: phone number '{}' already taken", cleanNewPhone);
            throw new ResourceConflictException("Phone number '" + cleanNewPhone + "' is already registered to another account");
        }

        String cooldownKey = REDIS_COOLDOWN_PHONE_CHANGE_PREFIX + user.getId();
        Boolean hasCooldown = stringRedisTemplate.hasKey(cooldownKey);
        if (Boolean.TRUE.equals(hasCooldown)) {
            Long remainingTtl = stringRedisTemplate.getExpire(cooldownKey, TimeUnit.SECONDS);
            long waitSeconds = (remainingTtl != null && remainingTtl > 0) ? remainingTtl : PHONE_CHANGE_COOLDOWN_DURATION.toSeconds();
            log.warn("Phone number change rate-limited for user: {}. Wait time: {}s", user.getUsername(), waitSeconds);
            throw new BadRequestException("Please wait " + waitSeconds + " seconds before requesting another verification code");
        }

        Duration pendingTtl = otpProperties.defaultTtl();
        String pendingPhoneKey = REDIS_PENDING_PHONE_CHANGE_PREFIX + user.getId();
        stringRedisTemplate.opsForValue().set(pendingPhoneKey, cleanNewPhone, pendingTtl);

        String otp = otpService.generateOtp("phone-change", user.getId().toString(), pendingTtl);
        stringRedisTemplate.opsForValue().set(cooldownKey, "1", PHONE_CHANGE_COOLDOWN_DURATION);

        log.info("Generated phone change verification OTP for user: {} for new phone number: {}", user.getUsername(), cleanNewPhone);

        NotificationEvent event = NotificationEvent.builder()
                .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                .templateCode("auth.phone-verification")
                .channel(NotificationChannel.SMS)
                .recipient(cleanNewPhone)
                .recipientName(user.getFullName() != null && !user.getFullName().isBlank() ? user.getFullName() : user.getUsername())
                .subject("Vaultix - Verify Your New Phone Number")
                .params(Map.of(
                        "otp", otp,
                        "expiresInMinutes", pendingTtl.toMinutes()
                ))
                .createdAt(Instant.now())
                .build();

        rabbitTemplate.convertAndSend(
                messagingProperties.exchange(),
                messagingProperties.phoneVerificationRoutingKey(),
                event);
        log.info("Dispatched phone number change verification notification to exchange '{}' with routing key '{}' for user: {}",
                messagingProperties.exchange(), messagingProperties.phoneVerificationRoutingKey(), user.getUsername());
    }

    @Override
    @Transactional
    public void confirmPhoneNumberChange(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Confirm phone number change request cannot be null")
            @Valid ConfirmPhoneNumberChangeRequest request) {

        log.info("Processing phone number change confirmation for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Phone number change confirmation rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        String pendingPhoneKey = REDIS_PENDING_PHONE_CHANGE_PREFIX + user.getId();
        String pendingPhone = stringRedisTemplate.opsForValue().get(pendingPhoneKey);

        if (pendingPhone == null || pendingPhone.isBlank()) {
            log.warn("Phone number change confirmation failed: no pending phone number change found for user: {}", user.getUsername());
            throw new BadRequestException("No pending phone number change request found or the verification code has expired");
        }

        boolean isValid = otpService.verifyOtp("phone-change", user.getId().toString(), request.otp().strip());
        if (!isValid) {
            log.warn("Invalid or expired phone change OTP supplied for user: {}", user.getUsername());
            throw new BadRequestException("Invalid or expired verification code");
        }

        String cleanPendingPhone = pendingPhone.strip();
        if (userRepository.existsByPhoneNumber(cleanPendingPhone)) {
            log.warn("Phone number change confirmation failed: target phone number '{}' was claimed by another account", cleanPendingPhone);
            stringRedisTemplate.delete(pendingPhoneKey);
            otpService.clearOtp("phone-change", user.getId().toString());
            throw new ResourceConflictException("Phone number '" + cleanPendingPhone + "' is already registered to another account");
        }

        String oldPhone = user.getPhoneNumber();
        user.setPhoneNumber(cleanPendingPhone);
        user.setPhoneNumberVerified(true);
        user.setUpdatedBy(userId);
        userRepository.save(user);

        stringRedisTemplate.delete(pendingPhoneKey);
        stringRedisTemplate.delete(REDIS_COOLDOWN_PHONE_CHANGE_PREFIX + user.getId());
        otpService.clearOtp("phone-change", user.getId().toString());

        log.info("Phone number successfully changed from '{}' to '{}' for user: {}",
                oldPhone, cleanPendingPhone, user.getUsername());

        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    String recipientName = user.getFullName() != null && !user.getFullName().isBlank()
                            ? user.getFullName()
                            : user.getUsername();

                    if (oldPhone != null && !oldPhone.isBlank()) {
                        NotificationEvent oldPhoneAlert = NotificationEvent.builder()
                                .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                                .templateCode("auth.phone-changed")
                                .channel(NotificationChannel.SMS)
                                .recipient(oldPhone)
                                .recipientName(recipientName)
                                .subject("Vaultix - Security Alert: Phone Number Changed")
                                .params(Map.of(
                                        "username", user.getUsername(),
                                        "oldPhoneNumber", oldPhone,
                                        "newPhoneNumber", cleanPendingPhone
                                ))
                                .createdAt(Instant.now())
                                .build();

                        rabbitTemplate.convertAndSend(
                                messagingProperties.exchange(),
                                messagingProperties.phoneChangedRoutingKey(),
                                oldPhoneAlert);
                        log.info("Dispatched phone changed security alert to old phone number '{}' for user: {}", oldPhone, user.getUsername());
                    }

                    NotificationEvent newPhoneConfirmation = NotificationEvent.builder()
                            .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                            .templateCode("auth.phone-changed")
                            .channel(NotificationChannel.SMS)
                            .recipient(cleanPendingPhone)
                            .recipientName(recipientName)
                            .subject("Vaultix - Phone Number Successfully Updated")
                            .params(Map.of(
                                    "username", user.getUsername(),
                                    "newPhoneNumber", cleanPendingPhone
                            ))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.phoneChangedRoutingKey(),
                            newPhoneConfirmation);
                    log.info("Dispatched phone changed confirmation notification to new phone number '{}' for user: {}", cleanPendingPhone, user.getUsername());

                    /* Dispatch security alert email to user's primary email address */
                    NotificationEvent emailAlert = NotificationEvent.builder()
                            .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                            .templateCode("auth.phone-changed")
                            .channel(NotificationChannel.EMAIL)
                            .recipient(user.getEmail())
                            .recipientName(recipientName)
                            .subject("Vaultix - Security Alert: Phone Number Changed")
                            .params(Map.of(
                                    "username", user.getUsername(),
                                    "email", user.getEmail(),
                                    "oldPhoneNumber", (oldPhone != null && !oldPhone.isBlank()) ? MaskUtil.maskPhone(oldPhone) : "None",
                                    "newPhoneNumber", MaskUtil.maskPhone(cleanPendingPhone)
                            ))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.phoneChangedRoutingKey(),
                            emailAlert);
                    log.info("Dispatched phone changed security alert email to '{}' for user: {}", user.getEmail(), user.getUsername());
                } catch (Exception ex) {
                    log.warn("Failed to dispatch phone changed notification events for user '{}': {}", user.getUsername(), ex.getMessage());
                }
            }
        });
    }

    @Override
    @Transactional
    public void revertEmail(@NotNull(message = "Revert email request cannot be null") @Valid RevertEmailRequest request) {
        String token = request.token().strip();
        log.info("Processing email revert request");

        String revertKey = REDIS_REVERT_EMAIL_PREFIX + token;
        String payload = stringRedisTemplate.opsForValue().get(revertKey);
        if (payload == null || !payload.contains(":")) {
            log.warn("Email revert failed: invalid or expired token");
            throw new BadRequestException("Invalid or expired email revert link. The link may have expired or already been used.");
        }

        String[] parts = payload.split(":", 2);
        UUID targetUserId = UUID.fromString(parts[0]);
        String oldEmail = parts[1].strip().toLowerCase(Locale.ROOT);

        User user = userRepository.findById(targetUserId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found for revert request"));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Email revert rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is disabled or deleted. Please contact support.");
        }

        userRepository.findByEmail(oldEmail).ifPresent(existingUser -> {
            if (!existingUser.getId().equals(user.getId())) {
                log.error("Email revert conflict: target email '{}' is claimed by user ID: {}", oldEmail, existingUser.getId());
                throw new ResourceConflictException("Target email '" + oldEmail + "' is currently claimed by another account. Please contact support.");
            }
        });

        String currentEmail = user.getEmail();
        user.setEmail(oldEmail);
        user.setEmailVerified(true);
        user.setPasswordHash(null);
        user.setUpdatedBy(targetUserId);
        userRepository.save(user);

        stringRedisTemplate.delete(revertKey);
        stringRedisTemplate.delete(REDIS_RESERVED_EMAIL_PREFIX + oldEmail);

        int revokedCount = tokenService.revokeAllUserTokens(user.getId());
        log.info("Email successfully reverted from '{}' back to '{}' for user: {}. Cleared password hash and revoked {} active sessions.",
                currentEmail, oldEmail, user.getUsername(), revokedCount);

        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    String recipientName = user.getFullName() != null && !user.getFullName().isBlank()
                            ? user.getFullName()
                            : user.getUsername();

                    String passwordResetUrl = buildFrontendUrl("/forgot-password");

                    NotificationEvent restoredEmailAlert = NotificationEvent.builder()
                            .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                            .templateCode("auth.email-reverted")
                            .channel(NotificationChannel.EMAIL)
                            .recipient(oldEmail)
                            .recipientName(recipientName)
                            .subject("Vaultix - Security Alert: Your Email Address Has Been Restored")
                            .params(Map.of(
                                    "username", user.getUsername(),
                                    "restoredEmail", oldEmail,
                                    "passwordResetUrl", passwordResetUrl
                            ))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.emailRevertedRoutingKey(),
                            restoredEmailAlert);
                    log.info("Dispatched email reverted alert to restored email '{}' for user: {}", oldEmail, user.getUsername());

                    NotificationEvent removedEmailNotice = NotificationEvent.builder()
                            .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                            .templateCode("auth.email-revert-notice")
                            .channel(NotificationChannel.EMAIL)
                            .recipient(currentEmail)
                            .recipientName(recipientName)
                            .subject("Vaultix - Notice: Email Association Removed")
                            .params(Map.of(
                                    "username", user.getUsername(),
                                    "removedEmail", currentEmail
                            ))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.emailRevertedRoutingKey(),
                            removedEmailNotice);
                    log.info("Dispatched email revert notice to removed email '{}' for user: {}", currentEmail, user.getUsername());
                } catch (Exception ex) {
                    log.warn("Failed to dispatch email reverted notifications for user '{}': {}", user.getUsername(), ex.getMessage());
                }
            }
        });
    }

    private String buildFrontendUrl(String path) {
        String base = frontendProperties.baseUrl().replaceAll("/+$", "");
        String cleanPath = path.startsWith("/") ? path : "/" + path;
        return base + cleanPath;
    }
}
