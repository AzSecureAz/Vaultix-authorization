package com.vaultix.authorization.service.impl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.AuthMessagingProperties;
import com.vaultix.authorization.config.properties.KekProperties;
import com.vaultix.authorization.config.properties.LockoutProperties;
import com.vaultix.authorization.config.properties.OtpProperties;
import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.LoginRequest;
import com.vaultix.authorization.dto.RefreshTokenRequest;
import com.vaultix.authorization.dto.RegisterRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.dto.mfa.MfaLoginRequest;
import com.vaultix.authorization.dto.mfa.SendMfaEmailOtpRequest;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.UserRecoveryCode;
import com.vaultix.authorization.entity.UserTotp;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.UserRecoveryCodeRepository;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.repository.UserTotpRepository;
import com.vaultix.authorization.security.CustomUserDetails;
import com.vaultix.authorization.service.AuthService;
import com.vaultix.authorization.service.OtpService;
import com.vaultix.authorization.service.TokenService;
import com.vaultix.common.crypto.AesGcmCryptoUtil;
import com.vaultix.common.crypto.RecoveryCodeUtil;
import com.vaultix.common.crypto.TotpUtil;
import com.vaultix.common.dto.notification.NotificationChannel;
import com.vaultix.common.dto.notification.NotificationEvent;
import com.vaultix.common.exception.BadRequestException;
import com.vaultix.common.exception.ResourceConflictException;
import com.vaultix.common.exception.ResourceNotFoundException;
import com.vaultix.common.util.ClientContextUtil.ClientContext;
import com.vaultix.common.util.MaskUtil;

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
    private final UserRecoveryCodeRepository userRecoveryCodeRepository;
    private final UserTotpRepository userTotpRepository;
    private final KekProperties kekProperties;
    private final LockoutProperties lockoutProperties;
    private final PasswordEncoder passwordEncoder;
    private final RabbitTemplate rabbitTemplate;
    private final AuthMessagingProperties messagingProperties;
    private final StringRedisTemplate stringRedisTemplate;
    private final OtpService otpService;
    private final OtpProperties otpProperties;

    public static final String REDIS_MFA_CHALLENGE_PREFIX = "auth:mfa:challenge:";
    public static final String REDIS_COOLDOWN_MFA_EMAIL_OTP_PREFIX = "auth:mfa:email:cooldown:";
    public static final Duration MFA_CHALLENGE_TTL = Duration.ofMinutes(5);
    public static final Duration MFA_EMAIL_OTP_COOLDOWN = Duration.ofSeconds(60);

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

        String reservedKey = AccountServiceImpl.REDIS_RESERVED_EMAIL_PREFIX + cleanEmail;
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

        if (userDetails.isMfaEnabled()) {
            log.info("MFA is enabled for user ID: {}. Issuing MFA challenge token.", userDetails.getId());
            String mfaToken = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
            stringRedisTemplate.opsForValue().set(REDIS_MFA_CHALLENGE_PREFIX + mfaToken, userDetails.getId().toString(), MFA_CHALLENGE_TTL);

            boolean hasRecoveryCodes = userRecoveryCodeRepository.existsByUserIdAndUsedFalse(userDetails.getId());
            String maskedEmail = MaskUtil.maskEmail(userDetails.getEmail());

            return AuthResponse.builder()
                    .mfaRequired(true)
                    .mfaToken(mfaToken)
                    .maskedEmail(maskedEmail)
                    .hasRecoveryCodes(hasRecoveryCodes)
                    .build();
        }

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
    public String sendMfaEmailOtp(
            @NotNull(message = "Request cannot be null")
            @Valid SendMfaEmailOtpRequest request) {

        String mfaToken = request.mfaToken().strip();
        String redisKey = REDIS_MFA_CHALLENGE_PREFIX + mfaToken;
        String userIdStr = stringRedisTemplate.opsForValue().get(redisKey);

        if (userIdStr == null || userIdStr.isBlank()) {
            log.warn("MFA email OTP request rejected: Invalid or expired MFA challenge token");
            throw new BadRequestException("Invalid or expired MFA challenge session. Please restart login.");
        }

        UUID userId;
        try {
            userId = UUID.fromString(userIdStr);
        } catch (IllegalArgumentException e) {
            log.error("Corrupt user ID in MFA challenge token Redis key: {}", userIdStr);
            throw new BadRequestException("Invalid MFA challenge session. Please restart login.");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("MFA email OTP request rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        String cooldownKey = REDIS_COOLDOWN_MFA_EMAIL_OTP_PREFIX + userId;
        Boolean hasCooldown = stringRedisTemplate.hasKey(cooldownKey);
        if (Boolean.TRUE.equals(hasCooldown)) {
            Long remainingTtl = stringRedisTemplate.getExpire(cooldownKey, TimeUnit.SECONDS);
            long waitSeconds = (remainingTtl != null && remainingTtl > 0) ? remainingTtl : MFA_EMAIL_OTP_COOLDOWN.toSeconds();
            log.warn("MFA email OTP rate-limited for user ID: {}. Wait time: {}s", userId, waitSeconds);
            throw new BadRequestException("Please wait " + waitSeconds + " seconds before requesting another verification code");
        }

        String otp = otpService.generateOtp("mfa-login", userId.toString(), otpProperties.defaultTtl());
        stringRedisTemplate.opsForValue().set(cooldownKey, "1", MFA_EMAIL_OTP_COOLDOWN);
        log.info("Generated MFA login email OTP for user ID: {}", userId);

        NotificationEvent event = NotificationEvent.builder()
                .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                .templateCode("auth.mfa-login-otp")
                .channel(NotificationChannel.EMAIL)
                .recipient(user.getEmail())
                .recipientName(user.getFullName() != null && !user.getFullName().isBlank() ? user.getFullName() : user.getUsername())
                .subject("Vaultix - Two-Factor Authentication Code")
                .params(Map.of(
                        "otp", otp,
                        "expiresInMinutes", otpProperties.defaultTtl().toMinutes()
                ))
                .createdAt(Instant.now())
                .build();

        rabbitTemplate.convertAndSend(
                messagingProperties.exchange(),
                messagingProperties.mfaLoginOtpRoutingKey(),
                event);
        log.info("Dispatched MFA login email OTP notification event to exchange '{}' with routing key '{}' for user ID: {}",
                messagingProperties.exchange(), messagingProperties.mfaLoginOtpRoutingKey(), userId);

        return "A one-time verification code has been sent to " + MaskUtil.maskEmail(user.getEmail());
    }

    @Override
    @Transactional
    public AuthResponse loginWithMfa(
            @NotNull(message = "MFA login request cannot be null")
            @Valid MfaLoginRequest request,
            ClientContext clientContext) {

        String mfaToken = request.mfaToken().strip();
        String rawCode = request.code().strip();
        String redisKey = REDIS_MFA_CHALLENGE_PREFIX + mfaToken;

        String userIdStr = stringRedisTemplate.opsForValue().get(redisKey);
        if (userIdStr == null || userIdStr.isBlank()) {
            log.warn("MFA login verification rejected: Invalid or expired MFA challenge token");
            throw new BadRequestException("Invalid or expired MFA challenge session. Please restart login.");
        }

        UUID userId;
        try {
            userId = UUID.fromString(userIdStr);
        } catch (IllegalArgumentException e) {
            log.error("Corrupt user ID in MFA challenge token Redis key: {}", userIdStr);
            throw new BadRequestException("Invalid MFA challenge session. Please restart login.");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("MFA login rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        String rawFactor = request.factor();
        String factor = (rawFactor != null && !rawFactor.isBlank())
                ? rawFactor.strip().toLowerCase(Locale.ROOT)
                : null;

        boolean verified = false;

        if (factor != null) {
            switch (factor) {
                case "email" -> {
                    /* Direct Email OTP verification - skips Postgres and AES crypto entirely */
                    boolean emailOtpValid = otpService.verifyOtp("mfa-login", userId.toString(), rawCode);
                    if (!emailOtpValid) {
                        log.warn("MFA login failed: Invalid or expired Email OTP for user ID: {}", userId);
                        throw new BadCredentialsException("Invalid or expired email verification code");
                    }
                    otpService.clearOtp("mfa-login", userId.toString());
                    verified = true;
                    log.info("MFA login verified successfully via direct Email OTP for user ID: {}", userId);
                }
                case "recovery_code", "recovery" -> {
                    /* Direct Emergency Recovery Code verification */
                    String codeHash = hashRecoveryCode(rawCode);
                    Optional<UserRecoveryCode> recoveryCodeOpt = userRecoveryCodeRepository
                            .findByUserIdAndCodeHashAndUsedFalse(userId, codeHash);

                    if (recoveryCodeOpt.isEmpty()) {
                        log.warn("MFA login failed: Invalid or used recovery code for user ID: {}", userId);
                        throw new BadCredentialsException("Invalid or already used recovery code");
                    }

                    UserRecoveryCode recoveryCode = recoveryCodeOpt.get();
                    recoveryCode.setUsed(true);
                    recoveryCode.setUsedAt(Instant.now());
                    userRecoveryCodeRepository.save(recoveryCode);

                    long remaining = userRecoveryCodeRepository.countByUserIdAndUsedFalse(userId);
                    log.warn("Emergency recovery code used for user ID: {}. Remaining codes: {}", userId, remaining);
                    verified = true;
                }
                case "totp" -> {
                    /* Direct TOTP Authenticator verification */
                    UserTotp totp = userTotpRepository.findByUserId(userId)
                            .orElseThrow(() -> new BadRequestException("No TOTP configuration found for this account"));

                    if (!totp.isVerified()) {
                        log.warn("MFA login rejected: TOTP is not active for user ID: {}", userId);
                        throw new BadRequestException("TOTP two-factor authentication is not active for this account");
                    }

                    String base32Secret = AesGcmCryptoUtil.decrypt(totp.getEncryptedSecret(), kekProperties.masterKey());
                    long currentStep = TotpUtil.calculateStep(Instant.now(), totp.getPeriod());
                    OptionalLong matchedStepOpt = TotpUtil.verifyCodeAndGetStep(
                            base32Secret,
                            rawCode,
                            currentStep,
                            TotpUtil.DEFAULT_WINDOW,
                            totp.getDigits(),
                            totp.getPeriod(),
                            TotpUtil.DEFAULT_HMAC_ALGORITHM);

                    if (matchedStepOpt.isEmpty()) {
                        log.warn("MFA login failed: Invalid TOTP verification code for user ID: {}", userId);
                        throw new BadCredentialsException("Invalid authenticator verification code");
                    }

                    long matchedStep = matchedStepOpt.getAsLong();
                    if (totp.getLastUsedStep() != null && matchedStep <= totp.getLastUsedStep()) {
                        log.warn("MFA login rejected: TOTP replay detected for user ID: {}", userId);
                        throw new BadRequestException("This verification code has already been used. Please wait for a new code.");
                    }

                    totp.setLastUsedStep(matchedStep);
                    totp.setLastUsedAt(Instant.now());
                    userTotpRepository.save(totp);
                    verified = true;
                    log.info("MFA login verified successfully via direct TOTP authenticator for user ID: {}", userId);
                }
                default -> {
                    log.warn("MFA login rejected: Unsupported factor '{}' for user ID: {}", factor, userId);
                    throw new BadRequestException("Unsupported MFA factor: '" + factor + "'. Supported factors are 'totp', 'email', or 'recovery_code'.");
                }
            }
        } else {
            /* Auto-detect factor when factor is not explicitly provided */
            if (rawCode.matches("^\\d{6}$")) {
                /* Try TOTP Authenticator code */
                Optional<UserTotp> totpOpt = userTotpRepository.findByUserId(userId);
                if (totpOpt.isPresent() && totpOpt.get().isVerified()) {
                    UserTotp totp = totpOpt.get();
                    String base32Secret = AesGcmCryptoUtil.decrypt(totp.getEncryptedSecret(), kekProperties.masterKey());
                    long currentStep = TotpUtil.calculateStep(Instant.now(), totp.getPeriod());
                    OptionalLong matchedStepOpt = TotpUtil.verifyCodeAndGetStep(
                            base32Secret,
                            rawCode,
                            currentStep,
                            TotpUtil.DEFAULT_WINDOW,
                            totp.getDigits(),
                            totp.getPeriod(),
                            TotpUtil.DEFAULT_HMAC_ALGORITHM);

                    if (matchedStepOpt.isPresent()) {
                        long matchedStep = matchedStepOpt.getAsLong();
                        if (totp.getLastUsedStep() != null && matchedStep <= totp.getLastUsedStep()) {
                            log.warn("MFA login rejected: TOTP replay detected for user ID: {}", userId);
                            throw new BadRequestException("This verification code has already been used. Please wait for a new code.");
                        }
                        totp.setLastUsedStep(matchedStep);
                        totp.setLastUsedAt(Instant.now());
                        userTotpRepository.save(totp);
                        verified = true;
                        log.info("MFA login verified successfully via auto-detected TOTP for user ID: {}", userId);
                    }
                }

                /* Fall back to Email OTP if TOTP did not match */
                if (!verified) {
                    boolean emailOtpValid = otpService.verifyOtp("mfa-login", userId.toString(), rawCode);
                    if (emailOtpValid) {
                        otpService.clearOtp("mfa-login", userId.toString());
                        verified = true;
                        log.info("MFA login verified successfully via auto-detected Email OTP for user ID: {}", userId);
                    }
                }
            } else {
                /* Try Emergency Recovery Code */
                String codeHash = hashRecoveryCode(rawCode);
                Optional<UserRecoveryCode> recoveryCodeOpt = userRecoveryCodeRepository
                        .findByUserIdAndCodeHashAndUsedFalse(userId, codeHash);

                if (recoveryCodeOpt.isPresent()) {
                    UserRecoveryCode recoveryCode = recoveryCodeOpt.get();
                    recoveryCode.setUsed(true);
                    recoveryCode.setUsedAt(Instant.now());
                    userRecoveryCodeRepository.save(recoveryCode);

                    long remaining = userRecoveryCodeRepository.countByUserIdAndUsedFalse(userId);
                    log.warn("Emergency recovery code used for user ID: {}. Remaining codes: {}", userId, remaining);
                    verified = true;
                }
            }
        }

        if (!verified) {
            log.warn("MFA login failed: Invalid verification code for user ID: {}", userId);
            throw new BadCredentialsException("Invalid verification code");
        }

        stringRedisTemplate.delete(redisKey);
        handleSuccessfulLogin(userId);

        CustomUserDetails userDetails = new CustomUserDetails(user);
        return tokenService.issueTokens(userDetails, ClientContext.ofNullable(clientContext));
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
