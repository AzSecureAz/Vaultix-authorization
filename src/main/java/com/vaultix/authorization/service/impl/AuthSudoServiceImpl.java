package com.vaultix.authorization.service.impl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.ImmutablePublicKeyCredentialRequestOptionsRequest;
import org.springframework.security.web.webauthn.management.RelyingPartyAuthenticationRequest;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.AuthMessagingProperties;
import com.vaultix.authorization.config.properties.KekProperties;
import com.vaultix.authorization.dto.SudoResponse;
import com.vaultix.authorization.dto.SudoVerifyRequest;
import com.vaultix.authorization.dto.oauth2.GitHubLoginRequest;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.UserRecoveryCode;
import com.vaultix.authorization.entity.UserSocialAccount;
import com.vaultix.authorization.entity.UserTotp;
import com.vaultix.authorization.entity.enums.SocialProvider;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.UserPasskeyCredentialRepository;
import com.vaultix.authorization.repository.UserRecoveryCodeRepository;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.repository.UserSocialAccountRepository;
import com.vaultix.authorization.repository.UserTotpRepository;
import com.vaultix.authorization.security.webauthn.JpaPublicKeyCredentialUserEntityRepository;
import com.vaultix.authorization.security.webauthn.RedisPublicKeyCredentialRequestOptionsRepository;
import com.vaultix.authorization.service.AuthSudoService;
import com.vaultix.authorization.service.GitHubAuthService;
import com.vaultix.authorization.service.GoogleAuthService;
import com.vaultix.authorization.service.OtpService;
import com.vaultix.authorization.service.SmsMfaService;
import com.vaultix.common.crypto.AesGcmCryptoUtil;
import com.vaultix.common.crypto.RecoveryCodeUtil;
import com.vaultix.common.crypto.TotpUtil;
import com.vaultix.common.dto.notification.NotificationChannel;
import com.vaultix.common.dto.notification.NotificationEvent;
import com.vaultix.common.exception.BadRequestException;
import com.vaultix.common.exception.ResourceNotFoundException;
import com.vaultix.common.security.SudoService;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
@RequiredArgsConstructor
public class AuthSudoServiceImpl implements AuthSudoService {

    private final UserRepository userRepository;
    private final UserSocialAccountRepository userSocialAccountRepository;
    private final UserTotpRepository userTotpRepository;
    private final UserRecoveryCodeRepository userRecoveryCodeRepository;
    private final PasswordEncoder passwordEncoder;
    private final GoogleAuthService googleAuthService;
    private final GitHubAuthService gitHubAuthService;
    private final SmsMfaService smsMfaService;
    private final OtpService otpService;
    private final SudoService sudoService;
    private final KekProperties kekProperties;
    private final RabbitTemplate rabbitTemplate;
    private final AuthMessagingProperties messagingProperties;
    private final UserPasskeyCredentialRepository passkeyRepository;
    private final WebAuthnRelyingPartyOperations webAuthnRelyingPartyOperations;
    private final RedisPublicKeyCredentialRequestOptionsRepository requestOptionsRepository;

    @Override
    @Transactional
    public SudoResponse verifySudo(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Session ID cannot be null") UUID sessionId,
            @NotNull(message = "Sudo verify request cannot be null") @Valid SudoVerifyRequest request,
            ClientContext clientContext) {

        log.info("Processing sudo verification for user ID: {}, session ID: {}", userId, sessionId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Sudo verification rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        /* 1. Primary Factor Validation: Password OR Google OR GitHub */
        boolean primaryVerified = false;

        String password = request.password();
        String googleIdToken = request.resolvedGoogleIdToken();
        String githubCode = request.resolvedGithubCode();

        if (password != null && !password.isBlank()) {
            if (user.getPasswordHash() == null || user.getPasswordHash().isBlank()) {
                throw new BadRequestException("This account does not have a password configured. Please verify via social login.");
            }
            if (!passwordEncoder.matches(password, user.getPasswordHash())) {
                log.warn("Sudo verification failed: invalid password for user: {}", user.getUsername());
                throw new BadCredentialsException("Invalid password");
            }
            primaryVerified = true;
            log.info("Primary sudo factor verified via password for user: {}", user.getUsername());
        } else if (googleIdToken != null && !googleIdToken.isBlank()) {
            UserSocialAccount linkedGoogle = userSocialAccountRepository
                    .findByUserIdAndProvider(userId, SocialProvider.GOOGLE)
                    .orElseThrow(() -> new BadRequestException("No Google account is linked to your profile"));

            String verifiedGoogleSub = googleAuthService.verifyGoogleIdToken(googleIdToken);
            if (!linkedGoogle.getProviderUserId().equals(verifiedGoogleSub)) {
                log.warn("Sudo verification failed: Google account mismatch for user: {}", user.getUsername());
                throw new BadCredentialsException("Google account does not match the linked account");
            }
            primaryVerified = true;
            log.info("Primary sudo factor verified via Google OAuth for user: {}", user.getUsername());
        } else if (githubCode != null && !githubCode.isBlank()) {
            UserSocialAccount linkedGitHub = userSocialAccountRepository
                    .findByUserIdAndProvider(userId, SocialProvider.GITHUB)
                    .orElseThrow(() -> new BadRequestException("No GitHub account is linked to your profile"));

            GitHubLoginRequest gitHubRequest = new GitHubLoginRequest(githubCode, request.resolvedGithubRedirectUri());
            String verifiedGitHubId = gitHubAuthService.verifyGitHubCode(gitHubRequest);
            if (!linkedGitHub.getProviderUserId().equals(verifiedGitHubId)) {
                log.warn("Sudo verification failed: GitHub account mismatch for user: {}", user.getUsername());
                throw new BadCredentialsException("GitHub account does not match the linked account");
            }
            primaryVerified = true;
            log.info("Primary sudo factor verified via GitHub OAuth for user: {}", user.getUsername());
        }

        if (!primaryVerified) {
            throw new BadRequestException("Primary authentication factor (password or social login) is required");
        }

        /* 2. Secondary MFA Factor (Required if user has TOTP or SMS MFA enabled) */
        boolean hasMfa = user.isMfaEnabled() || user.isSmsMfaEnabled();
        if (hasMfa) {
            boolean secondaryVerified = false;

            String totpCode = request.totpCode();
            String smsCode = request.smsCode();
            String recoveryCode = request.recoveryCode();

            if (totpCode != null && !totpCode.isBlank()) {
                UserTotp totp = userTotpRepository.findByUserId(userId)
                        .orElseThrow(() -> new BadRequestException("TOTP configuration not found for this account"));
                if (!totp.isVerified()) {
                    throw new BadRequestException("TOTP is not verified for this account");
                }

                String base32Secret = AesGcmCryptoUtil.decrypt(totp.getEncryptedSecret(), kekProperties.masterKey());
                long currentStep = TotpUtil.calculateStep(Instant.now(), totp.getPeriod());
                OptionalLong matchedStepOpt = TotpUtil.verifyCodeAndGetStep(
                        base32Secret,
                        totpCode.strip(),
                        currentStep,
                        TotpUtil.DEFAULT_WINDOW,
                        totp.getDigits(),
                        totp.getPeriod(),
                        TotpUtil.DEFAULT_HMAC_ALGORITHM);

                if (matchedStepOpt.isEmpty()) {
                    log.warn("Sudo verification failed: Invalid TOTP code for user: {}", user.getUsername());
                    throw new BadCredentialsException("Invalid or expired TOTP code");
                }
                long matchedStep = matchedStepOpt.getAsLong();
                if (totp.getLastUsedStep() != null && matchedStep <= totp.getLastUsedStep()) {
                    log.warn("Sudo verification failed: TOTP replay detected for user: {}", user.getUsername());
                    throw new BadRequestException("This verification code has already been used. Please wait for a new code.");
                }

                totp.setLastUsedStep(matchedStep);
                totp.setLastUsedAt(Instant.now());
                userTotpRepository.save(totp);
                secondaryVerified = true;
                log.info("Secondary sudo factor verified via TOTP for user: {}", user.getUsername());
            } else if (smsCode != null && !smsCode.isBlank()) {
                if (!user.isSmsMfaEnabled()) {
                    throw new BadRequestException("SMS two-factor authentication is not enabled for this account");
                }

                boolean smsValid = otpService.verifyOtp("login-sms-mfa", userId.toString(), smsCode.strip());
                if (!smsValid) {
                    log.warn("Sudo verification failed: Invalid SMS OTP for user: {}", user.getUsername());
                    throw new BadCredentialsException("Invalid or expired SMS verification code");
                }
                secondaryVerified = true;
                log.info("Secondary sudo factor verified via SMS OTP for user: {}", user.getUsername());
            } else if (recoveryCode != null && !recoveryCode.isBlank()) {
                boolean recoveryValid = verifyAndBurnRecoveryCode(userId, recoveryCode.strip(), user, clientContext);
                if (!recoveryValid) {
                    log.warn("Sudo verification failed: Invalid recovery code for user: {}", user.getUsername());
                    throw new BadCredentialsException("Invalid or already used recovery code");
                }
                secondaryVerified = true;
                log.info("Secondary sudo factor verified via emergency recovery code for user: {}", user.getUsername());
            }

            if (!secondaryVerified) {
                log.warn("Sudo verification rejected: MFA factor missing or unverified for user: {}", user.getUsername());
                throw new BadCredentialsException("Two-factor authentication code is required to elevate to sudo mode");
            }
        }

        /* 3. Elevate session in Redis via SudoService */
        sudoService.elevateSudo(sessionId);
        log.info("Successfully elevated sudo mode for session ID: {}, user: {}", sessionId, user.getUsername());

        long remaining = sudoService.getRemainingSeconds(sessionId).orElse(SudoService.DEFAULT_SUDO_DURATION.toSeconds());
        return SudoResponse.active(remaining);
    }

    @Override
    public SudoResponse getStatus(@NotNull(message = "Session ID cannot be null") UUID sessionId) {
        Optional<Long> remaining = sudoService.getRemainingSeconds(sessionId);
        return remaining.map(SudoResponse::active).orElseGet(SudoResponse::inactive);
    }

    @Override
    public void revokeSudo(@NotNull(message = "Session ID cannot be null") UUID sessionId) {
        sudoService.revokeSudo(sessionId);
    }

    @Override
    public void sendSudoSmsOtp(@NotNull(message = "User ID cannot be null") UUID userId) {
        smsMfaService.sendLoginSmsOtp(userId);
    }

    @Override
    public PublicKeyCredentialRequestOptions generatePasskeySudoOptions(
            @NotNull(message = "User ID cannot be null") UUID userId,
            HttpServletRequest request,
            HttpServletResponse response) {

        log.info("Generating passkey sudo request options for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Passkey sudo options rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        long passkeyCount = passkeyRepository.countByUserId(userId);
        if (passkeyCount == 0) {
            log.warn("Passkey sudo options rejected: no registered passkeys for user: {}", user.getUsername());
            throw new BadRequestException("No passkeys registered for this account. Please verify with password or social login.");
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        ImmutablePublicKeyCredentialRequestOptionsRequest optionsRequest
                = new ImmutablePublicKeyCredentialRequestOptionsRequest(authentication);

        PublicKeyCredentialRequestOptions options
                = webAuthnRelyingPartyOperations.createCredentialRequestOptions(optionsRequest);

        requestOptionsRepository.save(request, response, options);
        log.info("Successfully saved passkey sudo challenge to Redis for user: {}", user.getUsername());

        return options;
    }

    @Override
    @Transactional
    public SudoResponse verifyPasskeySudo(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Session ID cannot be null") UUID sessionId,
            @NotNull(message = "Credential assertion cannot be null") PublicKeyCredential<AuthenticatorAssertionResponse> credential,
            HttpServletRequest request,
            HttpServletResponse response) {

        log.info("Processing passkey sudo verification for user ID: {}, session ID: {}", userId, sessionId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Passkey sudo verification rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        /* 1. Retrieve the single-use request options challenge from Redis */
        PublicKeyCredentialRequestOptions requestOptions = requestOptionsRepository.load(request);
        if (requestOptions == null) {
            log.warn("Passkey sudo verification failed: No active challenge found for user: {}", user.getUsername());
            throw new BadCredentialsException("WebAuthn challenge expired or not found. Please request new options.");
        }

        /* Clear challenge cookie on the response */
        requestOptionsRepository.save(request, response, null);

        /* 2. Authenticate cryptographic assertion via WebAuthnRelyingPartyOperations */
        PublicKeyCredentialUserEntity userEntity;
        try {
            RelyingPartyAuthenticationRequest rpRequest
                    = new RelyingPartyAuthenticationRequest(requestOptions, credential);
            userEntity = webAuthnRelyingPartyOperations.authenticate(rpRequest);
        } catch (Exception ex) {
            log.warn("Passkey assertion verification failed for user '{}': {}", user.getUsername(), ex.getMessage());
            throw new BadCredentialsException("Passkey verification failed: " + ex.getMessage(), ex);
        }

        if (userEntity == null || userEntity.getId() == null) {
            throw new BadCredentialsException("Passkey verification returned no user identity");
        }

        UUID verifiedUserId = JpaPublicKeyCredentialUserEntityRepository.bytesToUuid(userEntity.getId());
        if (verifiedUserId == null || !verifiedUserId.equals(userId)) {
            log.warn("Passkey credential belongs to user ID '{}', expected '{}'", verifiedUserId, userId);
            throw new BadCredentialsException("Passkey credential belongs to a different account");
        }

        /* 4. Elevate session in Redis via SudoService */
        sudoService.elevateSudo(sessionId);
        log.info("Successfully elevated sudo mode via Passkey for session ID: {}, user: {}", sessionId, user.getUsername());

        long remaining = sudoService.getRemainingSeconds(sessionId).orElse(SudoService.DEFAULT_SUDO_DURATION.toSeconds());
        return SudoResponse.active(remaining);
    }

    private boolean verifyAndBurnRecoveryCode(UUID userId, String rawCode, User user, ClientContext clientContext) {
        String codeHash = hashRecoveryCode(rawCode);
        Optional<UserRecoveryCode> recoveryCodeOpt = userRecoveryCodeRepository
                .findByUserIdAndCodeHashAndUsedFalse(userId, codeHash);

        if (recoveryCodeOpt.isEmpty()) {
            return false;
        }

        UserRecoveryCode recoveryCode = recoveryCodeOpt.get();
        recoveryCode.setUsed(true);
        recoveryCode.setUsedAt(Instant.now());
        userRecoveryCodeRepository.save(recoveryCode);

        long remaining = userRecoveryCodeRepository.countByUserIdAndUsedFalse(userId);
        log.warn("Emergency recovery code used for sudo elevation for user ID: {}. Remaining codes: {}", userId, remaining);
        sendRecoveryCodeUsedAlert(user, remaining, clientContext);
        return true;
    }

    private void sendRecoveryCodeUsedAlert(User user, long remainingCodes, ClientContext clientContext) {
        ClientContext context = ClientContext.ofNullable(clientContext);
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("MMM dd, yyyy HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC);
        String formattedUsedAt = formatter.format(Instant.now());

        Runnable dispatchTask = () -> {
            try {
                NotificationEvent event = NotificationEvent.builder()
                        .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                        .templateCode("auth.recovery-code-used")
                        .channel(NotificationChannel.EMAIL)
                        .recipient(user.getEmail())
                        .recipientName(user.getFullName() != null && !user.getFullName().isBlank() ? user.getFullName() : user.getUsername())
                        .subject("Vaultix - Security Alert: Emergency Recovery Code Used")
                        .params(Map.of(
                                "username", user.getUsername(),
                                "email", user.getEmail(),
                                "remainingCodes", String.valueOf(remainingCodes),
                                "usedAt", formattedUsedAt,
                                "ipAddress", context.ip(),
                                "deviceInfo", context.deviceInfo(),
                                "location", context.location()
                        ))
                        .createdAt(Instant.now())
                        .build();

                rabbitTemplate.convertAndSend(
                        messagingProperties.exchange(),
                        messagingProperties.recoveryCodeUsedRoutingKey(),
                        event);
                log.info("Dispatched emergency recovery code used alert to exchange '{}' with routing key '{}' for user: {}",
                        messagingProperties.exchange(), messagingProperties.recoveryCodeUsedRoutingKey(), user.getUsername());
            } catch (Exception ex) {
                log.warn("Failed to dispatch recovery code used notification for user '{}': {}", user.getUsername(), ex.getMessage());
            }
        };

        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    dispatchTask.run();
                }
            });
        } else {
            dispatchTask.run();
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
