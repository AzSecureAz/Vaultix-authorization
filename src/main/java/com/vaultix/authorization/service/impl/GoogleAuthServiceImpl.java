package com.vaultix.authorization.service.impl;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import org.springframework.amqp.AmqpException;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.AuthMessagingProperties;
import com.vaultix.authorization.config.properties.GoogleProperties;
import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.oauth2.GoogleLoginRequest;
import com.vaultix.authorization.dto.oauth2.SocialAccountResponse;
import com.vaultix.authorization.entity.Role;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.UserSocialAccount;
import com.vaultix.authorization.entity.enums.SocialProvider;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.RoleRepository;
import com.vaultix.authorization.repository.UserRecoveryCodeRepository;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.repository.UserSocialAccountRepository;
import com.vaultix.authorization.security.CustomUserDetails;
import com.vaultix.authorization.service.GoogleAuthService;
import com.vaultix.authorization.service.TokenService;
import com.vaultix.common.dto.notification.NotificationChannel;
import com.vaultix.common.dto.notification.NotificationEvent;
import com.vaultix.common.exception.BadRequestException;
import com.vaultix.common.exception.ResourceConflictException;
import com.vaultix.common.exception.ResourceNotFoundException;
import com.vaultix.common.util.ClientContextUtil.ClientContext;
import com.vaultix.common.util.MaskUtil;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
public class GoogleAuthServiceImpl implements GoogleAuthService {

    private final UserSocialAccountRepository userSocialAccountRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserRecoveryCodeRepository userRecoveryCodeRepository;
    private final TokenService tokenService;
    private final StringRedisTemplate stringRedisTemplate;
    private final RabbitTemplate rabbitTemplate;
    private final AuthMessagingProperties messagingProperties;
    private final GoogleProperties googleProperties;
    private final JwtDecoder googleJwtDecoder;

    public GoogleAuthServiceImpl(
            UserSocialAccountRepository userSocialAccountRepository,
            UserRepository userRepository,
            RoleRepository roleRepository,
            UserRecoveryCodeRepository userRecoveryCodeRepository,
            TokenService tokenService,
            StringRedisTemplate stringRedisTemplate,
            RabbitTemplate rabbitTemplate,
            AuthMessagingProperties messagingProperties,
            GoogleProperties googleProperties,
            @Qualifier("googleIdTokenDecoder") JwtDecoder googleJwtDecoder) {
        this.userSocialAccountRepository = userSocialAccountRepository;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.userRecoveryCodeRepository = userRecoveryCodeRepository;
        this.tokenService = tokenService;
        this.stringRedisTemplate = stringRedisTemplate;
        this.rabbitTemplate = rabbitTemplate;
        this.messagingProperties = messagingProperties;
        this.googleProperties = googleProperties;
        this.googleJwtDecoder = googleJwtDecoder;
    }

    @Override
    @Transactional
    public AuthResponse loginWithGoogle(
            @NotNull(message = "Google login request cannot be null")
            @Valid GoogleLoginRequest request,
            ClientContext clientContext) {

        Jwt jwt = verifyAndDecodeGoogleToken(request.idToken());

        String providerUserId = jwt.getSubject();
        String rawEmail = jwt.getClaimAsString("email");
        String cleanEmail = rawEmail.strip().toLowerCase(Locale.ROOT);
        String displayName = sanitizeDisplayName(jwt.getClaimAsString("name"));
        String avatarUrl = sanitizeAvatarUrl(jwt.getClaimAsString("picture"));

        log.info("Processing Google login for provider user id: '{}', email: '{}'", providerUserId, cleanEmail);

        Optional<UserSocialAccount> existingAccountOpt
                = userSocialAccountRepository.findWithUserByProviderAndProviderUserId(SocialProvider.GOOGLE, providerUserId);

        if (existingAccountOpt.isPresent()) {
            UserSocialAccount socialAccount = existingAccountOpt.get();
            User user = socialAccount.getUser();

            return handleExistingLinkedUser(user, socialAccount, cleanEmail, displayName, avatarUrl, clientContext);
        }

        /* Check if account with this email already exists under password or another provider */
        Optional<User> existingUserWithEmail = userRepository.findByEmail(cleanEmail);
        if (existingUserWithEmail.isPresent()) {
            log.warn("Google login rejected: user with email '{}' exists but Google is not linked.", cleanEmail);
            throw new ResourceConflictException(
                    "An account with this email already exists. Please sign in with your password and link your Google account in Settings.");
        }

        /* Verify reservation cooling-off period */
        String reservedKey = AccountServiceImpl.REDIS_RESERVED_EMAIL_PREFIX + cleanEmail;
        if (Boolean.TRUE.equals(stringRedisTemplate.hasKey(reservedKey))) {
            log.warn("Google registration rejected: email '{}' is in cooling-off period", cleanEmail);
            throw new ResourceConflictException(
                    "Email '" + cleanEmail + "' is currently in a cooling-off reservation period and cannot be registered");
        }

        /* Auto-provision new user */
        return autoProvisionGoogleUser(providerUserId, cleanEmail, displayName, avatarUrl, clientContext);
    }

    @Override
    @Transactional
    public SocialAccountResponse linkGoogle(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Google login request cannot be null")
            @Valid GoogleLoginRequest request) {

        Jwt jwt = verifyAndDecodeGoogleToken(request.idToken());

        String providerUserId = jwt.getSubject();
        String rawEmail = jwt.getClaimAsString("email");
        String cleanEmail = rawEmail != null ? rawEmail.strip().toLowerCase(Locale.ROOT) : null;
        String displayName = sanitizeDisplayName(jwt.getClaimAsString("name"));
        String avatarUrl = sanitizeAvatarUrl(jwt.getClaimAsString("picture"));

        log.info("Processing Google linking request for user ID: '{}', providerUserId: '{}'", userId, providerUserId);

        Optional<UserSocialAccount> existingSocial
                = userSocialAccountRepository.findByProviderAndProviderUserId(SocialProvider.GOOGLE, providerUserId);

        if (existingSocial.isPresent()) {
            if (existingSocial.get().getUser().getId().equals(userId)) {
                throw new ResourceConflictException("This Google account is already linked to your profile.");
            } else {
                throw new ResourceConflictException("This Google account is already linked to another Vaultix user.");
            }
        }

        if (userSocialAccountRepository.findByUserIdAndProvider(userId, SocialProvider.GOOGLE).isPresent()) {
            throw new ResourceConflictException("You have already linked a Google account to your profile.");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        UserSocialAccount socialAccount = UserSocialAccount.builder()
                .user(user)
                .provider(SocialProvider.GOOGLE)
                .providerUserId(providerUserId)
                .email(cleanEmail)
                .displayName(displayName)
                .avatarUrl(avatarUrl)
                .build();

        UserSocialAccount saved = userSocialAccountRepository.save(socialAccount);

        if (!user.isHasSocialAccounts()) {
            user.setHasSocialAccounts(true);
            userRepository.save(user);
        }

        /* If user's primary email matches Google's verified email, mark verified */
        if (cleanEmail != null && cleanEmail.equalsIgnoreCase(user.getEmail()) && !user.isEmailVerified()) {
            user.setEmailVerified(true);
            userRepository.save(user);
            log.info("Verified primary email for user ID: '{}' via linked Google account", userId);
        }

        log.info("Successfully linked Google account (UID: {}) to user ID: {}", providerUserId, userId);
        return SocialAccountResponse.fromEntity(saved);
    }

    private AuthResponse handleExistingLinkedUser(
            User user,
            UserSocialAccount socialAccount,
            String cleanEmail,
            String displayName,
            String avatarUrl,
            ClientContext clientContext) {

        Instant now = Instant.now();

        if (user.getStatus() == UserStatus.LOCKED) {
            if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(now)) {
                log.warn("Google login rejected: account is locked for user ID: {}", user.getId());
                throw new LockedException("Account is temporarily locked. Please try again later.");
            } else {
                user.setStatus(UserStatus.ACTIVE);
                user.setLockedUntil(null);
                user.setFailedLoginAttempts(0);
            }
        } else if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Google login rejected: account disabled/deleted for user ID: {}", user.getId());
            throw new DisabledException("Account is disabled. Please contact support.");
        }

        user.setFailedLoginAttempts(0);
        user.setLastLoginAt(now);
        userRepository.save(user);

        /* Synchronize profile metadata if changed */
        boolean modified = false;
        if (cleanEmail != null && !cleanEmail.equalsIgnoreCase(socialAccount.getEmail())) {
            socialAccount.setEmail(cleanEmail);
            modified = true;
        }
        if (displayName != null && !displayName.equals(socialAccount.getDisplayName())) {
            socialAccount.setDisplayName(displayName);
            modified = true;
        }
        if (avatarUrl != null && !avatarUrl.equals(socialAccount.getAvatarUrl())) {
            socialAccount.setAvatarUrl(avatarUrl);
            modified = true;
        }
        if (modified) {
            userSocialAccountRepository.save(socialAccount);
        }

        /* Enforce MFA if enabled on the user */
        if (user.isMfaEnabled() || user.isSmsMfaEnabled()) {
            log.info("MFA is enabled for user ID: {}. Issuing MFA challenge token for Google login.", user.getId());
            String mfaToken = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
            stringRedisTemplate.opsForValue().set(
                    AuthServiceImpl.REDIS_MFA_CHALLENGE_PREFIX + mfaToken,
                    user.getId().toString(),
                    AuthServiceImpl.MFA_CHALLENGE_TTL);

            boolean hasRecoveryCodes = userRecoveryCodeRepository.existsByUserIdAndUsedFalse(user.getId());
            String maskedPhone = (user.isSmsMfaEnabled() && user.getPhoneNumber() != null)
                    ? MaskUtil.maskPhone(user.getPhoneNumber())
                    : null;

            return AuthResponse.builder()
                    .mfaRequired(true)
                    .mfaToken(mfaToken)
                    .hasRecoveryCodes(hasRecoveryCodes)
                    .totpEnabled(user.isMfaEnabled())
                    .smsMfaEnabled(user.isSmsMfaEnabled())
                    .maskedPhoneNumber(maskedPhone)
                    .build();
        }

        User reloadedUser = userRepository.findWithRolesAndPermissionsById(user.getId()).orElse(user);
        CustomUserDetails userDetails = new CustomUserDetails(reloadedUser);
        return tokenService.issueTokens(userDetails, ClientContext.ofNullable(clientContext));
    }

    private AuthResponse autoProvisionGoogleUser(
            String providerUserId,
            String cleanEmail,
            String displayName,
            String avatarUrl,
            ClientContext clientContext) {

        String username = generateUniqueUsername(cleanEmail);
        Instant now = Instant.now();

        Set<Role> roles = new HashSet<>();
        roleRepository.findByName("ROLE_USER").ifPresent(roles::add);

        User newUser = User.builder()
                .username(username)
                .email(cleanEmail)
                .fullName(displayName)
                .status(UserStatus.ACTIVE)
                .emailVerified(true)
                .phoneNumberVerified(false)
                .mfaEnabled(false)
                .passkeyEnabled(false)
                .smsMfaEnabled(false)
                .hasSocialAccounts(true)
                .failedLoginAttempts(0)
                .lastLoginAt(now)
                .roles(roles)
                .build();

        User savedUser = userRepository.save(newUser);
        log.info("Auto-provisioned new user '{}' ({}) via Google OAuth2 with ID: {}", username, cleanEmail, savedUser.getId());

        UserSocialAccount socialAccount = UserSocialAccount.builder()
                .user(savedUser)
                .provider(SocialProvider.GOOGLE)
                .providerUserId(providerUserId)
                .email(cleanEmail)
                .displayName(displayName)
                .avatarUrl(avatarUrl)
                .build();

        userSocialAccountRepository.save(socialAccount);

        /* Dispatch welcome email notification event */
        dispatchWelcomeNotification(savedUser);

        CustomUserDetails userDetails = new CustomUserDetails(savedUser);
        return tokenService.issueTokens(userDetails, ClientContext.ofNullable(clientContext));
    }

    private void dispatchWelcomeNotification(User savedUser) {
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
                                    "email", savedUser.getEmail()))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.welcomeRoutingKey(),
                            welcomeEvent);
                    log.info("Dispatched welcome notification event for Google user: {}", savedUser.getUsername());
                } catch (AmqpException ex) {
                    log.warn("Failed to dispatch welcome notification event for Google user '{}': {}", savedUser.getEmail(), ex.getMessage());
                }
            }
        });
    }

    private Jwt verifyAndDecodeGoogleToken(String idToken) {
        if (googleProperties.clientId() == null || googleProperties.clientId().isBlank()
                || "YOUR_GOOGLE_CLIENT_ID".equals(googleProperties.clientId())) {
            log.warn("Google OAuth2 client ID is not configured (VAULTIX_GOOGLE_CLIENT_ID)");
            throw new BadRequestException("Google authentication is currently unavailable: client ID is not configured.");
        }

        Jwt jwt;
        try {
            jwt = googleJwtDecoder.decode(idToken);
        } catch (JwtException | IllegalArgumentException ex) {
            log.warn("Failed to decode or verify Google ID token: {}", ex.getMessage());
            throw new BadCredentialsException("Invalid or expired Google ID token");
        }

        /* 1. Verify Issuer */
        String issuer = jwt.getIssuer() != null ? jwt.getIssuer().toString() : "";
        if (!"https://accounts.google.com".equals(issuer) && !"accounts.google.com".equals(issuer)) {
            log.warn("Google ID token issuer mismatch: {}", issuer);
            throw new BadCredentialsException("Invalid Google ID token issuer");
        }

        /* 2. Verify Audience */
        List<String> audience = jwt.getAudience();
        if (audience == null || !audience.contains(googleProperties.clientId())) {
            log.warn("Google ID token audience mismatch. Expected: {}, Present: {}", googleProperties.clientId(), audience);
            throw new BadCredentialsException("Google ID token audience mismatch");
        }

        /* 3. Verify Subject */
        String subject = jwt.getSubject();
        if (subject == null || subject.isBlank()) {
            throw new BadCredentialsException("Google ID token missing subject claim");
        }

        /* 4. Verify Email and verification status */
        String email = jwt.getClaimAsString("email");
        if (email == null || email.isBlank()) {
            throw new BadCredentialsException("Google ID token does not contain an email address");
        }

        Object emailVerifiedClaim = jwt.getClaim("email_verified");
        boolean isVerified = switch (emailVerifiedClaim) {
            case Boolean b ->
                b;
            case String s ->
                Boolean.parseBoolean(s);
            case null, default ->
                false;
        };

        if (!isVerified) {
            log.warn("Google ID token rejected: email '{}' is not verified by Google", email);
            throw new BadCredentialsException("Google account email is not verified");
        }

        return jwt;
    }

    private String generateUniqueUsername(String email) {
        String localPart = email.split("@")[0].replaceAll("[^a-zA-Z0-9_.-]", "").toLowerCase(Locale.ROOT);
        if (localPart.length() < 3) {
            localPart = "user";
        } else if (localPart.length() > 30) {
            localPart = localPart.substring(0, 30);
        }

        if (!userRepository.existsByUsername(localPart)) {
            return localPart;
        }

        for (int i = 0; i < 10; i++) {
            int randomSuffix = ThreadLocalRandom.current().nextInt(1000, 9999);
            String candidate = localPart + "_" + randomSuffix;
            if (!userRepository.existsByUsername(candidate)) {
                return candidate;
            }
        }

        return localPart + "_" + UUID.randomUUID().toString().substring(0, 8);
    }

    private String sanitizeDisplayName(String rawName) {
        if (rawName == null || rawName.isBlank()) {
            return null;
        }
        String stripped = rawName.strip();
        return stripped.length() > 256 ? stripped.substring(0, 256).strip() : stripped;
    }

    private String sanitizeAvatarUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            return null;
        }
        String stripped = rawUrl.strip();
        return stripped.length() > 1024 ? stripped.substring(0, 1024).strip() : stripped;
    }
}
