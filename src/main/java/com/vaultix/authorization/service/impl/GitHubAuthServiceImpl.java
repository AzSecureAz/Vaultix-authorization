package com.vaultix.authorization.service.impl;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.vaultix.authorization.config.properties.AuthMessagingProperties;
import com.vaultix.authorization.config.properties.GitHubProperties;
import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.oauth2.GitHubLoginRequest;
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
import com.vaultix.authorization.service.GitHubAuthService;
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
public class GitHubAuthServiceImpl implements GitHubAuthService {

    private static final String GITHUB_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token";
    private static final String GITHUB_USER_API_URL = "https://api.github.com/user";
    private static final String GITHUB_EMAILS_API_URL = "https://api.github.com/user/emails";

    private final UserSocialAccountRepository userSocialAccountRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserRecoveryCodeRepository userRecoveryCodeRepository;
    private final TokenService tokenService;
    private final StringRedisTemplate stringRedisTemplate;
    private final RabbitTemplate rabbitTemplate;
    private final AuthMessagingProperties messagingProperties;
    private final GitHubProperties gitHubProperties;
    private final RestClient restClient;

    public GitHubAuthServiceImpl(
            UserSocialAccountRepository userSocialAccountRepository,
            UserRepository userRepository,
            RoleRepository roleRepository,
            UserRecoveryCodeRepository userRecoveryCodeRepository,
            TokenService tokenService,
            StringRedisTemplate stringRedisTemplate,
            RabbitTemplate rabbitTemplate,
            AuthMessagingProperties messagingProperties,
            GitHubProperties gitHubProperties) {

        this.userSocialAccountRepository = userSocialAccountRepository;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.userRecoveryCodeRepository = userRecoveryCodeRepository;
        this.tokenService = tokenService;
        this.stringRedisTemplate = stringRedisTemplate;
        this.rabbitTemplate = rabbitTemplate;
        this.messagingProperties = messagingProperties;
        this.gitHubProperties = gitHubProperties;

        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(Duration.ofSeconds(5));
        requestFactory.setReadTimeout(Duration.ofSeconds(10));

        this.restClient = RestClient.builder()
                .requestFactory(requestFactory)
                .defaultHeader(HttpHeaders.USER_AGENT, "Vaultix-Identity-Platform")
                .build();
    }

    @Override
    @Transactional
    public AuthResponse loginWithGitHub(
            @NotNull(message = "GitHub login request cannot be null")
            @Valid GitHubLoginRequest request,
            ClientContext clientContext) {

        GitHubIdentity identity = fetchGitHubIdentity(request);

        String providerUserId = identity.providerUserId();
        String cleanEmail = identity.email();
        String displayName = sanitizeDisplayName(identity.displayName());
        String avatarUrl = sanitizeAvatarUrl(identity.avatarUrl());

        log.info("Processing GitHub login for provider user id: '{}', email: '{}'", providerUserId, cleanEmail);

        Optional<UserSocialAccount> existingAccountOpt
                = userSocialAccountRepository.findWithUserByProviderAndProviderUserId(SocialProvider.GITHUB, providerUserId);

        if (existingAccountOpt.isPresent()) {
            UserSocialAccount socialAccount = existingAccountOpt.get();
            User user = socialAccount.getUser();

            return handleExistingLinkedUser(user, socialAccount, cleanEmail, displayName, avatarUrl, clientContext);
        }

        /* Check if account with this email already exists under password or another provider */
        Optional<User> existingUserWithEmail = userRepository.findByEmail(cleanEmail);
        if (existingUserWithEmail.isPresent()) {
            log.warn("GitHub login rejected: user with email '{}' exists but GitHub is not linked.", cleanEmail);
            throw new ResourceConflictException(
                    "An account with this email already exists. Please sign in with your password and link your GitHub account in Settings.");
        }

        /* Verify reservation cooling-off period */
        String reservedKey = AccountServiceImpl.REDIS_RESERVED_EMAIL_PREFIX + cleanEmail;
        if (Boolean.TRUE.equals(stringRedisTemplate.hasKey(reservedKey))) {
            log.warn("GitHub registration rejected: email '{}' is in cooling-off period", cleanEmail);
            throw new ResourceConflictException(
                    "Email '" + cleanEmail + "' is currently in a cooling-off reservation period and cannot be registered");
        }

        /* Auto-provision new user */
        return autoProvisionGitHubUser(identity, displayName, avatarUrl, clientContext);
    }

    @Override
    @Transactional
    public SocialAccountResponse linkGitHub(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "GitHub login request cannot be null")
            @Valid GitHubLoginRequest request) {

        GitHubIdentity identity = fetchGitHubIdentity(request);

        String providerUserId = identity.providerUserId();
        String cleanEmail = identity.email();
        String displayName = sanitizeDisplayName(identity.displayName());
        String avatarUrl = sanitizeAvatarUrl(identity.avatarUrl());

        log.info("Processing GitHub linking request for user ID: '{}', providerUserId: '{}'", userId, providerUserId);

        Optional<UserSocialAccount> existingSocial
                = userSocialAccountRepository.findByProviderAndProviderUserId(SocialProvider.GITHUB, providerUserId);

        if (existingSocial.isPresent()) {
            if (existingSocial.get().getUser().getId().equals(userId)) {
                throw new ResourceConflictException("This GitHub account is already linked to your profile.");
            } else {
                throw new ResourceConflictException("This GitHub account is already linked to another Vaultix user.");
            }
        }

        if (userSocialAccountRepository.findByUserIdAndProvider(userId, SocialProvider.GITHUB).isPresent()) {
            throw new ResourceConflictException("You have already linked a GitHub account to your profile.");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        UserSocialAccount socialAccount = UserSocialAccount.builder()
                .user(user)
                .provider(SocialProvider.GITHUB)
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

        /* If user's primary email matches GitHub's verified email, mark verified */
        if (cleanEmail != null && cleanEmail.equalsIgnoreCase(user.getEmail()) && !user.isEmailVerified()) {
            user.setEmailVerified(true);
            userRepository.save(user);
            log.info("Verified primary email for user ID: '{}' via linked GitHub account", userId);
        }

        log.info("Successfully linked GitHub account (UID: {}) to user ID: {}", providerUserId, userId);

        /* Dispatch social account linked security alert notification email */
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    NotificationEvent event = NotificationEvent.builder()
                            .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                            .templateCode("auth.social-account-linked")
                            .channel(NotificationChannel.EMAIL)
                            .recipient(user.getEmail())
                            .recipientName(user.getFullName() != null && !user.getFullName().isBlank()
                                    ? user.getFullName()
                                    : user.getUsername())
                            .subject("Vaultix - Security Alert: New GitHub Account Linked")
                            .params(Map.of(
                                    "username", user.getUsername(),
                                    "provider", "GitHub",
                                    "connectedEmail", cleanEmail != null ? cleanEmail : "N/A"
                            ))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.socialAccountLinkedRoutingKey(),
                            event);
                    log.info("Dispatched social account linked security alert email for user: {}", user.getUsername());
                } catch (Exception ex) {
                    log.warn("Failed to dispatch social account linked notification for user '{}': {}", user.getUsername(), ex.getMessage());
                }
            }
        });

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
                log.warn("GitHub login rejected: account is locked for user ID: {}", user.getId());
                throw new LockedException("Account is temporarily locked. Please try again later.");
            } else {
                user.setStatus(UserStatus.ACTIVE);
                user.setLockedUntil(null);
                user.setFailedLoginAttempts(0);
            }
        } else if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("GitHub login rejected: account disabled/deleted for user ID: {}", user.getId());
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
            log.info("MFA is enabled for user ID: {}. Issuing MFA challenge token for GitHub login.", user.getId());
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

    private AuthResponse autoProvisionGitHubUser(
            GitHubIdentity identity,
            String displayName,
            String avatarUrl,
            ClientContext clientContext) {

        String username = determineCandidateUsername(identity.login(), identity.email());
        Instant now = Instant.now();

        Set<Role> roles = new HashSet<>();
        roleRepository.findByName("ROLE_USER").ifPresent(roles::add);

        User newUser = User.builder()
                .username(username)
                .email(identity.email())
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
        log.info("Auto-provisioned new user '{}' ({}) via GitHub OAuth2 with ID: {}", username, identity.email(), savedUser.getId());

        UserSocialAccount socialAccount = UserSocialAccount.builder()
                .user(savedUser)
                .provider(SocialProvider.GITHUB)
                .providerUserId(identity.providerUserId())
                .email(identity.email())
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
                                    "email", savedUser.getEmail(),
                                    "emailVerified", savedUser.isEmailVerified()))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.welcomeRoutingKey(),
                            welcomeEvent);
                    log.info("Dispatched welcome notification event for GitHub user: {}", savedUser.getUsername());
                } catch (Exception ex) {
                    log.warn("Failed to dispatch welcome notification event for GitHub user '{}': {}", savedUser.getEmail(), ex.getMessage());
                }
            }
        });
    }

    private GitHubIdentity fetchGitHubIdentity(GitHubLoginRequest request) {
        if (gitHubProperties.clientId() == null || gitHubProperties.clientId().isBlank()
                || "YOUR_GITHUB_CLIENT_ID".equals(gitHubProperties.clientId())
                || gitHubProperties.clientSecret() == null || gitHubProperties.clientSecret().isBlank()
                || "YOUR_GITHUB_CLIENT_SECRET".equals(gitHubProperties.clientSecret())) {
            log.warn("GitHub OAuth2 client ID or client secret is not configured");
            throw new BadRequestException("GitHub authentication is currently unavailable: OAuth credentials are not configured.");
        }

        String accessToken = exchangeCodeForAccessToken(request.code(), request.redirectUri());
        GitHubUserResponse userResponse = fetchGitHubUserProfile(accessToken);
        String verifiedEmail = fetchGitHubPrimaryVerifiedEmail(accessToken);

        String providerUserId = String.valueOf(userResponse.id());
        String displayName = userResponse.name() != null && !userResponse.name().isBlank()
                ? userResponse.name()
                : userResponse.login();

        return new GitHubIdentity(
                providerUserId,
                verifiedEmail,
                userResponse.login(),
                displayName,
                userResponse.avatarUrl());
    }

    private String exchangeCodeForAccessToken(String code, String requestRedirectUri) {
        Map<String, String> body = new java.util.HashMap<>();
        body.put("client_id", gitHubProperties.clientId());
        body.put("client_secret", gitHubProperties.clientSecret());
        body.put("code", code);

        String redirectUri = (requestRedirectUri != null && !requestRedirectUri.isBlank())
                ? requestRedirectUri
                : gitHubProperties.redirectUri();
        if (redirectUri != null && !redirectUri.isBlank()) {
            body.put("redirect_uri", redirectUri);
        }

        GitHubTokenResponse tokenResponse;
        try {
            tokenResponse = restClient.post()
                    .uri(GITHUB_ACCESS_TOKEN_URL)
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .body(GitHubTokenResponse.class);
        } catch (RestClientResponseException ex) {
            log.warn("GitHub token exchange HTTP error [status: {}]: {}", ex.getStatusCode(), ex.getResponseBodyAsString());
            throw new BadCredentialsException("Failed to exchange GitHub authorization code: " + ex.getMessage());
        } catch (Exception ex) {
            log.warn("Failed to exchange GitHub code: {}", ex.getMessage());
            throw new BadCredentialsException("Unable to contact GitHub authorization servers. Please try again.");
        }

        if (tokenResponse == null || tokenResponse.accessToken() == null || tokenResponse.accessToken().isBlank()) {
            String errorMsg = tokenResponse != null && tokenResponse.errorDescription() != null
                    ? tokenResponse.errorDescription()
                    : "Invalid or expired GitHub authorization code";
            log.warn("GitHub OAuth token exchange failed: {}", errorMsg);
            throw new BadCredentialsException(errorMsg);
        }

        return tokenResponse.accessToken();
    }

    private GitHubUserResponse fetchGitHubUserProfile(String accessToken) {
        try {
            GitHubUserResponse userResponse = restClient.get()
                    .uri(GITHUB_USER_API_URL)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .header(HttpHeaders.ACCEPT, "application/vnd.github+json")
                    .retrieve()
                    .body(GitHubUserResponse.class);

            if (userResponse == null || userResponse.id() == null) {
                log.warn("GitHub user profile response is empty or missing ID");
                throw new BadCredentialsException("Failed to retrieve profile from GitHub");
            }
            return userResponse;
        } catch (RestClientResponseException ex) {
            log.warn("GitHub user profile fetch failed [status: {}]: {}", ex.getStatusCode(), ex.getResponseBodyAsString());
            throw new BadCredentialsException("Failed to fetch user profile from GitHub: " + ex.getMessage());
        }
    }

    private String fetchGitHubPrimaryVerifiedEmail(String accessToken) {
        List<GitHubEmailResponse> emails;
        try {
            emails = restClient.get()
                    .uri(GITHUB_EMAILS_API_URL)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .header(HttpHeaders.ACCEPT, "application/vnd.github+json")
                    .retrieve()
                    .body(new ParameterizedTypeReference<List<GitHubEmailResponse>>() {
                    });
        } catch (RestClientResponseException ex) {
            log.warn("GitHub user emails fetch failed [status: {}]: {}", ex.getStatusCode(), ex.getResponseBodyAsString());
            throw new BadCredentialsException("Failed to fetch verified email from GitHub: " + ex.getMessage());
        }

        if (emails == null || emails.isEmpty()) {
            throw new BadCredentialsException("No email address found on your GitHub account");
        }

        /* 1. Try to find the primary verified email */
        Optional<String> primaryVerifiedEmail = emails.stream()
                .filter(e -> e.primary() && e.verified())
                .map(GitHubEmailResponse::email)
                .filter(email -> email != null && !email.isBlank())
                .findFirst();

        if (primaryVerifiedEmail.isPresent()) {
            return primaryVerifiedEmail.get().strip().toLowerCase(Locale.ROOT);
        }

        /* 2. Fall back to any verified email on the account */
        Optional<String> anyVerifiedEmail = emails.stream()
                .filter(GitHubEmailResponse::verified)
                .map(GitHubEmailResponse::email)
                .filter(email -> email != null && !email.isBlank())
                .findFirst();

        if (anyVerifiedEmail.isPresent()) {
            return anyVerifiedEmail.get().strip().toLowerCase(Locale.ROOT);
        }

        throw new BadCredentialsException("Your GitHub account must have at least one verified email address to continue");
    }

    private String determineCandidateUsername(String githubLogin, String email) {
        if (githubLogin != null && !githubLogin.isBlank()) {
            String sanitized = githubLogin.replaceAll("[^a-zA-Z0-9_.-]", "").toLowerCase(Locale.ROOT);
            if (sanitized.length() >= 3) {
                if (sanitized.length() > 30) {
                    sanitized = sanitized.substring(0, 30);
                }
                if (!userRepository.existsByUsername(sanitized)) {
                    return sanitized;
                }
            }
        }
        return generateUniqueUsername(email);
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

    private record GitHubIdentity(
            String providerUserId,
            String email,
            String login,
            String displayName,
            String avatarUrl) {

    }

    private record GitHubTokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("scope") String scope,
            @JsonProperty("error") String error,
            @JsonProperty("error_description") String errorDescription) {

    }

    private record GitHubUserResponse(
            Long id,
            String login,
            String name,
            @JsonProperty("avatar_url") String avatarUrl,
            String email) {

    }

    private record GitHubEmailResponse(
            String email,
            boolean primary,
            boolean verified,
            String visibility) {

    }

    @Override
    public String verifyGitHubCode(GitHubLoginRequest request) {
        GitHubIdentity identity = fetchGitHubIdentity(request);
        return identity.providerUserId();
    }
}
