package com.vaultix.authorization.service.impl;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.validation.annotation.Validated;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vaultix.authorization.config.properties.JwtProperties;
import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.RefreshTokenRequest;
import com.vaultix.authorization.entity.RefreshToken;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.RefreshTokenRepository;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.security.CustomUserDetails;
import com.vaultix.authorization.service.SigningKeyService;
import com.vaultix.authorization.service.TokenService;
import com.vaultix.common.security.TokenBlacklistService;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final SigningKeyService signingKeyService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtProperties jwtProperties;
    private final TokenBlacklistService tokenBlacklistService;

    @Override
    @Transactional
    public AuthResponse issueTokens(
            @NotNull(message = "User details cannot be null") CustomUserDetails userDetails,
            ClientContext clientContext) {

        if (userDetails.getId() == null) {
            throw new BadCredentialsException("User details and user ID are required");
        }

        log.info("Issuing initial access and refresh tokens for user ID: {}", userDetails.getId());

        Instant now = Instant.now();
        Instant accessExp = now.plus(jwtProperties.accessTokenExpiration());
        Instant refreshExp = now.plus(jwtProperties.refreshTokenExpiration());

        UUID accessTokenJti = UUID.ofEpochMillis(System.currentTimeMillis());
        UUID refreshTokenJti = UUID.ofEpochMillis(System.currentTimeMillis());

        ClientContext context = ClientContext.ofNullable(clientContext);

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .user(userRepository.getReferenceById(userDetails.getId()))
                .refreshTokenJti(refreshTokenJti)
                .accessTokenJti(accessTokenJti)
                .gen(1)
                .deviceInfo(truncate(context.deviceInfo(), 256))
                .ipAddress(truncate(context.ip(), 64))
                .locationInfo(truncate(context.location(), 256))
                .revoked(false)
                .expiresAt(refreshExp)
                .build();

        refreshTokenRepository.save(refreshTokenEntity);

        return buildAuthResponse(userDetails, accessTokenJti, refreshTokenJti, 1, accessExp, refreshExp);
    }

    @Override
    @Transactional
    public AuthResponse refreshTokens(
            @NotBlank(message = "Refresh token is required")
            @Size(max = RefreshTokenRequest.MAX_LENGTH, message = "Refresh token cannot exceed " + RefreshTokenRequest.MAX_LENGTH + " characters") String rawRefreshToken,
            ClientContext clientContext) {

        String token = rawRefreshToken.strip();

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(token);
        } catch (ParseException e) {
            log.warn("Malformed refresh token received: {}", e.getMessage());
            throw new BadCredentialsException("Malformed refresh token", e);
        }

        String kid = signedJWT.getHeader().getKeyID();
        if (kid == null) {
            throw new BadCredentialsException("Refresh token missing kid header");
        }

        JWK jwk = signingKeyService.getJwkSet().getKeyByKeyId(kid);
        if (jwk == null || !(jwk instanceof RSAKey rsaKey)) {
            log.warn("Signing key not found or invalid for kid: {}", kid);
            throw new BadCredentialsException("Unknown or rotated signing key");
        }

        try {
            JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
            if (!signedJWT.verify(verifier)) {
                log.warn("Signature verification failed for refresh token kid: {}", kid);
                throw new BadCredentialsException("Invalid token signature");
            }
        } catch (JOSEException e) {
            log.error("Error during token signature verification", e);
            throw new BadCredentialsException("Signature verification error", e);
        }

        JWTClaimsSet claims;
        try {
            claims = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new BadCredentialsException("Failed to parse token claims", e);
        }

        if (!jwtProperties.issuer().equals(claims.getIssuer())) {
            throw new BadCredentialsException("Invalid token issuer");
        }

        Date expirationTime = claims.getExpirationTime();
        if (expirationTime == null || expirationTime.before(new Date())) {
            throw new BadCredentialsException("Refresh token has expired");
        }

        if (!"refresh".equals(claims.getClaim("token_type"))) {
            throw new BadCredentialsException("Token is not a valid refresh token");
        }

        String jtiString = claims.getJWTID();
        if (jtiString == null) {
            throw new BadCredentialsException("Refresh token missing jti claim");
        }

        UUID refreshTokenJti;
        try {
            refreshTokenJti = UUID.fromString(jtiString);
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException("Invalid jti format in refresh token");
        }

        RefreshToken existingSession = refreshTokenRepository.findWithUserAndRolesAndPermissionsByRefreshTokenJti(refreshTokenJti)
                .orElseThrow(() -> new BadCredentialsException("Refresh token session not found"));

        if (existingSession.isRevoked()) {
            throw new BadCredentialsException("Refresh token has been revoked");
        }

        if (existingSession.getExpiresAt().isBefore(Instant.now())) {
            throw new BadCredentialsException("Refresh token session has expired");
        }

        User user = existingSession.getUser();
        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Attempt to refresh token for disabled/deleted user: {}", user.getUsername());
            existingSession.setRevoked(true);
            existingSession.setRevokedAt(Instant.now());
            refreshTokenRepository.save(existingSession);
            tokenBlacklistService.blacklist(existingSession.getAccessTokenJti().toString(), jwtProperties.accessTokenExpiration());
            throw new BadCredentialsException("User account is disabled");
        }

        Object genClaim = claims.getClaim("gen");
        int incomingGen = (genClaim instanceof Number n) ? n.intValue() : 1;

        if (incomingGen != existingSession.getGen()) {
            log.warn("SECURITY ALERT: Token replay detected! Incoming gen: {}, DB gen: {} for user ID: {}",
                    incomingGen, existingSession.getGen(), user.getId());
            existingSession.setRevoked(true);
            existingSession.setRevokedAt(Instant.now());
            refreshTokenRepository.save(existingSession);
            tokenBlacklistService.blacklist(existingSession.getAccessTokenJti().toString(), jwtProperties.accessTokenExpiration());
            throw new BadCredentialsException("Token replay detected: session revoked");
        }

        tokenBlacklistService.blacklist(existingSession.getAccessTokenJti().toString(), jwtProperties.accessTokenExpiration());

        UUID newAccessTokenJti = UUID.ofEpochMillis(System.currentTimeMillis());
        int nextGen = existingSession.getGen() + 1;
        Instant now = Instant.now();
        Instant accessExp = now.plus(jwtProperties.accessTokenExpiration());
        Instant newRefreshExp = now.plus(jwtProperties.refreshTokenExpiration());

        ClientContext context = ClientContext.ofNullable(clientContext);
        existingSession.setAccessTokenJti(newAccessTokenJti);
        existingSession.setGen(nextGen);
        existingSession.setExpiresAt(newRefreshExp);
        existingSession.setDeviceInfo(truncate(context.deviceInfo(), 256));
        existingSession.setIpAddress(truncate(context.ip(), 64));
        existingSession.setLocationInfo(truncate(context.location(), 256));
        refreshTokenRepository.save(existingSession);

        log.info("Updated refresh token session in-place for user ID: {} (Generation: {} -> {})",
                user.getId(), existingSession.getGen() - 1, nextGen);

        CustomUserDetails userDetails = new CustomUserDetails(existingSession.getUser());

        return buildAuthResponse(userDetails, newAccessTokenJti, existingSession.getRefreshTokenJti(), nextGen, accessExp, newRefreshExp);
    }

    @Override
    @Transactional
    public void logout(
            @NotBlank(message = "Access token JTI is required")
            @Size(max = 64, message = "Access token JTI cannot exceed 64 characters") String accessTokenJti) {

        String cleanedJti = accessTokenJti.strip();
        log.info("Processing logout for access token JTI: {}", cleanedJti);

        tokenBlacklistService.blacklist(cleanedJti, jwtProperties.accessTokenExpiration());

        try {
            UUID jtiUuid = UUID.fromString(cleanedJti);
            refreshTokenRepository.findByAccessTokenJti(jtiUuid).ifPresent(session -> {
                session.setRevoked(true);
                session.setRevokedAt(Instant.now());
                refreshTokenRepository.save(session);
                log.info("Revoked refresh token session for user ID: {} upon logout", session.getUser().getId());
            });
        } catch (IllegalArgumentException e) {
            log.warn("Invalid UUID format for access token JTI during logout: {}", cleanedJti);
        }
    }

    @Override
    @Transactional
    public int revokeAllUserTokens(@NotNull(message = "User ID cannot be null") UUID userId) {
        log.info("Revoking all active tokens and sessions for user ID: {}", userId);

        Instant now = Instant.now();
        List<UUID> activeAccessTokenJtis = refreshTokenRepository.findActiveAccessTokenJtisByUserId(userId, now);

        int revokedCount = 0;
        if (!activeAccessTokenJtis.isEmpty()) {
            blacklistTokensAfterCommit(activeAccessTokenJtis);
            revokedCount = refreshTokenRepository.revokeByAccessTokenJtis(activeAccessTokenJtis, now);
        }

        log.info("Revoked {} refresh token sessions and scheduled blacklist for {} access tokens for user ID: {}",
                revokedCount, activeAccessTokenJtis.size(), userId);
        return revokedCount;
    }

    private void blacklistTokensAfterCommit(List<UUID> activeAccessTokenJtis) {
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    for (UUID jti : activeAccessTokenJtis) {
                        tokenBlacklistService.blacklist(jti.toString(), jwtProperties.accessTokenExpiration());
                    }
                    log.debug("Successfully blacklisted {} access token JTIs in Redis after transaction commit", activeAccessTokenJtis.size());
                }
            });
        } else {
            for (UUID jti : activeAccessTokenJtis) {
                tokenBlacklistService.blacklist(jti.toString(), jwtProperties.accessTokenExpiration());
            }
            log.debug("Successfully blacklisted {} access token JTIs in Redis immediately", activeAccessTokenJtis.size());
        }
    }

    private AuthResponse buildAuthResponse(
            CustomUserDetails userDetails,
            UUID accessTokenJti,
            UUID refreshTokenJti,
            int gen,
            Instant accessExp,
            Instant refreshExp) {

        RSAKey activeKey = signingKeyService.getActiveSigningKey();

        try {
            JWSSigner signer = new RSASSASigner(activeKey.toRSAPrivateKey());
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(activeKey.getKeyID())
                    .type(JOSEObjectType.JWT)
                    .build();

            Instant now = Instant.now();

            JWTClaimsSet accessClaims = new JWTClaimsSet.Builder()
                    .issuer(jwtProperties.issuer())
                    .subject(userDetails.getId().toString())
                    .jwtID(accessTokenJti.toString())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(accessExp))
                    .claim("token_type", "access")
                    .claim("sid", refreshTokenJti.toString())
                    .claim("roles_permissions", userDetails.getRolePermissions())
                    .build();

            SignedJWT signedAccessToken = new SignedJWT(header, accessClaims);
            signedAccessToken.sign(signer);
            String accessTokenString = signedAccessToken.serialize();

            JWTClaimsSet refreshClaims = new JWTClaimsSet.Builder()
                    .issuer(jwtProperties.issuer())
                    .subject(userDetails.getId().toString())
                    .jwtID(refreshTokenJti.toString())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(refreshExp))
                    .claim("token_type", "refresh")
                    .claim("gen", gen)
                    .build();

            SignedJWT signedRefreshToken = new SignedJWT(header, refreshClaims);
            signedRefreshToken.sign(signer);
            String refreshTokenString = signedRefreshToken.serialize();

            return AuthResponse.builder()
                    .accessToken(accessTokenString)
                    .refreshToken(refreshTokenString)
                    .tokenType(AuthResponse.TOKEN_TYPE_BEARER)
                    .expiresIn(jwtProperties.accessTokenExpiration().toSeconds())
                    .build();

        } catch (JOSEException e) {
            log.error("Failed to cryptographically sign JWT for user: {}", userDetails.getId(), e);
            throw new IllegalStateException("Failed to sign JWT tokens", e);
        }
    }

    @Override
    @Transactional
    public int cleanExpiredTokens() {
        Instant now = Instant.now();
        Instant revokedThreshold = now.minus(jwtProperties.refreshTokenCleanupGracePeriod());
        Instant expiredThreshold = now;

        int totalDeleted = 0;
        int deleted;
        do {
            deleted = refreshTokenRepository.deleteExpiredTokensBatch(
                    revokedThreshold,
                    expiredThreshold,
                    jwtProperties.refreshTokenCleanupBatchSize()
            );
            totalDeleted += deleted;
        } while (deleted == jwtProperties.refreshTokenCleanupBatchSize());

        if (totalDeleted > 0) {
            log.info("Cleaned up {} expired/revoked refresh tokens from database", totalDeleted);
        }
        return totalDeleted;
    }

    private String truncate(String value, int maxLength) {
        String stripped = value.strip();
        return stripped.length() > maxLength ? stripped.substring(0, maxLength) : stripped;
    }
}
