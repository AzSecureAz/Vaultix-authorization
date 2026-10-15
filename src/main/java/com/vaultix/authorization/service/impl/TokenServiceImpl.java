package com.vaultix.authorization.service.impl;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
import com.vaultix.authorization.dto.UserSummaryDto;
import com.vaultix.authorization.entity.RefreshToken;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.RefreshTokenRepository;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.security.CustomUserDetails;
import com.vaultix.authorization.service.SigningKeyService;
import com.vaultix.authorization.service.TokenService;
import com.vaultix.common.security.TokenBlacklistService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private final SigningKeyService signingKeyService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtProperties jwtProperties;
    private final TokenBlacklistService tokenBlacklistService;

    @Override
    @Transactional
    public AuthResponse issueTokens(CustomUserDetails userDetails, String deviceInfo, String ipAddress) {
        log.info("Issuing initial access and refresh tokens for user ID: {}", userDetails.getId());

        Instant now = Instant.now();
        Instant accessExp = now.plus(jwtProperties.accessTokenExpiration());
        Instant refreshExp = now.plus(jwtProperties.refreshTokenExpiration());

        UUID accessTokenJti = UUID.ofEpochMillis(System.currentTimeMillis());
        UUID refreshTokenJti = UUID.ofEpochMillis(System.currentTimeMillis());

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .user(userRepository.getReferenceById(userDetails.getId()))
                .refreshTokenJti(refreshTokenJti)
                .accessTokenJti(accessTokenJti)
                .gen(1)
                .deviceInfo(deviceInfo)
                .ipAddress(ipAddress)
                .revoked(false)
                .expiresAt(refreshExp)
                .build();

        refreshTokenRepository.save(refreshTokenEntity);

        return buildAuthResponse(userDetails, accessTokenJti, refreshTokenJti, 1, accessExp, refreshExp);
    }

    @Override
    @Transactional
    public AuthResponse refreshTokens(String rawRefreshToken, String deviceInfo, String ipAddress) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            throw new BadCredentialsException("Refresh token is required");
        }

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(rawRefreshToken);
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
        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED || user.getStatus() == UserStatus.EXPIRED) {
            log.warn("Attempt to refresh token for disabled/deleted/expired user: {}", user.getUsername());
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

        existingSession.setAccessTokenJti(newAccessTokenJti);
        existingSession.setGen(nextGen);
        existingSession.setExpiresAt(newRefreshExp);
        existingSession.setDeviceInfo(deviceInfo);
        existingSession.setIpAddress(ipAddress);
        refreshTokenRepository.save(existingSession);

        log.info("Updated refresh token session in-place for user ID: {} (Generation: {} -> {})",
                user.getId(), existingSession.getGen() - 1, nextGen);

        CustomUserDetails userDetails = new CustomUserDetails(existingSession.getUser());

        return buildAuthResponse(userDetails, newAccessTokenJti, existingSession.getRefreshTokenJti(), nextGen, accessExp, newRefreshExp);
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

            Set<String> roles = userDetails.getRolePermissions() != null
                    ? userDetails.getRolePermissions().keySet()
                    : Set.of();

            JWTClaimsSet accessClaims = new JWTClaimsSet.Builder()
                    .issuer(jwtProperties.issuer())
                    .subject(userDetails.getId().toString())
                    .jwtID(accessTokenJti.toString())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(accessExp))
                    .claim("username", userDetails.getUsername())
                    .claim("email", userDetails.getEmail())
                    .claim("roles", roles)
                    .claim("roles_permissions", userDetails.getRolePermissions())
                    .claim("email_verified", userDetails.isEmailVerified())
                    .claim("must_change_password", userDetails.isMustChangePassword())
                    .claim("mfa_enabled", userDetails.isMfaEnabled())
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
                    .claim("access_token_jti", accessTokenJti.toString())
                    .claim("gen", gen)
                    .build();

            SignedJWT signedRefreshToken = new SignedJWT(header, refreshClaims);
            signedRefreshToken.sign(signer);
            String refreshTokenString = signedRefreshToken.serialize();

            UserSummaryDto userSummary = UserSummaryDto.builder()
                    .id(userDetails.getId())
                    .username(userDetails.getUsername())
                    .email(userDetails.getEmail())
                    .emailVerified(userDetails.isEmailVerified())
                    .mfaEnabled(userDetails.isMfaEnabled())
                    .passkeyEnabled(userDetails.isPasskeyEnabled())
                    .hasSocialAccounts(userDetails.isHasSocialAccounts())
                    .roles(roles)
                    .rolePermissions(userDetails.getRolePermissions())
                    .build();

            return AuthResponse.builder()
                    .accessToken(accessTokenString)
                    .refreshToken(refreshTokenString)
                    .tokenType(AuthResponse.TOKEN_TYPE_BEARER)
                    .expiresIn(jwtProperties.accessTokenExpiration().toSeconds())
                    .mustChangePassword(userDetails.isMustChangePassword())
                    .user(userSummary)
                    .build();

        } catch (JOSEException e) {
            log.error("Failed to cryptographically sign JWT for user: {}", userDetails.getId(), e);
            throw new IllegalStateException("Failed to sign JWT tokens", e);
        }
    }
}
