package com.vaultix.authorization.security.webauthn;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCose;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.UserPasskeyCredential;
import com.vaultix.authorization.repository.UserPasskeyCredentialRepository;
import com.vaultix.authorization.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class JpaUserCredentialRepository implements UserCredentialRepository {

    private final UserPasskeyCredentialRepository passkeyRepository;
    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public CredentialRecord findByCredentialId(Bytes credentialId) {
        if (credentialId == null) {
            return null;
        }

        String credId = credentialId.toBase64UrlString();
        return passkeyRepository.findByCredentialId(credId)
                .map(this::toCredentialRecord)
                .orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public List<CredentialRecord> findByUserId(Bytes userId) {
        if (userId == null) {
            return List.of();
        }

        String userEntityId = userId.toBase64UrlString();
        return passkeyRepository.findByUserEntityUserId(userEntityId).stream()
                .map(this::toCredentialRecord)
                .toList();
    }

    @Override
    @Transactional
    public void save(CredentialRecord record) {
        if (record == null || record.getCredentialId() == null || record.getUserEntityUserId() == null) {
            return;
        }

        String credId = record.getCredentialId().toBase64UrlString();
        String userEntityId = record.getUserEntityUserId().toBase64UrlString();

        Optional<UserPasskeyCredential> existingOpt = passkeyRepository.findByCredentialId(credId);
        if (existingOpt.isPresent()) {
            UserPasskeyCredential existing = existingOpt.get();
            existing.setSignatureCount(record.getSignatureCount());
            existing.setUvInitialized(record.isUvInitialized());
            existing.setBackupEligible(record.isBackupEligible());
            existing.setBackupState(record.isBackupState());
            existing.setLastUsedAt(record.getLastUsed());
            if (record.getLabel() != null && !record.getLabel().isBlank()) {
                existing.setLabel(record.getLabel());
            }
            if (record.getTransports() != null) {
                existing.setAuthenticatorTransports(serializeTransports(record.getTransports()));
            }
            passkeyRepository.save(existing);
            return;
        }

        UUID userId = JpaPublicKeyCredentialUserEntityRepository.bytesToUuid(record.getUserEntityUserId());
        User user = null;
        if (userId != null) {
            user = userRepository.findById(userId).orElse(null);
        }

        if (user == null) {
            log.warn("Cannot save passkey credential '{}': user not found for userEntityUserId '{}'", credId, userEntityId);
            return;
        }

        UserPasskeyCredential newCredential = UserPasskeyCredential.builder()
                .user(user)
                .credentialId(credId)
                .userEntityUserId(userEntityId)
                .publicKey(record.getPublicKey().getBytes())
                .signatureCount(record.getSignatureCount())
                .uvInitialized(record.isUvInitialized())
                .backupEligible(record.isBackupEligible())
                .backupState(record.isBackupState())
                .authenticatorTransports(serializeTransports(record.getTransports()))
                .publicKeyCredentialType(record.getCredentialType() != null ? record.getCredentialType().getValue() : "public-key")
                .attestationObject(record.getAttestationObject() != null ? record.getAttestationObject().getBytes() : null)
                .attestationClientDataJson(record.getAttestationClientDataJSON() != null ? record.getAttestationClientDataJSON().getBytes() : null)
                .label(record.getLabel() != null && !record.getLabel().isBlank() ? record.getLabel() : "Passkey")
                .lastUsedAt(record.getLastUsed())
                .createdAt(record.getCreated())
                .build();

        passkeyRepository.save(newCredential);

        if (!user.isPasskeyEnabled()) {
            user.setPasskeyEnabled(true);
            userRepository.save(user);
        }
        log.info("Saved new passkey credential '{}' for user '{}'", credId, user.getUsername());
    }

    @Override
    @Transactional
    public void delete(Bytes credentialId) {
        if (credentialId == null) {
            return;
        }

        String credId = credentialId.toBase64UrlString();
        Optional<UserPasskeyCredential> credOpt = passkeyRepository.findByCredentialId(credId);
        if (credOpt.isEmpty()) {
            return;
        }

        UserPasskeyCredential cred = credOpt.get();
        User user = cred.getUser();
        passkeyRepository.delete(cred);

        if (passkeyRepository.countByUserId(user.getId()) == 0) {
            user.setPasskeyEnabled(false);
            userRepository.save(user);
            log.info("All passkeys removed for user '{}'. Set passkeyEnabled to false.", user.getUsername());
        }
    }

    private CredentialRecord toCredentialRecord(UserPasskeyCredential entity) {
        Bytes credId = Bytes.fromBase64(entity.getCredentialId());
        Bytes userEntityId = Bytes.fromBase64(entity.getUserEntityUserId());

        return ImmutableCredentialRecord.builder()
                .credentialType(PublicKeyCredentialType.valueOf(entity.getPublicKeyCredentialType()))
                .credentialId(credId)
                .userEntityUserId(userEntityId)
                .publicKey(new ImmutablePublicKeyCose(entity.getPublicKey()))
                .signatureCount(entity.getSignatureCount())
                .uvInitialized(entity.isUvInitialized())
                .transports(deserializeTransports(entity.getAuthenticatorTransports()))
                .backupEligible(entity.isBackupEligible())
                .backupState(entity.isBackupState())
                .attestationObject(entity.getAttestationObject() != null ? new Bytes(entity.getAttestationObject()) : null)
                .attestationClientDataJSON(entity.getAttestationClientDataJson() != null ? new Bytes(entity.getAttestationClientDataJson()) : null)
                .created(entity.getCreatedAt())
                .lastUsed(entity.getLastUsedAt())
                .label(entity.getLabel())
                .build();
    }

    private String serializeTransports(Set<AuthenticatorTransport> transports) {
        if (transports == null || transports.isEmpty()) {
            return null;
        }
        return transports.stream()
                .map(AuthenticatorTransport::getValue)
                .collect(Collectors.joining(","));
    }

    private Set<AuthenticatorTransport> deserializeTransports(String transports) {
        if (transports == null || transports.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(transports.split(","))
                .map(String::strip)
                .filter(s -> !s.isEmpty())
                .map(s -> AuthenticatorTransport.valueOf(s.toLowerCase(Locale.ROOT)))
                .collect(Collectors.toSet());
    }
}
