package com.vaultix.authorization.security.webauthn;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCose;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import com.vaultix.authorization.config.properties.AuthMessagingProperties;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.UserPasskeyCredential;
import com.vaultix.authorization.repository.UserPasskeyCredentialRepository;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.validation.ValidPasskeyLabelValidator;
import com.vaultix.common.dto.notification.NotificationChannel;
import com.vaultix.common.dto.notification.NotificationEvent;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class JpaUserCredentialRepository implements UserCredentialRepository {

    private final UserPasskeyCredentialRepository passkeyRepository;
    private final UserRepository userRepository;
    private final RabbitTemplate rabbitTemplate;
    private final AuthMessagingProperties messagingProperties;

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
                existing.setLabel(ValidPasskeyLabelValidator.sanitizeOrDefault(record.getLabel(), existing.getLabel()));
            }
            if (record.getTransports() != null) {
                existing.setAuthenticatorTransports(serializeTransports(record.getTransports()));
            }
            passkeyRepository.save(existing);
            return;
        }

        UUID userId = JpaPublicKeyCredentialUserEntityRepository.bytesToUuid(record.getUserEntityUserId());
        User user = (userId != null) ? userRepository.findById(userId).orElse(null) : null;

        if (user == null) {
            log.warn("Cannot save passkey credential '{}': user not found for userEntityUserId '{}'", credId, userEntityId);
            return;
        }

        String safeLabel = ValidPasskeyLabelValidator.sanitizeOrDefault(record.getLabel(), "Passkey");

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
                .label(safeLabel)
                .lastUsedAt(record.getLastUsed())
                .createdAt(record.getCreated())
                .build();

        passkeyRepository.save(newCredential);

        if (!user.isPasskeyEnabled()) {
            user.setPasskeyEnabled(true);
            userRepository.save(user);
        }
        log.info("Saved new passkey credential '{}' for user '{}'", credId, user.getUsername());

        /* Dispatch passkey-added security alert notification email */
        final User finalUser = user;
        final String passkeyLabel = newCredential.getLabel();
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    dispatchPasskeyAddedNotification(finalUser, passkeyLabel);
                }
            });
        } else {
            dispatchPasskeyAddedNotification(finalUser, passkeyLabel);
        }
    }

    private void dispatchPasskeyAddedNotification(User user, String passkeyLabel) {
        try {
            NotificationEvent event = NotificationEvent.builder()
                    .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                    .templateCode("auth.passkey-added")
                    .channel(NotificationChannel.EMAIL)
                    .recipient(user.getEmail())
                    .recipientName(user.getFullName() != null && !user.getFullName().isBlank() ? user.getFullName() : user.getUsername())
                    .subject("Vaultix - Security Alert: New Passkey Added")
                    .params(Map.of(
                            "username", user.getUsername(),
                            "email", user.getEmail(),
                            "passkeyLabel", passkeyLabel != null ? passkeyLabel : "Passkey"
                    ))
                    .createdAt(Instant.now())
                    .build();

            rabbitTemplate.convertAndSend(
                    messagingProperties.exchange(),
                    messagingProperties.passkeyAddedRoutingKey(),
                    event);
            log.info("Dispatched passkey added security alert email to '{}' for user: {}", user.getEmail(), user.getUsername());
        } catch (Exception ex) {
            log.warn("Failed to dispatch passkey added notification for user '{}': {}", user.getUsername(), ex.getMessage());
        }
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
