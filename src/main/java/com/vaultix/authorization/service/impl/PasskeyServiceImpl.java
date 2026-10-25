package com.vaultix.authorization.service.impl;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.AuthMessagingProperties;
import com.vaultix.authorization.dto.mfa.PasskeyResponse;
import com.vaultix.authorization.dto.mfa.UpdatePasskeyRequest;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.UserPasskeyCredential;
import com.vaultix.authorization.repository.UserPasskeyCredentialRepository;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.service.PasskeyService;
import com.vaultix.common.dto.notification.NotificationChannel;
import com.vaultix.common.dto.notification.NotificationEvent;
import com.vaultix.common.exception.ResourceNotFoundException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
@RequiredArgsConstructor
public class PasskeyServiceImpl implements PasskeyService {

    private final UserRepository userRepository;
    private final UserPasskeyCredentialRepository passkeyCredentialRepository;
    private final RabbitTemplate rabbitTemplate;
    private final AuthMessagingProperties messagingProperties;

    @Override
    @Transactional(readOnly = true)
    public List<PasskeyResponse> getUserPasskeys(UUID userId) {
        return passkeyCredentialRepository.findByUserIdOrderByCreatedAtDesc(userId)
                .stream()
                .map(PasskeyResponse::fromEntity)
                .toList();
    }

    @Override
    @Transactional
    public PasskeyResponse updatePasskeyLabel(UUID userId, UUID passkeyId, UpdatePasskeyRequest request) {
        UserPasskeyCredential credential = passkeyCredentialRepository.findByIdAndUserId(passkeyId, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Passkey not found with id: " + passkeyId));

        credential.setLabel(request.label().strip());
        UserPasskeyCredential updated = passkeyCredentialRepository.save(credential);
        log.info("Updated label for passkey '{}' belonging to user '{}'", passkeyId, userId);

        return PasskeyResponse.fromEntity(updated);
    }

    @Override
    @Transactional
    public void deletePasskey(UUID userId, UUID passkeyId) {
        UserPasskeyCredential credential = passkeyCredentialRepository.findByIdAndUserId(passkeyId, userId)
                .orElseThrow(() -> new ResourceNotFoundException("Passkey not found with id: " + passkeyId));

        User user = credential.getUser();
        String passkeyLabel = credential.getLabel() != null && !credential.getLabel().isBlank()
                ? credential.getLabel()
                : "Passkey";

        passkeyCredentialRepository.delete(credential);
        log.info("Deleted passkey '{}' belonging to user '{}'", passkeyId, userId);

        long remainingCount = passkeyCredentialRepository.countByUserId(userId);
        if (remainingCount == 0) {
            user.setPasskeyEnabled(false);
            userRepository.save(user);
            log.info("Disabled passkey flag for user '{}' as no remaining passkeys exist", userId);
        }

        /* Dispatch passkey-removed security alert notification email after transaction commits */
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    NotificationEvent event = NotificationEvent.builder()
                            .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                            .templateCode("auth.passkey-removed")
                            .channel(NotificationChannel.EMAIL)
                            .recipient(user.getEmail())
                            .recipientName(user.getFullName() != null && !user.getFullName().isBlank() ? user.getFullName() : user.getUsername())
                            .subject("Vaultix - Security Alert: Passkey Removed")
                            .params(Map.of(
                                    "username", user.getUsername(),
                                    "email", user.getEmail(),
                                    "passkeyLabel", passkeyLabel,
                                    "remainingPasskeys", remainingCount
                            ))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.passkeyRemovedRoutingKey(),
                            event);
                    log.info("Dispatched passkey removed security alert email to '{}' for user: {}", user.getEmail(), user.getUsername());
                } catch (Exception ex) {
                    log.warn("Failed to dispatch passkey removed notification for user '{}': {}", user.getUsername(), ex.getMessage());
                }
            }
        });
    }
}
