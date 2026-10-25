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
import com.vaultix.authorization.dto.oauth2.SocialAccountResponse;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.UserSocialAccount;
import com.vaultix.authorization.entity.enums.SocialProvider;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.repository.UserSocialAccountRepository;
import com.vaultix.authorization.service.SocialAccountService;
import com.vaultix.common.dto.notification.NotificationChannel;
import com.vaultix.common.dto.notification.NotificationEvent;
import com.vaultix.common.exception.ResourceNotFoundException;

import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
@RequiredArgsConstructor
public class SocialAccountServiceImpl implements SocialAccountService {

    private final UserSocialAccountRepository userSocialAccountRepository;
    private final UserRepository userRepository;
    private final RabbitTemplate rabbitTemplate;
    private final AuthMessagingProperties messagingProperties;

    @Override
    @Transactional(readOnly = true)
    public List<SocialAccountResponse> getLinkedAccounts(@NotNull(message = "User ID cannot be null") UUID userId) {
        return userSocialAccountRepository.findByUserIdOrderByCreatedAtDesc(userId)
                .stream()
                .map(SocialAccountResponse::fromEntity)
                .toList();
    }

    @Override
    @Transactional
    public void unlinkAccount(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Social provider cannot be null") SocialProvider provider) {

        log.info("Processing social account unlink request for user ID: '{}', provider: '{}'", userId, provider);

        UserSocialAccount account = userSocialAccountRepository.findByUserIdAndProvider(userId, provider)
                .orElseThrow(() -> new ResourceNotFoundException("No linked " + provider.name() + " account found"));

        User user = account.getUser();
        String connectedEmail = account.getEmail() != null ? account.getEmail() : "N/A";
        String providerName = provider.name();

        userSocialAccountRepository.delete(account);

        long remainingSocialAccounts = userSocialAccountRepository.countByUserId(userId);
        if (remainingSocialAccounts == 0) {
            user.setHasSocialAccounts(false);
            userRepository.save(user);
        }

        log.info("Successfully unlinked {} account for user ID: '{}'. Remaining social accounts: {}",
                provider, userId, remainingSocialAccounts);

        /* Dispatch social account unlinked security alert notification email */
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    NotificationEvent event = NotificationEvent.builder()
                            .eventId(UUID.ofEpochMillis(System.currentTimeMillis()))
                            .templateCode("auth.social-account-unlinked")
                            .channel(NotificationChannel.EMAIL)
                            .recipient(user.getEmail())
                            .recipientName(user.getFullName() != null && !user.getFullName().isBlank()
                                    ? user.getFullName()
                                    : user.getUsername())
                            .subject("Vaultix - Security Alert: " + providerName + " Account Disconnected")
                            .params(Map.of(
                                    "username", user.getUsername(),
                                    "provider", providerName,
                                    "connectedEmail", connectedEmail
                            ))
                            .createdAt(Instant.now())
                            .build();

                    rabbitTemplate.convertAndSend(
                            messagingProperties.exchange(),
                            messagingProperties.socialAccountUnlinkedRoutingKey(),
                            event);
                    log.info("Dispatched social account unlinked security alert email for user: {}", user.getUsername());
                } catch (Exception ex) {
                    log.warn("Failed to dispatch social account unlinked notification for user '{}': {}", user.getUsername(), ex.getMessage());
                }
            }
        });
    }
}
