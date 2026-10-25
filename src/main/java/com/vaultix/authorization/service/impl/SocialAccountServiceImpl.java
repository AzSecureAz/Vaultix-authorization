package com.vaultix.authorization.service.impl;

import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.oauth2.SocialAccountResponse;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.UserSocialAccount;
import com.vaultix.authorization.entity.enums.SocialProvider;
import com.vaultix.authorization.repository.UserPasskeyCredentialRepository;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.repository.UserSocialAccountRepository;
import com.vaultix.authorization.service.SocialAccountService;
import com.vaultix.common.exception.BadRequestException;
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
    private final UserPasskeyCredentialRepository userPasskeyCredentialRepository;

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

        /* Guard against account lockout: verify user has at least one remaining authentication factor */
        boolean hasPassword = user.getPasswordHash() != null && !user.getPasswordHash().isBlank();
        boolean hasPasskeys = user.isPasskeyEnabled() || userPasskeyCredentialRepository.countByUserId(userId) > 0;
        boolean hasOtherSocialAccounts = userSocialAccountRepository.countByUserId(userId) > 1;

        if (!hasPassword && !hasPasskeys && !hasOtherSocialAccounts) {
            log.warn("Account unlink rejected: user ID '{}' would have no remaining authentication methods", userId);
            throw new BadRequestException(
                    "Cannot unlink your only authentication method. Please set a password or register a passkey before unlinking your "
                    + provider.name() + " account.");
        }

        userSocialAccountRepository.delete(account);

        long remainingSocialAccounts = userSocialAccountRepository.countByUserId(userId);
        if (remainingSocialAccounts == 0) {
            user.setHasSocialAccounts(false);
            userRepository.save(user);
        }

        log.info("Successfully unlinked {} account for user ID: '{}'. Remaining social accounts: {}",
                provider, userId, remainingSocialAccounts);
    }
}
