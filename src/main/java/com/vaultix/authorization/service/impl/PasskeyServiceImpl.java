package com.vaultix.authorization.service.impl;

import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.mfa.PasskeyResponse;
import com.vaultix.authorization.dto.mfa.UpdatePasskeyRequest;
import com.vaultix.authorization.entity.UserPasskeyCredential;
import com.vaultix.authorization.repository.UserPasskeyCredentialRepository;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.service.PasskeyService;
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

        passkeyCredentialRepository.delete(credential);
        log.info("Deleted passkey '{}' belonging to user '{}'", passkeyId, userId);

        long remainingCount = passkeyCredentialRepository.countByUserId(userId);
        if (remainingCount == 0) {
            userRepository.findById(userId).ifPresent(user -> {
                user.setPasskeyEnabled(false);
                userRepository.save(user);
                log.info("Disabled passkey flag for user '{}' as no remaining passkeys exist", userId);
            });
        }
    }
}
