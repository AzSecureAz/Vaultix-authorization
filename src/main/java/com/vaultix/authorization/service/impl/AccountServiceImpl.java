package com.vaultix.authorization.service.impl;

import java.util.Locale;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.ChangeUsernameRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.service.AccountService;
import com.vaultix.common.exception.BadRequestException;
import com.vaultix.common.exception.ResourceConflictException;
import com.vaultix.common.exception.ResourceNotFoundException;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
@RequiredArgsConstructor
public class AccountServiceImpl implements AccountService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public UserProfileDto changeUsername(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Change username request cannot be null")
            @Valid ChangeUsernameRequest request) {

        log.info("Processing username change request for user ID: {}", userId);

        User user = userRepository.findWithRolesAndPermissionsById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + userId));

        if (user.getStatus() == UserStatus.DISABLED || user.getStatus() == UserStatus.DELETED) {
            log.warn("Username change rejected for {} user: {}", user.getStatus(), user.getUsername());
            throw new BadRequestException("Account is " + user.getStatus().name().toLowerCase(Locale.ROOT) + ". Please contact support.");
        }

        String cleanNewUsername = request.username().strip().toLowerCase(Locale.ROOT);

        if (cleanNewUsername.equals(user.getUsername().toLowerCase(Locale.ROOT))) {
            log.warn("Username change rejected: identical username supplied by user ID: {}", userId);
            throw new BadRequestException("New username cannot be the same as your current username");
        }

        if (userRepository.existsByUsername(cleanNewUsername)) {
            log.warn("Username change rejected: username '{}' already taken", cleanNewUsername);
            throw new ResourceConflictException("Username '" + cleanNewUsername + "' is already taken");
        }

        String oldUsername = user.getUsername();
        user.setUsername(cleanNewUsername);
        user.setUpdatedBy(userId);
        User savedUser = userRepository.save(user);

        log.info("Username successfully changed from '{}' to '{}' for user ID: {}",
                oldUsername, cleanNewUsername, userId);

        return UserProfileDto.fromEntity(savedUser);
    }
}
