package com.vaultix.authorization.service.impl;

import java.util.Locale;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.vaultix.authorization.dto.admin.UserResponse;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.service.UserService;
import com.vaultix.common.exception.ResourceNotFoundException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public Page<UserResponse> getAllUsers(Pageable pageable) {
        Pageable page = (pageable != null) ? pageable : Pageable.unpaged();
        log.debug("Retrieving all users with pageable: {}", page);
        return userRepository.findAllWithRolesBy(page)
                .map(UserResponse::fromEntity);
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserByIdentifier(String identifier) {
        User user = findUserEntityByIdentifier(identifier);
        return UserResponse.fromEntity(user);
    }

    private User findUserEntityByIdentifier(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            throw new ResourceNotFoundException("User identifier cannot be blank");
        }

        String stripped = identifier.strip();
        if (stripped.length() > 256) {
            throw new ResourceNotFoundException("User not found with identifier: " + stripped);
        }

        try {
            UUID id = UUID.fromString(stripped);
            return userRepository.findWithRolesById(id)
                    .orElseThrow(() -> new ResourceNotFoundException("User not found with identifier: " + stripped));
        } catch (IllegalArgumentException ignored) {
        }

        String normalized = stripped.toLowerCase(Locale.ROOT);
        return userRepository.findWithRolesByUsernameOrEmail(normalized, normalized)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with identifier: " + stripped));
    }
}
