package com.vaultix.authorization.service.impl;

import java.util.Locale;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.admin.UserResponse;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.service.UserService;
import com.vaultix.common.exception.ResourceNotFoundException;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public Page<UserResponse> getAllUsers(Pageable pageable) {
        Pageable page = (pageable != null && pageable.isPaged())
                ? pageable
                : PageRequest.of(0, 10, Sort.by(Sort.Direction.DESC, "createdAt"));
        log.debug("Retrieving all users with pageable: {}", page);
        return userRepository.findAllWithRolesBy(page)
                .map(UserResponse::fromEntity);
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserByIdentifier(
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier) {

        User user = findUserEntityByIdentifier(identifier);
        return UserResponse.fromEntity(user);
    }

    private User findUserEntityByIdentifier(String identifier) {
        String stripped = identifier.strip();

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
