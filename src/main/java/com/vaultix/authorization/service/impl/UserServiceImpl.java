package com.vaultix.authorization.service.impl;

import java.time.Instant;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.UserProperties;
import com.vaultix.authorization.dto.admin.CreateUserRequest;
import com.vaultix.authorization.dto.admin.UpdateUserRequest;
import com.vaultix.authorization.dto.admin.UserResponse;
import com.vaultix.authorization.entity.Role;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.RoleStatus;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.RoleRepository;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.service.TokenService;
import com.vaultix.authorization.service.UserService;
import com.vaultix.common.exception.BadRequestException;
import com.vaultix.common.exception.ResourceConflictException;
import com.vaultix.common.exception.ResourceNotFoundException;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final TokenService tokenService;
    private final StringRedisTemplate stringRedisTemplate;
    private final UserProperties userProperties;

    @Override
    @Transactional(readOnly = true)
    public Page<UserResponse> getAllUsers(Pageable pageable) {
        Pageable page = (pageable != null && pageable.isPaged())
                ? (pageable.getPageSize() > 50
                ? PageRequest.of(pageable.getPageNumber(), 50, pageable.getSort())
                : pageable)
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

    @Override
    @Transactional
    public UserResponse createUser(
            @NotNull(message = "Create user request cannot be null")
            @Valid CreateUserRequest request,
            @NotNull(message = "Actor ID cannot be null") UUID actorId) {

        int actorHighestLevel = resolveActorHighestLevel(actorId, "create");

        String cleanUsername = request.username().strip().toLowerCase(Locale.ROOT);
        String cleanEmail = request.email().strip().toLowerCase(Locale.ROOT);
        String cleanFullName = (request.fullName() != null && !request.fullName().isBlank())
                ? request.fullName().strip()
                : null;

        if (userRepository.existsByUsername(cleanUsername)) {
            throw new ResourceConflictException("User already exists with username: " + cleanUsername);
        }

        if (userRepository.existsByEmail(cleanEmail)) {
            throw new ResourceConflictException("User already exists with email: " + cleanEmail);
        }

        String reservedKey = AccountServiceImpl.REDIS_RESERVED_EMAIL_PREFIX + cleanEmail;
        if (Boolean.TRUE.equals(stringRedisTemplate.hasKey(reservedKey))) {
            log.warn("Admin user creation rejected: email '{}' is in a cooling-off reservation period", cleanEmail);
            throw new ResourceConflictException("Email '" + cleanEmail + "' is currently in a cooling-off reservation period and cannot be registered");
        }

        Set<Role> rolesToAssign = resolveAndValidateRoles(request.roles(), actorHighestLevel, actorId);

        User newUser = User.builder()
                .username(cleanUsername)
                .email(cleanEmail)
                .passwordHash(null)
                .fullName(cleanFullName)
                .status(UserStatus.ACTIVE)
                .emailVerified(false)
                .roles(rolesToAssign)
                .createdBy(actorId)
                .build();

        User savedUser = userRepository.save(newUser);
        log.info("User '{}' ({}) created successfully by actor {}", cleanUsername, cleanEmail, actorId);

        return UserResponse.fromEntity(savedUser);
    }

    @Override
    @Transactional
    public UserResponse updateUser(
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @NotNull(message = "Update user request cannot be null")
            @Valid UpdateUserRequest request,
            @NotNull(message = "Actor ID cannot be null") UUID actorId) {

        int actorHighestLevel = resolveActorHighestLevel(actorId, "update");
        User user = findUserEntityByIdentifier(identifier);

        if (user.getStatus() == UserStatus.DELETED) {
            throw new BadRequestException("User '" + user.getUsername() + "' is deleted and cannot be updated");
        }

        validateActorPrivilege(user, actorHighestLevel, actorId, "update");

        boolean isChanged = false;

        if (request.roles() != null) {
            Set<String> requestedRoleNames = request.roles().stream()
                    .filter(name -> name != null && !name.isBlank())
                    .map(name -> {
                        String upper = name.strip().toUpperCase(Locale.ROOT);
                        return upper.startsWith("ROLE_") ? upper : "ROLE_" + upper;
                    })
                    .collect(Collectors.toSet());

            Set<String> currentRoleNames = user.getRoles() != null
                    ? user.getRoles().stream().map(Role::getName).collect(Collectors.toSet())
                    : Set.of();

            if (!currentRoleNames.equals(requestedRoleNames)) {
                Set<Role> rolesToAssign = resolveAndValidateRoles(requestedRoleNames, actorHighestLevel, actorId);
                user.setRoles(rolesToAssign);
                isChanged = true;
            }
        }

        if (!isChanged) {
            log.debug("No changes detected for user '{}'. Skipping update.", user.getUsername());
            return UserResponse.fromEntity(user);
        }

        user.setUpdatedBy(actorId);
        User savedUser = userRepository.save(user);
        log.info("User '{}' updated successfully by actor {}", savedUser.getUsername(), actorId);

        tokenService.revokeAllUserTokens(savedUser.getId());

        return UserResponse.fromEntity(savedUser);
    }

    @Override
    @Transactional
    public UserResponse disableUser(
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId) {

        User user = findUserEntityByIdentifier(identifier);
        String username = user.getUsername();

        if (user.getStatus() == UserStatus.DELETED) {
            throw new BadRequestException("User '" + username + "' is deleted and cannot be disabled");
        }

        if (user.getStatus() == UserStatus.DISABLED) {
            log.info("User '{}' is already disabled", username);
            return UserResponse.fromEntity(user);
        }

        int actorHighestLevel = resolveActorHighestLevel(actorId, "disable");
        validateActorPrivilege(user, actorHighestLevel, actorId, "disable");

        user.setStatus(UserStatus.DISABLED);
        user.setUpdatedBy(actorId);
        User savedUser = userRepository.save(user);
        log.info("Marked user '{}' as DISABLED by actor: {}", username, actorId);

        tokenService.revokeAllUserTokens(savedUser.getId());

        return UserResponse.fromEntity(savedUser);
    }

    @Override
    @Transactional
    public UserResponse enableUser(
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId) {

        User user = findUserEntityByIdentifier(identifier);
        String username = user.getUsername();

        if (user.getStatus() == UserStatus.DELETED) {
            throw new BadRequestException("User '" + username + "' is deleted and cannot be enabled");
        }

        if (user.getStatus() == UserStatus.ACTIVE) {
            log.info("User '{}' is already enabled", username);
            return UserResponse.fromEntity(user);
        }

        int actorHighestLevel = resolveActorHighestLevel(actorId, "enable");
        validateActorPrivilege(user, actorHighestLevel, actorId, "enable");

        user.setStatus(UserStatus.ACTIVE);
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setUpdatedBy(actorId);
        User savedUser = userRepository.save(user);
        log.info("Marked user '{}' as ACTIVE by actor: {}", username, actorId);

        return UserResponse.fromEntity(savedUser);
    }

    @Override
    @Transactional
    public UserResponse deleteUser(
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId) {

        User user = findUserEntityByIdentifier(identifier);
        String username = user.getUsername();

        if (user.getStatus() == UserStatus.DELETED) {
            log.info("User '{}' is already deleted", username);
            return UserResponse.fromEntity(user);
        }

        int actorHighestLevel = resolveActorHighestLevel(actorId, "delete");
        validateActorPrivilege(user, actorHighestLevel, actorId, "delete");

        user.setStatus(UserStatus.DELETED);
        user.setUpdatedBy(actorId);
        User savedUser = userRepository.save(user);
        log.info("Marked user '{}' as DELETED by actor: {}", username, actorId);

        tokenService.revokeAllUserTokens(savedUser.getId());

        return UserResponse.fromEntity(savedUser);
    }

    @Override
    @Transactional
    public UserResponse restoreUser(
            @NotBlank(message = "User identifier is required")
            @Size(max = 256, message = "User identifier cannot exceed 256 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId) {

        User user = findUserEntityByIdentifier(identifier);
        String username = user.getUsername();

        if (user.getStatus() != UserStatus.DELETED) {
            throw new BadRequestException("User '" + username + "' is not deleted and cannot be restored");
        }

        int actorHighestLevel = resolveActorHighestLevel(actorId, "restore");
        validateActorPrivilege(user, actorHighestLevel, actorId, "restore");

        user.setStatus(UserStatus.DISABLED);
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setUpdatedBy(actorId);
        User savedUser = userRepository.save(user);
        log.info("Marked user '{}' as RESTORED (DISABLED) by actor: {}", username, actorId);

        return UserResponse.fromEntity(savedUser);
    }

    private int resolveActorHighestLevel(UUID actorId, String action) {
        User actor = userRepository.findWithRolesById(actorId)
                .orElseThrow(() -> new ResourceNotFoundException("Actor user not found with ID: " + actorId));

        int highestLevel = Integer.MAX_VALUE;
        if (actor.getRoles() != null) {
            for (Role role : actor.getRoles()) {
                if (role.getStatus() == RoleStatus.ENABLED && role.getLevel() < highestLevel) {
                    highestLevel = role.getLevel();
                }
            }
        }

        if (highestLevel == Integer.MAX_VALUE) {
            throw new AccessDeniedException("Actor has no active roles and cannot " + action + " users");
        }

        return highestLevel;
    }

    private Set<Role> resolveAndValidateRoles(Set<String> requestedRoleNames, int actorHighestLevel, UUID actorId) {
        if (requestedRoleNames == null || requestedRoleNames.isEmpty()) {
            return new HashSet<>();
        }

        Set<String> canonicalNames = requestedRoleNames.stream()
                .filter(name -> name != null && !name.isBlank())
                .map(name -> {
                    String upper = name.strip().toUpperCase(Locale.ROOT);
                    return upper.startsWith("ROLE_") ? upper : "ROLE_" + upper;
                })
                .collect(Collectors.toSet());

        if (canonicalNames.isEmpty()) {
            return new HashSet<>();
        }

        Set<Role> foundRoles = roleRepository.findAllByNameIn(canonicalNames);
        if (foundRoles.size() != canonicalNames.size()) {
            Set<String> foundNames = foundRoles.stream().map(Role::getName).collect(Collectors.toSet());
            Set<String> missing = canonicalNames.stream().filter(r -> !foundNames.contains(r)).collect(Collectors.toSet());
            throw new ResourceNotFoundException("Roles not found: " + missing);
        }

        Set<String> disabledRoles = foundRoles.stream()
                .filter(r -> r.getStatus() != RoleStatus.ENABLED)
                .map(Role::getName)
                .collect(Collectors.toSet());
        if (!disabledRoles.isEmpty()) {
            throw new AccessDeniedException("Cannot assign disabled roles: " + disabledRoles);
        }

        Set<String> unauthorizedRoles = foundRoles.stream()
                .filter(r -> r.getLevel() <= actorHighestLevel)
                .map(r -> r.getName() + " (level " + r.getLevel() + ")")
                .collect(Collectors.toSet());
        if (!unauthorizedRoles.isEmpty()) {
            log.warn("Actor {} with highest level {} attempted to assign unauthorized roles: {}",
                    actorId, actorHighestLevel, unauthorizedRoles);
            throw new AccessDeniedException("Insufficient privilege: Cannot assign roles with level <= "
                    + actorHighestLevel + ": " + unauthorizedRoles);
        }

        return new HashSet<>(foundRoles);
    }

    private void validateActorPrivilege(User targetUser, int actorHighestLevel, UUID actorId, String action) {
        if (targetUser.getId() != null && targetUser.getId().equals(actorId)) {
            log.warn("Actor {} attempted to {} their own account", actorId, action);
            throw new AccessDeniedException("Cannot " + action + " your own account");
        }

        int targetUserHighestLevel = Integer.MAX_VALUE;
        if (targetUser.getRoles() != null) {
            for (Role role : targetUser.getRoles()) {
                if (role.getLevel() != null && role.getLevel() < targetUserHighestLevel) {
                    targetUserHighestLevel = role.getLevel();
                }
            }
        }

        if (targetUserHighestLevel <= actorHighestLevel) {
            log.warn("Actor {} with highest level {} attempted to {} user '{}' with highest level {}",
                    actorId, actorHighestLevel, targetUser.getUsername(), targetUserHighestLevel);
            throw new AccessDeniedException("Insufficient privilege to " + action + " user '" + targetUser.getUsername()
                    + "' with role level " + targetUserHighestLevel + " (your highest active role level is " + actorHighestLevel + ")");
        }
    }

    @Override
    @Transactional
    public int cleanSoftDeletedUsers() {
        Instant threshold = Instant.now().minus(userProperties.cleanupGracePeriod());

        int totalDeleted = 0;
        int deleted;
        do {
            deleted = userRepository.deleteSoftDeletedUsersBatch(
                    threshold,
                    userProperties.cleanupBatchSize()
            );
            totalDeleted += deleted;
        } while (deleted == userProperties.cleanupBatchSize());

        if (totalDeleted > 0) {
            log.info("Cleaned up {} soft-deleted users from database (older than {})", totalDeleted, threshold);
        }
        return totalDeleted;
    }
}
