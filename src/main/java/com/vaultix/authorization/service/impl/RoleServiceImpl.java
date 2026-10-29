package com.vaultix.authorization.service.impl;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.config.properties.JwtProperties;
import com.vaultix.authorization.config.properties.RoleProperties;
import com.vaultix.authorization.dto.admin.CreateRoleRequest;
import com.vaultix.authorization.dto.admin.RoleResponse;
import com.vaultix.authorization.dto.admin.UpdateRoleRequest;
import com.vaultix.authorization.entity.Permission;
import com.vaultix.authorization.entity.Role;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.PermissionStatus;
import com.vaultix.authorization.entity.enums.RoleStatus;
import com.vaultix.authorization.repository.PermissionRepository;
import com.vaultix.authorization.repository.RoleRepository;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.service.RoleService;
import com.vaultix.common.constant.SecurityTopics;
import com.vaultix.common.exception.BadRequestException;
import com.vaultix.common.exception.ResourceConflictException;
import com.vaultix.common.exception.ResourceNotFoundException;
import com.vaultix.common.security.RoleRevocationService;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@Validated
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PermissionRepository permissionRepository;
    private final StringRedisTemplate stringRedisTemplate;
    private final RoleRevocationService roleRevocationService;
    private final JwtProperties jwtProperties;
    private final RoleProperties roleProperties;

    @Override
    @Transactional(readOnly = true)
    public Page<RoleResponse> getAllRoles(Pageable pageable) {
        Pageable page = (pageable != null && pageable.isPaged())
                ? (pageable.getPageSize() > 50
                ? PageRequest.of(pageable.getPageNumber(), 50, pageable.getSort())
                : pageable)
                : PageRequest.of(0, 10, Sort.by(Sort.Direction.DESC, "createdAt"));

        log.debug("Retrieving all roles with pageable: {}", page);
        return roleRepository.findAllWithPermissionsBy(page)
                .map(RoleResponse::fromEntity);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<RoleResponse> getAssignableRoles(String search, Pageable pageable) {
        Pageable page = (pageable != null && pageable.isPaged())
                ? (pageable.getPageSize() > 50
                ? PageRequest.of(pageable.getPageNumber(), 50, pageable.getSort())
                : pageable)
                : PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "level"));

        if (search != null && !search.isBlank()) {
            String cleanSearch = search.strip();
            log.debug("Searching assignable roles containing '{}' with pageable: {}", cleanSearch, page);
            return roleRepository.findByNameContainingIgnoreCase(cleanSearch, page)
                    .map(RoleResponse::fromEntityWithoutPermissions);
        }

        log.debug("Retrieving all assignable roles with pageable: {}", page);
        return roleRepository.findAll(page)
                .map(RoleResponse::fromEntityWithoutPermissions);
    }

    @Override
    @Transactional(readOnly = true)
    public RoleResponse getRoleByIdentifier(
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier) {

        Role role = findRoleEntityByIdentifier(identifier);
        return RoleResponse.fromEntity(role);
    }

    @Override
    @Transactional
    public RoleResponse createRole(
            @NotNull(message = "Create role request cannot be null")
            @Valid CreateRoleRequest request,
            @NotNull(message = "Actor ID cannot be null") UUID actorId) {

        ActorContext actor = resolveActorContext(actorId, "create");

        if (request.level() <= actor.highestLevel()) {
            log.warn("Actor {} with highest level {} attempted to create role '{}' with level {}",
                    actorId, actor.highestLevel(), request.name(), request.level());
            throw new AccessDeniedException("Insufficient privilege: Cannot create a role with level " + request.level()
                    + " (must be strictly greater than your highest active role level " + actor.highestLevel() + ")");
        }

        Set<Permission> permissionsToAssign = new HashSet<>();
        if (request.permissions() != null && !request.permissions().isEmpty()) {
            Set<String> requestedPermNames = request.permissions().stream()
                    .filter(perm -> perm != null && !perm.isBlank())
                    .map(perm -> perm.strip().toLowerCase(Locale.ROOT))
                    .collect(Collectors.toSet());

            permissionsToAssign = resolvePermissions(requestedPermNames, Set.of(), actor.permissions(), actorId);
        }

        String stripped = request.name().strip();
        String upper = stripped.toUpperCase(Locale.ROOT);
        String canonicalName = upper.startsWith("ROLE_") ? upper : "ROLE_" + upper;

        if (roleRepository.findByName(canonicalName).isPresent()) {
            throw new ResourceConflictException("Role already exists with name: " + canonicalName);
        }

        Role newRole = Role.builder()
                .name(canonicalName)
                .description(request.description() != null ? request.description().strip() : null)
                .level(request.level())
                .status(RoleStatus.ENABLED)
                .permissions(permissionsToAssign)
                .createdBy(actorId)
                .build();

        Role savedRole = roleRepository.save(newRole);
        log.info("Role '{}' with level {} created successfully by actor {}", canonicalName, savedRole.getLevel(), actorId);

        return RoleResponse.fromEntity(savedRole);
    }

    @Override
    @Transactional
    public RoleResponse updateRole(
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @NotNull(message = "Update role request cannot be null")
            @Valid UpdateRoleRequest request,
            @NotNull(message = "Actor ID cannot be null") UUID actorId) {

        ActorContext actor = resolveActorContext(actorId, "update");
        Role role = findRoleEntityByIdentifier(identifier);

        if (role.getStatus() == RoleStatus.DELETED) {
            throw new BadRequestException("Role '" + role.getName() + "' is deleted and cannot be updated");
        }

        if (role.getLevel() <= actor.highestLevel()) {
            log.warn("Actor {} with highest level {} attempted to update role '{}' with level {}",
                    actorId, actor.highestLevel(), role.getName(), role.getLevel());
            throw new AccessDeniedException("Insufficient privilege to update role '" + role.getName()
                    + "' with level " + role.getLevel() + " (your highest active role level is " + actor.highestLevel() + ")");
        }

        boolean isChanged = false;
        boolean needsRevocation = false;

        if (request.description() != null) {
            String strippedDesc = request.description().strip();
            String newDesc = strippedDesc.isBlank() ? null : strippedDesc;
            if (!Objects.equals(role.getDescription(), newDesc)) {
                role.setDescription(newDesc);
                isChanged = true;
            }
        }

        if (request.level() != null && !request.level().equals(role.getLevel())) {
            if (request.level() <= actor.highestLevel()) {
                log.warn("Actor {} with highest level {} attempted to set level to {} on role '{}'",
                        actorId, actor.highestLevel(), request.level(), role.getName());
                throw new AccessDeniedException("Insufficient privilege: Cannot set role level to " + request.level()
                        + " (must be strictly greater than your highest active role level " + actor.highestLevel() + ")");
            }
            role.setLevel(request.level());
            isChanged = true;
        }

        if (request.permissions() != null) {
            Set<String> requestedPermNames = request.permissions().stream()
                    .filter(perm -> perm != null && !perm.isBlank())
                    .map(perm -> perm.strip().toLowerCase(Locale.ROOT))
                    .collect(Collectors.toSet());

            Set<String> currentPermNames = role.getPermissions().stream()
                    .map(Permission::getName)
                    .collect(Collectors.toSet());

            if (!currentPermNames.equals(requestedPermNames)) {
                Set<Permission> permissionsToAssign = resolvePermissions(requestedPermNames, currentPermNames, actor.permissions(), actorId);
                role.setPermissions(permissionsToAssign);
                needsRevocation = true;
                isChanged = true;
            }
        }

        if (!isChanged) {
            log.debug("No changes detected for role '{}'. Skipping update.", role.getName());
            return RoleResponse.fromEntity(role);
        }

        role.setUpdatedBy(actorId);
        Role savedRole = roleRepository.save(role);
        log.info("Role '{}' updated successfully by actor {}", savedRole.getName(), actorId);

        if (needsRevocation) {
            publishRevocationAfterCommit(savedRole.getName());
        }

        return RoleResponse.fromEntity(savedRole);
    }

    @Override
    @Transactional
    public RoleResponse disableRole(
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId) {

        Role role = findRoleEntityByIdentifier(identifier);
        String roleName = role.getName();

        if (role.getStatus() == RoleStatus.DELETED) {
            throw new BadRequestException("Role '" + roleName + "' is deleted and cannot be disabled");
        }

        if (role.getStatus() == RoleStatus.DISABLED) {
            log.info("Role '{}' is already disabled", roleName);
            return RoleResponse.fromEntity(role);
        }

        validateActorPrivilege(role, actorId, "disable");

        role.setStatus(RoleStatus.DISABLED);
        role.setUpdatedBy(actorId);
        roleRepository.save(role);
        log.info("Marked role '{}' as DISABLED by actor: {}", roleName, actorId);

        publishRevocationAfterCommit(roleName);

        return RoleResponse.fromEntity(role);
    }

    @Override
    @Transactional
    public RoleResponse enableRole(
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId) {

        Role role = findRoleEntityByIdentifier(identifier);
        String roleName = role.getName();

        if (role.getStatus() == RoleStatus.DELETED) {
            throw new BadRequestException("Role '" + roleName + "' is deleted and cannot be enabled");
        }

        if (role.getStatus() == RoleStatus.ENABLED) {
            log.info("Role '{}' is already enabled", roleName);
            return RoleResponse.fromEntity(role);
        }

        validateActorPrivilege(role, actorId, "enable");

        role.setStatus(RoleStatus.ENABLED);
        role.setUpdatedBy(actorId);
        roleRepository.save(role);
        log.info("Marked role '{}' as ENABLED by actor: {}", roleName, actorId);

        return RoleResponse.fromEntity(role);
    }

    @Override
    @Transactional
    public RoleResponse deleteRole(
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId) {

        Role role = findRoleEntityByIdentifier(identifier);
        String roleName = role.getName();

        if (role.getStatus() == RoleStatus.DELETED) {
            log.info("Role '{}' is already deleted", roleName);
            return RoleResponse.fromEntity(role);
        }

        validateActorPrivilege(role, actorId, "delete");

        role.setStatus(RoleStatus.DELETED);
        role.setUpdatedBy(actorId);
        roleRepository.save(role);
        log.info("Marked role '{}' as DELETED by actor: {}", roleName, actorId);

        publishRevocationAfterCommit(roleName);

        return RoleResponse.fromEntity(role);
    }

    @Override
    @Transactional
    public RoleResponse restoreRole(
            @NotBlank(message = "Role identifier is required")
            @Size(max = 64, message = "Role identifier cannot exceed 64 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId) {

        Role role = findRoleEntityByIdentifier(identifier);
        String roleName = role.getName();

        if (role.getStatus() != RoleStatus.DELETED) {
            throw new BadRequestException("Role '" + roleName + "' is not deleted and cannot be restored");
        }

        validateActorPrivilege(role, actorId, "restore");

        role.setStatus(RoleStatus.DISABLED);
        role.setUpdatedBy(actorId);
        roleRepository.save(role);
        log.info("Marked role '{}' as RESTORED (DISABLED) by actor: {}", roleName, actorId);

        return RoleResponse.fromEntity(role);
    }

    private void validateActorPrivilege(Role role, UUID actorId, String action) {
        ActorContext actor = resolveActorContext(actorId, action);
        if (role.getLevel() <= actor.highestLevel()) {
            log.warn("Actor {} with highest level {} attempted to {} role '{}' with level {}",
                    actorId, actor.highestLevel(), action, role.getName(), role.getLevel());
            throw new AccessDeniedException("Insufficient privilege to " + action + " role '" + role.getName()
                    + "' with level " + role.getLevel() + " (your highest active role level is " + actor.highestLevel() + ")");
        }
    }

    private ActorContext resolveActorContext(UUID actorId, String action) {
        User actor = userRepository.findWithRolesAndPermissionsById(actorId)
                .orElseThrow(() -> new ResourceNotFoundException("Actor user not found with ID: " + actorId));

        int highestLevel = Integer.MAX_VALUE;
        Set<String> permissions = new HashSet<>();

        if (actor.getRoles() != null) {
            for (Role r : actor.getRoles()) {
                if (r.getStatus() == RoleStatus.ENABLED) {
                    if (r.getLevel() < highestLevel) {
                        highestLevel = r.getLevel();
                    }
                    if (r.getPermissions() != null) {
                        for (Permission p : r.getPermissions()) {
                            if (p.getStatus() == PermissionStatus.ENABLED) {
                                permissions.add(p.getName());
                            }
                        }
                    }
                }
            }
        }

        if (highestLevel == Integer.MAX_VALUE) {
            throw new AccessDeniedException("Actor has no active roles and cannot " + action + " roles");
        }

        return ActorContext.builder()
                .highestLevel(highestLevel)
                .permissions(permissions)
                .build();
    }

    private Set<Permission> resolvePermissions(
            Set<String> requestedNames,
            Set<String> currentRolePermNames,
            Set<String> actorPermissions,
            UUID actorId) {

        if (requestedNames.isEmpty()) {
            return new HashSet<>();
        }

        Set<String> newlyAddedPermissions = requestedNames.stream()
                .filter(perm -> !currentRolePermNames.contains(perm))
                .collect(Collectors.toSet());

        Set<String> unheldPermissions = newlyAddedPermissions.stream()
                .filter(perm -> !actorPermissions.contains(perm))
                .collect(Collectors.toSet());

        if (!unheldPermissions.isEmpty()) {
            log.warn("Actor {} attempted to assign permissions they do not possess: {}", actorId, unheldPermissions);
            throw new AccessDeniedException("Insufficient privilege: Cannot assign permissions you do not possess: "
                    + unheldPermissions);
        }

        Set<Permission> permissionsToAssign = permissionRepository.findAllByNameIn(requestedNames);
        if (permissionsToAssign.size() != requestedNames.size()) {
            Set<String> foundNames = permissionsToAssign.stream().map(Permission::getName).collect(Collectors.toSet());
            Set<String> missing = requestedNames.stream().filter(p -> !foundNames.contains(p)).collect(Collectors.toSet());
            throw new ResourceNotFoundException("Permissions not found: " + missing);
        }

        Set<String> disabledPerms = permissionsToAssign.stream()
                .filter(p -> p.getStatus() != PermissionStatus.ENABLED)
                .map(Permission::getName)
                .collect(Collectors.toSet());
        if (!disabledPerms.isEmpty()) {
            throw new AccessDeniedException("Cannot assign disabled permissions: " + disabledPerms);
        }

        return new HashSet<>(permissionsToAssign);
    }

    private void publishRevocationAfterCommit(String roleName) {
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    broadcastRoleRevocation(roleName);
                }
            });
        } else {
            broadcastRoleRevocation(roleName);
        }
    }

    @Builder
    private record ActorContext(int highestLevel, Set<String> permissions) {

    }

    private Role findRoleEntityByIdentifier(String identifier) {
        String stripped = identifier.strip();

        try {
            UUID id = UUID.fromString(stripped);
            return roleRepository.findWithPermissionsById(id)
                    .orElseThrow(() -> new ResourceNotFoundException("Role not found with identifier: " + stripped));
        } catch (IllegalArgumentException ignored) {
        }

        String upper = stripped.toUpperCase(Locale.ROOT);
        String roleName = upper.startsWith("ROLE_") ? upper : "ROLE_" + upper;

        return roleRepository.findWithPermissionsByName(roleName)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found with identifier: " + stripped));
    }

    private void broadcastRoleRevocation(String roleName) {
        String cleanName = roleName.strip().toUpperCase(Locale.ROOT);

        try {
            Instant now = Instant.now();
            stringRedisTemplate.opsForHash().put(RoleRevocationService.KEY, cleanName, now.toString());

            long ttlSeconds = jwtProperties.accessTokenExpiration().toSeconds();
            stringRedisTemplate.execute((RedisCallback<Object>) connection -> connection.execute(
                    "HEXPIRE",
                    RoleRevocationService.KEY.getBytes(StandardCharsets.UTF_8),
                    String.valueOf(ttlSeconds).getBytes(StandardCharsets.UTF_8),
                    "FIELDS".getBytes(StandardCharsets.UTF_8),
                    "1".getBytes(StandardCharsets.UTF_8),
                    cleanName.getBytes(StandardCharsets.UTF_8)
            ));

            stringRedisTemplate.convertAndSend(SecurityTopics.ROLE_REVOCATION, cleanName);
            roleRevocationService.handleRevocationEvent(cleanName);
            log.info("Persisted disabled role '{}' to Redis hash '{}' with TTL {}s and broadcasted to topic '{}'",
                    cleanName, RoleRevocationService.KEY, ttlSeconds, SecurityTopics.ROLE_REVOCATION);
        } catch (Exception e) {
            log.warn("Failed to update Redis for disabled role '{}'. Other instances will sync on cache TTL expiry", cleanName, e);
        }
    }

    @Override
    @Transactional
    public int cleanSoftDeletedRoles() {
        Instant threshold = Instant.now().minus(roleProperties.cleanupGracePeriod());

        int totalDeleted = 0;
        int deleted;
        do {
            deleted = roleRepository.deleteSoftDeletedRolesBatch(
                    threshold,
                    roleProperties.cleanupBatchSize()
            );
            totalDeleted += deleted;
        } while (deleted == roleProperties.cleanupBatchSize());

        if (totalDeleted > 0) {
            log.info("Cleaned up {} soft-deleted roles from database (older than {})", totalDeleted, threshold);
        }
        return totalDeleted;
    }
}
