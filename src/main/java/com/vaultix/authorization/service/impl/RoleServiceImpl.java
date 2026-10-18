package com.vaultix.authorization.service.impl;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import com.vaultix.authorization.config.properties.JwtProperties;
import com.vaultix.authorization.dto.admin.CreateRoleRequest;
import com.vaultix.authorization.dto.admin.RoleResponse;
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
import com.vaultix.common.exception.ResourceConflictException;
import com.vaultix.common.exception.ResourceNotFoundException;
import com.vaultix.common.security.RoleRevocationService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PermissionRepository permissionRepository;
    private final StringRedisTemplate stringRedisTemplate;
    private final RoleRevocationService roleRevocationService;
    private final JwtProperties jwtProperties;

    @Override
    @Transactional(readOnly = true)
    public Page<RoleResponse> getAllRoles(Pageable pageable) {
        Pageable page = (pageable != null) ? pageable : Pageable.unpaged();
        log.debug("Retrieving all roles with pageable: {}", page);
        return roleRepository.findAllWithPermissionsBy(page)
                .map(RoleResponse::fromEntity);
    }

    @Override
    @Transactional(readOnly = true)
    public RoleResponse getRoleByIdentifier(String identifier) {
        Role role = findRoleEntityByIdentifier(identifier);
        return RoleResponse.fromEntity(role);
    }

    @Override
    @Transactional
    public RoleResponse createRole(CreateRoleRequest request, UUID actorId) {
        if (actorId == null) {
            throw new AccessDeniedException("Actor ID is required to create a role");
        }

        User actor = userRepository.findWithRolesAndPermissionsById(actorId)
                .orElseThrow(() -> new ResourceNotFoundException("Actor user not found with ID: " + actorId));

        int actorHighestLevel = Integer.MAX_VALUE;
        Set<String> actorPermissions = new HashSet<>();

        if (actor.getRoles() != null) {
            for (Role r : actor.getRoles()) {
                if (r.getStatus() == RoleStatus.ENABLED) {
                    if (r.getLevel() < actorHighestLevel) {
                        actorHighestLevel = r.getLevel();
                    }
                    if (r.getPermissions() != null) {
                        for (Permission p : r.getPermissions()) {
                            if (p.getStatus() == PermissionStatus.ENABLED) {
                                actorPermissions.add(p.getName());
                            }
                        }
                    }
                }
            }
        }

        if (actorHighestLevel == Integer.MAX_VALUE) {
            throw new AccessDeniedException("Actor has no active roles and cannot create roles");
        }

        if (request.level() <= actorHighestLevel) {
            log.warn("Actor {} with highest level {} attempted to create role '{}' with level {}",
                    actorId, actorHighestLevel, request.name(), request.level());
            throw new AccessDeniedException("Insufficient privilege: Cannot create a role with level " + request.level()
                    + " (must be strictly greater than your highest active role level " + actorHighestLevel + ")");
        }

        Set<Permission> permissionsToAssign = new HashSet<>();
        if (request.permissions() != null && !request.permissions().isEmpty()) {
            Set<String> requestedPermNames = request.permissions().stream()
                    .filter(perm -> perm != null && !perm.isBlank())
                    .map(perm -> perm.strip().toLowerCase(Locale.ROOT))
                    .collect(Collectors.toSet());

            Set<String> unheldPermissions = requestedPermNames.stream()
                    .filter(perm -> !actorPermissions.contains(perm))
                    .collect(Collectors.toSet());

            if (!unheldPermissions.isEmpty()) {
                log.warn("Actor {} attempted to assign permissions they do not possess: {}", actorId, unheldPermissions);
                throw new AccessDeniedException("Insufficient privilege: Cannot assign permissions you do not possess: "
                        + unheldPermissions);
            }

            permissionsToAssign = permissionRepository.findAllByNameIn(requestedPermNames);
            if (permissionsToAssign.size() != requestedPermNames.size()) {
                Set<String> foundNames = permissionsToAssign.stream().map(Permission::getName).collect(Collectors.toSet());
                Set<String> missing = requestedPermNames.stream().filter(p -> !foundNames.contains(p)).collect(Collectors.toSet());
                throw new ResourceNotFoundException("Permissions not found: " + missing);
            }

            Set<String> disabledPerms = permissionsToAssign.stream()
                    .filter(p -> p.getStatus() != PermissionStatus.ENABLED)
                    .map(Permission::getName)
                    .collect(Collectors.toSet());
            if (!disabledPerms.isEmpty()) {
                throw new AccessDeniedException("Cannot assign disabled permissions: " + disabledPerms);
            }
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
    public RoleResponse disableRole(String identifier, UUID actorId) {
        if (actorId == null) {
            throw new AccessDeniedException("Actor ID is required to disable a role");
        }

        Role role = findRoleEntityByIdentifier(identifier);
        String roleName = role.getName();

        if (role.getStatus() == RoleStatus.DISABLED) {
            log.info("Role '{}' is already disabled", roleName);
            return RoleResponse.fromEntity(role);
        }

        validateActorPrivilege(role, actorId, "disable");

        role.setStatus(RoleStatus.DISABLED);
        role.setUpdatedBy(actorId);
        roleRepository.saveAndFlush(role);
        log.info("Marked role '{}' as DISABLED by actor: {}", roleName, actorId);

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

        return RoleResponse.fromEntity(role);
    }

    @Override
    @Transactional
    public RoleResponse enableRole(String identifier, UUID actorId) {
        if (actorId == null) {
            throw new AccessDeniedException("Actor ID is required to enable a role");
        }

        Role role = findRoleEntityByIdentifier(identifier);
        String roleName = role.getName();

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

    private void validateActorPrivilege(Role role, UUID actorId, String action) {
        if (actorId == null) {
            throw new AccessDeniedException("Actor ID is required to " + action + " a role");
        }

        User actor = userRepository.findWithRolesAndPermissionsById(actorId)
                .orElseThrow(() -> new ResourceNotFoundException("Actor user not found with ID: " + actorId));

        int actorHighestLevel = actor.getRoles().stream()
                .filter(r -> r.getStatus() == RoleStatus.ENABLED)
                .mapToInt(Role::getLevel)
                .min()
                .orElse(Integer.MAX_VALUE);

        if (actorHighestLevel == Integer.MAX_VALUE) {
            throw new AccessDeniedException("Actor has no active roles and cannot " + action + " roles");
        }

        if (role.getLevel() <= actorHighestLevel) {
            log.warn("Actor {} with highest level {} attempted to {} role '{}' with level {}",
                    actorId, actorHighestLevel, action, role.getName(), role.getLevel());
            throw new AccessDeniedException("Insufficient privilege to " + action + " role '" + role.getName()
                    + "' with level " + role.getLevel() + " (your highest active role level is " + actorHighestLevel + ")");
        }
    }

    private Role findRoleEntityByIdentifier(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            throw new ResourceNotFoundException("Role identifier cannot be blank");
        }

        String stripped = identifier.strip();
        if (stripped.length() > 64) {
            throw new ResourceNotFoundException("Role not found with identifier: " + stripped);
        }

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
        if (roleName == null || roleName.isBlank()) {
            return;
        }

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
}
