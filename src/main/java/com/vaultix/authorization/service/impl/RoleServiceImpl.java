package com.vaultix.authorization.service.impl;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

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
import com.vaultix.authorization.dto.admin.RoleResponse;
import com.vaultix.authorization.entity.Role;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.RoleStatus;
import com.vaultix.authorization.repository.RoleRepository;
import com.vaultix.authorization.repository.UserRepository;
import com.vaultix.authorization.service.RoleService;
import com.vaultix.common.constant.SecurityTopics;
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
    private final StringRedisTemplate stringRedisTemplate;
    private final RoleRevocationService roleRevocationService;
    private final JwtProperties jwtProperties;

    @Override
    @Transactional(readOnly = true)
    public Page<RoleResponse> getAllRoles(Pageable pageable) {
        log.debug("Retrieving all roles with pageable: {}", pageable);
        return roleRepository.findAllWithPermissionsBy(pageable)
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
    public RoleResponse disableRole(String identifier, UUID actorId) {
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
        log.info("Marked role '{}' as DISABLED by actor: {}", roleName, actorId != null ? actorId : "SYSTEM");

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
        log.info("Marked role '{}' as ENABLED by actor: {}", roleName, actorId != null ? actorId : "SYSTEM");

        return RoleResponse.fromEntity(role);
    }

    private void validateActorPrivilege(Role role, UUID actorId, String action) {
        if (actorId == null) {
            return;
        }

        User actor = userRepository.findWithRolesAndPermissionsById(actorId)
                .orElseThrow(() -> new ResourceNotFoundException("Actor user not found with ID: " + actorId));

        int actorHighestLevel = actor.getRoles().stream()
                .filter(r -> r.getStatus() == RoleStatus.ENABLED)
                .mapToInt(Role::getLevel)
                .min()
                .orElse(Integer.MAX_VALUE);

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
        try {
            Instant now = Instant.now();
            stringRedisTemplate.opsForHash().put(RoleRevocationService.KEY, roleName, now.toString());

            long ttlSeconds = jwtProperties.accessTokenExpiration().toSeconds();
            stringRedisTemplate.execute((RedisCallback<Object>) connection -> connection.execute(
                    "HEXPIRE",
                    RoleRevocationService.KEY.getBytes(StandardCharsets.UTF_8),
                    String.valueOf(ttlSeconds).getBytes(StandardCharsets.UTF_8),
                    "FIELDS".getBytes(StandardCharsets.UTF_8),
                    "1".getBytes(StandardCharsets.UTF_8),
                    roleName.getBytes(StandardCharsets.UTF_8)
            ));

            stringRedisTemplate.convertAndSend(SecurityTopics.ROLE_REVOCATION, roleName);
            roleRevocationService.handleRevocationEvent(roleName);
            log.info("Persisted disabled role '{}' to Redis hash '{}' with TTL {}s and broadcasted to topic '{}'",
                    roleName, RoleRevocationService.KEY, ttlSeconds, SecurityTopics.ROLE_REVOCATION);
        } catch (Exception e) {
            log.warn("Failed to update Redis for disabled role '{}'. Other instances will sync on cache TTL expiry", roleName, e);
        }
    }
}
