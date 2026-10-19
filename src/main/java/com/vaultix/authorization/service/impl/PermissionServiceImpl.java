package com.vaultix.authorization.service.impl;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import com.vaultix.authorization.config.properties.JwtProperties;
import com.vaultix.authorization.dto.admin.PermissionResponse;
import com.vaultix.authorization.entity.Permission;
import com.vaultix.authorization.entity.enums.PermissionStatus;
import com.vaultix.authorization.repository.PermissionRepository;
import com.vaultix.authorization.service.PermissionService;
import com.vaultix.common.constant.SecurityTopics;
import com.vaultix.common.exception.ResourceNotFoundException;
import com.vaultix.common.security.PermissionRevocationService;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class PermissionServiceImpl implements PermissionService {

    private final PermissionRepository permissionRepository;
    private final StringRedisTemplate stringRedisTemplate;
    private final PermissionRevocationService permissionRevocationService;
    private final JwtProperties jwtProperties;

    @Override
    @Transactional(readOnly = true)
    public Page<PermissionResponse> getAllPermissions(Pageable pageable) {
        Pageable page = (pageable != null) ? pageable : Pageable.unpaged();
        log.debug("Retrieving all permissions with pageable: {}", page);
        return permissionRepository.findAll(page)
                .map(PermissionResponse::fromEntity);
    }

    @Override
    @Transactional(readOnly = true)
    public PermissionResponse getPermissionByIdentifier(
            @NotBlank(message = "Permission identifier is required")
            @Size(max = 128, message = "Permission identifier cannot exceed 128 characters") String identifier) {

        Permission permission = findPermissionEntityByIdentifier(identifier);
        return PermissionResponse.fromEntity(permission);
    }

    @Override
    @Transactional
    public PermissionResponse disablePermission(
            @NotBlank(message = "Permission identifier is required")
            @Size(max = 128, message = "Permission identifier cannot exceed 128 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId) {

        Permission permission = findPermissionEntityByIdentifier(identifier);
        String permissionName = permission.getName();

        if (permission.getStatus() == PermissionStatus.DISABLED) {
            log.info("Permission '{}' is already disabled", permissionName);
            return PermissionResponse.fromEntity(permission);
        }

        permission.setStatus(PermissionStatus.DISABLED);
        permission.setUpdatedBy(actorId);
        permissionRepository.save(permission);
        log.info("Marked permission '{}' as DISABLED by actor: {}", permissionName, actorId);

        publishRevocationAfterCommit(permissionName);

        return PermissionResponse.fromEntity(permission);
    }

    @Override
    @Transactional
    public PermissionResponse enablePermission(
            @NotBlank(message = "Permission identifier is required")
            @Size(max = 128, message = "Permission identifier cannot exceed 128 characters") String identifier,
            @NotNull(message = "Actor ID cannot be null") UUID actorId) {

        Permission permission = findPermissionEntityByIdentifier(identifier);
        String permissionName = permission.getName();

        if (permission.getStatus() == PermissionStatus.ENABLED) {
            log.info("Permission '{}' is already enabled", permissionName);
            return PermissionResponse.fromEntity(permission);
        }

        permission.setStatus(PermissionStatus.ENABLED);
        permission.setUpdatedBy(actorId);
        permissionRepository.save(permission);
        log.info("Marked permission '{}' as ENABLED by actor: {}", permissionName, actorId);

        return PermissionResponse.fromEntity(permission);
    }

    private Permission findPermissionEntityByIdentifier(String identifier) {
        String stripped = identifier.strip();

        try {
            UUID id = UUID.fromString(stripped);
            return permissionRepository.findById(id)
                    .orElseThrow(() -> new ResourceNotFoundException("Permission not found with identifier: " + stripped));
        } catch (IllegalArgumentException ignored) {
        }

        String normalized = stripped.toLowerCase(Locale.ROOT);
        return permissionRepository.findByName(normalized)
                .orElseThrow(() -> new ResourceNotFoundException("Permission not found with identifier: " + stripped));
    }

    private void broadcastPermissionRevocation(String permissionName) {
        String cleanName = permissionName.strip().toLowerCase(Locale.ROOT);

        try {
            Instant now = Instant.now();
            stringRedisTemplate.opsForHash().put(PermissionRevocationService.KEY, cleanName, now.toString());

            long ttlSeconds = jwtProperties.accessTokenExpiration().toSeconds();
            stringRedisTemplate.execute((RedisCallback<Object>) connection -> connection.execute(
                    "HEXPIRE",
                    PermissionRevocationService.KEY.getBytes(StandardCharsets.UTF_8),
                    String.valueOf(ttlSeconds).getBytes(StandardCharsets.UTF_8),
                    "FIELDS".getBytes(StandardCharsets.UTF_8),
                    "1".getBytes(StandardCharsets.UTF_8),
                    cleanName.getBytes(StandardCharsets.UTF_8)
            ));

            stringRedisTemplate.convertAndSend(SecurityTopics.PERMISSION_REVOCATION, cleanName);
            permissionRevocationService.handleRevocationEvent(cleanName);
            log.info("Persisted disabled permission '{}' to Redis hash '{}' with TTL {}s and broadcasted to topic '{}'",
                    cleanName, PermissionRevocationService.KEY, ttlSeconds, SecurityTopics.PERMISSION_REVOCATION);
        } catch (Exception e) {
            log.warn("Failed to update Redis for disabled permission '{}'. Other instances will sync on cache TTL expiry", cleanName, e);
        }
    }

    private void publishRevocationAfterCommit(String permissionName) {
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    broadcastPermissionRevocation(permissionName);
                }
            });
        } else {
            broadcastPermissionRevocation(permissionName);
        }
    }
}
