package com.vaultix.authorization.service.impl;

import java.util.Locale;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.vaultix.authorization.dto.admin.PermissionResponse;
import com.vaultix.authorization.repository.PermissionRepository;
import com.vaultix.authorization.service.PermissionService;
import com.vaultix.common.exception.ResourceNotFoundException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class PermissionServiceImpl implements PermissionService {

    private final PermissionRepository permissionRepository;

    @Override
    @Transactional(readOnly = true)
    public Page<PermissionResponse> getAllPermissions(Pageable pageable) {
        log.debug("Retrieving all permissions with pageable: {}", pageable);
        return permissionRepository.findAll(pageable)
                .map(PermissionResponse::fromEntity);
    }

    @Override
    @Transactional(readOnly = true)
    public PermissionResponse getPermissionByIdentifier(String identifier) {
        if (identifier == null || identifier.isBlank()) {
            throw new ResourceNotFoundException("Permission identifier cannot be blank");
        }

        String stripped = identifier.strip();

        try {
            UUID id = UUID.fromString(stripped);
            return permissionRepository.findById(id)
                    .map(PermissionResponse::fromEntity)
                    .orElseThrow(() -> new ResourceNotFoundException("Permission not found with identifier: " + stripped));
        } catch (IllegalArgumentException ignored) {
        }

        String normalizedName = stripped.toLowerCase(Locale.ROOT);
        return permissionRepository.findByName(normalizedName)
                .map(PermissionResponse::fromEntity)
                .orElseThrow(() -> new ResourceNotFoundException("Permission not found with identifier: " + stripped));
    }
}
