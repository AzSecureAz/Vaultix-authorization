package com.vaultix.authorization.service.impl;

import java.util.Locale;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.vaultix.authorization.dto.admin.RoleResponse;
import com.vaultix.authorization.entity.Role;
import com.vaultix.authorization.repository.RoleRepository;
import com.vaultix.authorization.service.RoleService;
import com.vaultix.common.exception.ResourceNotFoundException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;

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
}
