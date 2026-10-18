package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.vaultix.authorization.dto.admin.CreateRoleRequest;
import com.vaultix.authorization.dto.admin.RoleResponse;

public interface RoleService {

    Page<RoleResponse> getAllRoles(Pageable pageable);

    RoleResponse getRoleByIdentifier(String identifier);

    RoleResponse createRole(CreateRoleRequest request, UUID actorId);

    RoleResponse disableRole(String identifier, UUID actorId);

    RoleResponse enableRole(String identifier, UUID actorId);
}
