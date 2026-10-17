package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.vaultix.authorization.dto.admin.PermissionResponse;

public interface PermissionService {

    Page<PermissionResponse> getAllPermissions(Pageable pageable);

    PermissionResponse getPermissionByIdentifier(String identifier);

    PermissionResponse disablePermission(String identifier, UUID actorId);

    PermissionResponse enablePermission(String identifier, UUID actorId);
}
