package com.vaultix.authorization.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.vaultix.authorization.dto.admin.RoleResponse;

public interface RoleService {

    Page<RoleResponse> getAllRoles(Pageable pageable);

    RoleResponse getRoleByIdentifier(String identifier);
}
