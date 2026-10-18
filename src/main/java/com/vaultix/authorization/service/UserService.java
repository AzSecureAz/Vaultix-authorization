package com.vaultix.authorization.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.vaultix.authorization.dto.admin.UserResponse;

public interface UserService {

    Page<UserResponse> getAllUsers(Pageable pageable);

    UserResponse getUserByIdentifier(String identifier);
}
