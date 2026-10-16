package com.vaultix.authorization.service;

import java.util.UUID;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.LoginRequest;
import com.vaultix.authorization.dto.UserProfileDto;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

public interface AuthService {

    AuthResponse login(LoginRequest request, ClientContext clientContext);

    AuthResponse refreshToken(String rawRefreshToken, ClientContext clientContext);

    void logout(String accessTokenJti);

    UserProfileDto getProfile(UUID userId);
}
