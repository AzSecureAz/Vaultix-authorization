package com.vaultix.authorization.service;

import java.util.UUID;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.LoginRequest;
import com.vaultix.authorization.dto.UserProfileDto;

public interface AuthService {

    AuthResponse login(LoginRequest request, String deviceInfo, String ipAddress);

    AuthResponse refreshToken(String rawRefreshToken, String deviceInfo, String ipAddress);

    void logout(String accessTokenJti);

    UserProfileDto getProfile(UUID userId);
}
