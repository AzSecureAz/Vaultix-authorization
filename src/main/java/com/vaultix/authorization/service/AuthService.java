package com.vaultix.authorization.service;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.LoginRequest;

public interface AuthService {

    AuthResponse login(LoginRequest request, String deviceInfo, String ipAddress);

    AuthResponse refreshToken(String rawRefreshToken, String deviceInfo, String ipAddress);
}
