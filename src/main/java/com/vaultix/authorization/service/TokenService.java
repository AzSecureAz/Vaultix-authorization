package com.vaultix.authorization.service;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.security.CustomUserDetails;

public interface TokenService {

    AuthResponse issueTokens(CustomUserDetails userDetails, String deviceInfo, String ipAddress);

    AuthResponse refreshTokens(String rawRefreshToken, String deviceInfo, String ipAddress);
}
