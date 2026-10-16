package com.vaultix.authorization.service;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.security.CustomUserDetails;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

public interface TokenService {

    AuthResponse issueTokens(CustomUserDetails userDetails, ClientContext clientContext);

    AuthResponse refreshTokens(String rawRefreshToken, ClientContext clientContext);

    void logout(String accessTokenJti);
}
