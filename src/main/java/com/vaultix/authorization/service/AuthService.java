package com.vaultix.authorization.service;

import com.vaultix.authorization.dto.LoginRequest;

public interface AuthService {

    String login(LoginRequest request);
}
