package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.AuthResponse;
import com.vaultix.authorization.dto.oauth2.GoogleLoginRequest;
import com.vaultix.authorization.dto.oauth2.SocialAccountResponse;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

@Validated
public interface GoogleAuthService {

    AuthResponse loginWithGoogle(
            @NotNull(message = "Google login request cannot be null")
            @Valid GoogleLoginRequest request,
            ClientContext clientContext);

    SocialAccountResponse linkGoogle(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Google login request cannot be null")
            @Valid GoogleLoginRequest request);
}
