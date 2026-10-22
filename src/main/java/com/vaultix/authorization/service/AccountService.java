package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.ChangeUsernameRequest;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

@Validated
public interface AccountService {

    void changeUsername(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Change username request cannot be null")
            @Valid ChangeUsernameRequest request);
}
