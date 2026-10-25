package com.vaultix.authorization.service;

import java.util.UUID;

import org.springframework.validation.annotation.Validated;

import com.vaultix.authorization.dto.SudoResponse;
import com.vaultix.authorization.dto.SudoVerifyRequest;
import com.vaultix.common.util.ClientContextUtil.ClientContext;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

@Validated
public interface AuthSudoService {

    SudoResponse verifySudo(
            @NotNull(message = "User ID cannot be null") UUID userId,
            @NotNull(message = "Session ID cannot be null") UUID sessionId,
            @NotNull(message = "Sudo verify request cannot be null") @Valid SudoVerifyRequest request,
            ClientContext clientContext);

    SudoResponse getStatus(@NotNull(message = "Session ID cannot be null") UUID sessionId);

    void revokeSudo(@NotNull(message = "Session ID cannot be null") UUID sessionId);

    void sendSudoSmsOtp(@NotNull(message = "User ID cannot be null") UUID userId);
}
