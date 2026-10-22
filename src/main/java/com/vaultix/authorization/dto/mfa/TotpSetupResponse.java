package com.vaultix.authorization.dto.mfa;

public record TotpSetupResponse(
        String secret,
        String otpauthUrl) {

}
