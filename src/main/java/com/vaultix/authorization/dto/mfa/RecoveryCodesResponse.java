package com.vaultix.authorization.dto.mfa;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record RecoveryCodesResponse(
        List<String> recoveryCodes) {

}
