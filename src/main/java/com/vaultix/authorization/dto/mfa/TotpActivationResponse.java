package com.vaultix.authorization.dto.mfa;

import java.util.List;

public record TotpActivationResponse(List<String> recoveryCodes) {

}
