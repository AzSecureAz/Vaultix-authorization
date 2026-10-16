package com.vaultix.authorization.security;

public final class AuthSecurityExpressions {

    private AuthSecurityExpressions() {
    }

    public static final String CAN_READ_KEYS = "hasAuthority('key:read')";
}
