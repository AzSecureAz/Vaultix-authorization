package com.vaultix.authorization.security;

public final class AuthSecurityExpressions {

    private AuthSecurityExpressions() {
    }

    public static final String CAN_READ_KEYS = "hasAuthority('key:read')";
    public static final String CAN_ROTATE_KEYS = "hasAuthority('key:rotate')";
}
