package com.vaultix.authorization.security;

public final class AuthSecurityExpressions {

    private AuthSecurityExpressions() {
    }

    public static final String CAN_CREATE_USER = "hasAuthority('user:create')";
    public static final String CAN_READ_USER = "hasAuthority('user:read')";
    public static final String CAN_UPDATE_USER = "hasAuthority('user:update')";
    public static final String CAN_DELETE_USER = "hasAuthority('user:delete')";

    public static final String CAN_CREATE_ROLE = "hasAuthority('role:create')";
    public static final String CAN_READ_ROLE = "hasAuthority('role:read')";
    public static final String CAN_UPDATE_ROLE = "hasAuthority('role:update')";
    public static final String CAN_DELETE_ROLE = "hasAuthority('role:delete')";

    public static final String CAN_READ_PERMISSION = "hasAuthority('permission:read')";

    public static final String CAN_READ_KEY = "hasAuthority('key:read')";
    public static final String CAN_ROTATE_KEY = "hasAuthority('key:rotate')";
}
