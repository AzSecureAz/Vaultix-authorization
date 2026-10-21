package com.vaultix.authorization.security;

import com.vaultix.common.security.CommonSecurityExpressions;

public final class AuthSecurityExpressions {

    private AuthSecurityExpressions() {
    }

    public static final String CAN_READ_KEYS = "hasAuthority('key:read')";
    public static final String CAN_ROTATE_KEYS = "hasAuthority('key:rotate')";
    public static final String CAN_READ_PERMISSIONS = CommonSecurityExpressions.IS_ADMIN + " or hasAuthority('permission:read')";
    public static final String CAN_READ_ROLES = "hasAuthority('role:read')";
    public static final String CAN_CREATE_ROLES = "hasAuthority('role:create')";
    public static final String CAN_UPDATE_ROLES = "hasAuthority('role:update')";
    public static final String CAN_READ_USERS = "hasAuthority('user:read')";
    public static final String CAN_CREATE_USERS = "hasAuthority('user:create')";
    public static final String CAN_UPDATE_USERS = "hasAuthority('user:update')";
    public static final String CAN_DELETE_USERS = "hasAuthority('user:delete')";
}
