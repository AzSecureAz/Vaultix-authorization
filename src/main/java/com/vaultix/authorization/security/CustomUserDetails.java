package com.vaultix.authorization.security;

import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.vaultix.authorization.entity.Permission;
import com.vaultix.authorization.entity.Role;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.PermissionStatus;
import com.vaultix.authorization.entity.enums.RoleStatus;
import com.vaultix.authorization.entity.enums.UserStatus;

import lombok.Getter;
import lombok.ToString;

@Getter
@ToString(exclude = "password")
public class CustomUserDetails implements UserDetails {

    private final UUID id;
    private final String username;
    private final String password;
    private final UserStatus status;
    private final Instant lockedUntil;
    private final Collection<? extends GrantedAuthority> authorities;
    private final Map<String, Set<String>> rolePermissions;

    public CustomUserDetails(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.password = user.getPasswordHash();
        this.status = user.getStatus();
        this.lockedUntil = user.getLockedUntil();

        Map<String, Set<String>> rolePermMap = new HashMap<>();
        Set<GrantedAuthority> auths = new HashSet<>();
        if (user.getRoles() != null) {
            for (Role role : user.getRoles()) {
                if (role.getStatus() == RoleStatus.ENABLED) {
                    auths.add(new SimpleGrantedAuthority(role.getName()));
                    Set<String> perms = new HashSet<>();
                    if (role.getPermissions() != null) {
                        for (Permission p : role.getPermissions()) {
                            if (p.getStatus() == PermissionStatus.ENABLED) {
                                perms.add(p.getName());
                                auths.add(new SimpleGrantedAuthority(p.getName()));
                            }
                        }
                    }
                    rolePermMap.put(role.getName(), Set.copyOf(perms));
                }
            }
        }
        this.authorities = Set.copyOf(auths);
        this.rolePermissions = Map.copyOf(rolePermMap);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        if (status == UserStatus.LOCKED) {
            return lockedUntil != null && lockedUntil.isBefore(Instant.now());
        }
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        if (status == UserStatus.ACTIVE) {
            return true;
        }
        if (status == UserStatus.LOCKED) {
            return lockedUntil != null && lockedUntil.isBefore(Instant.now());
        }
        return false;
    }
}
