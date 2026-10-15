package com.vaultix.authorization.security;

import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.vaultix.authorization.entity.Role;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.PermissionStatus;
import com.vaultix.authorization.entity.enums.RoleStatus;
import com.vaultix.authorization.entity.enums.UserStatus;

import lombok.Getter;

@Getter
public class CustomUserDetails implements UserDetails {

    private final UUID id;
    private final String username;
    private final String email;
    private final String password;
    private final boolean emailVerified;
    private final boolean mustChangePassword;
    private final UserStatus status;
    private final Instant lockedUntil;
    private final Collection<? extends GrantedAuthority> authorities;

    public CustomUserDetails(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.email = user.getEmail();
        this.password = user.getPasswordHash();
        this.emailVerified = user.isEmailVerified();
        this.mustChangePassword = user.isMustChangePassword();
        this.status = user.getStatus();
        this.lockedUntil = user.getLockedUntil();

        Set<GrantedAuthority> auths = new HashSet<>();
        if (user.getRoles() != null) {
            for (Role role : user.getRoles()) {
                if (role.getStatus() == RoleStatus.ENABLED) {
                    auths.add(new SimpleGrantedAuthority(role.getName()));
                    if (role.getPermissions() != null) {
                        role.getPermissions().stream()
                                .filter(p -> p.getStatus() == PermissionStatus.ENABLED)
                                .forEach(p -> auths.add(new SimpleGrantedAuthority(p.getName())));
                    }
                }
            }
        }
        this.authorities = Set.copyOf(auths);
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
        return status != UserStatus.EXPIRED && status != UserStatus.DELETED;
    }

    @Override
    public boolean isAccountNonLocked() {
        if (status == UserStatus.LOCKED) {
            return lockedUntil != null && lockedUntil.isBefore(Instant.now());
        }
        return status != UserStatus.DELETED;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return status == UserStatus.ACTIVE;
    }
}
