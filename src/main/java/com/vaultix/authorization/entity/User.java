package com.vaultix.authorization.entity;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.hibernate.annotations.UuidGenerator;

import com.vaultix.authorization.entity.enums.UserStatus;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString(onlyExplicitlyIncluded = true)
public class User {

    @Id
    @GeneratedValue
    @UuidGenerator(style = UuidGenerator.Style.VERSION_7)
    @Column(name = "id", updatable = false, nullable = false)
    @EqualsAndHashCode.Include
    @ToString.Include
    private UUID id;

    @Column(name = "username", length = 128, nullable = false, unique = true)
    @ToString.Include
    private String username;

    @Column(name = "email", length = 256, nullable = false, unique = true)
    @ToString.Include
    private String email;

    @Column(name = "password_hash", length = 256)
    private String passwordHash;

    @Column(name = "full_name", length = 256)
    @ToString.Include
    private String fullName;

    @Column(name = "phone_number", length = 32)
    @ToString.Include
    private String phoneNumber;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", length = 16, nullable = false)
    @Builder.Default
    @ToString.Include
    private UserStatus status = UserStatus.ACTIVE;

    @Column(name = "email_verified", nullable = false)
    @Builder.Default
    @ToString.Include
    private boolean emailVerified = false;

    @Column(name = "must_change_password", nullable = false)
    @Builder.Default
    @ToString.Include
    private boolean mustChangePassword = false;

    @Column(name = "mfa_enabled", nullable = false)
    @Builder.Default
    @ToString.Include
    private boolean mfaEnabled = false;

    @Column(name = "passkey_enabled", nullable = false)
    @Builder.Default
    @ToString.Include
    private boolean passkeyEnabled = false;

    @Column(name = "has_social_accounts", nullable = false)
    @Builder.Default
    @ToString.Include
    private boolean hasSocialAccounts = false;

    @Column(name = "failed_login_attempts", nullable = false)
    @Builder.Default
    @ToString.Include
    private int failedLoginAttempts = 0;

    @Column(name = "locked_until")
    @ToString.Include
    private Instant lockedUntil;

    @Column(name = "last_login_at")
    @ToString.Include
    private Instant lastLoginAt;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    @Column(name = "created_at", nullable = false, updatable = false)
    @ToString.Include
    private Instant createdAt;

    @Column(name = "created_by", updatable = false)
    @ToString.Include
    private UUID createdBy;

    @Column(name = "updated_at")
    @ToString.Include
    private Instant updatedAt;

    @Column(name = "updated_by")
    @ToString.Include
    private UUID updatedBy;

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = Instant.now();
        }
        if (this.status == null) {
            this.status = UserStatus.ACTIVE;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = Instant.now();
    }
}
