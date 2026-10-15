package com.vaultix.authorization.entity;

import java.time.Instant;
import java.util.UUID;

import org.hibernate.annotations.UuidGenerator;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
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
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString(onlyExplicitlyIncluded = true)
public class RefreshToken {

    @Id
    @GeneratedValue
    @UuidGenerator(style = UuidGenerator.Style.VERSION_7)
    @Column(name = "id", updatable = false, nullable = false)
    @EqualsAndHashCode.Include
    @ToString.Include
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @Column(name = "refresh_token_jti", nullable = false, unique = true, updatable = false)
    @ToString.Include
    private UUID refreshTokenJti;

    @Column(name = "access_token_jti", nullable = false, unique = true)
    @ToString.Include
    private UUID accessTokenJti;

    @Column(name = "gen", nullable = false)
    @Builder.Default
    @ToString.Include
    private int gen = 1;

    @Column(name = "device_info", length = 256, nullable = false)
    @ToString.Include
    private String deviceInfo;

    @Column(name = "ip_address", length = 64, nullable = false)
    @ToString.Include
    private String ipAddress;

    @Column(name = "revoked", nullable = false)
    @Builder.Default
    @ToString.Include
    private boolean revoked = false;

    @Column(name = "revoked_at")
    @ToString.Include
    private Instant revokedAt;

    @Column(name = "expires_at", nullable = false)
    @ToString.Include
    private Instant expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    @ToString.Include
    private Instant createdAt;

    @Column(name = "updated_at")
    @ToString.Include
    private Instant updatedAt;

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = Instant.now();
        }
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = Instant.now();
    }
}
