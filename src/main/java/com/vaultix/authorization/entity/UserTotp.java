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
import jakarta.persistence.OneToOne;
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
@Table(name = "user_totp")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString(onlyExplicitlyIncluded = true)
public class UserTotp {

    @Id
    @GeneratedValue
    @UuidGenerator(style = UuidGenerator.Style.VERSION_7)
    @Column(name = "id", updatable = false, nullable = false)
    @EqualsAndHashCode.Include
    @ToString.Include
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false, unique = true, updatable = false)
    private User user;

    @Column(name = "encrypted_secret", nullable = false, columnDefinition = "TEXT")
    private String encryptedSecret;

    @Column(name = "verified", nullable = false)
    @Builder.Default
    @ToString.Include
    private boolean verified = false;

    @Column(name = "digits", nullable = false, updatable = false)
    @Builder.Default
    @ToString.Include
    private int digits = 6;

    @Column(name = "period", nullable = false, updatable = false)
    @Builder.Default
    @ToString.Include
    private int period = 30;

    @Column(name = "algorithm", length = 16, nullable = false, updatable = false)
    @Builder.Default
    @ToString.Include
    private String algorithm = "SHA1";

    @Column(name = "last_used_step")
    @ToString.Include
    private Long lastUsedStep;

    @Column(name = "last_used_at")
    @ToString.Include
    private Instant lastUsedAt;

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
        if (this.digits == 0) {
            this.digits = 6;
        }
        if (this.period == 0) {
            this.period = 30;
        }
        if (this.algorithm == null || this.algorithm.isBlank()) {
            this.algorithm = "SHA1";
        }
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = Instant.now();
    }
}
