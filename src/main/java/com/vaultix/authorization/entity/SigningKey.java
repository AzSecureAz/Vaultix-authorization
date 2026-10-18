package com.vaultix.authorization.entity;

import java.time.Instant;
import java.util.UUID;

import org.hibernate.annotations.UuidGenerator;

import com.vaultix.authorization.entity.enums.KeyStatus;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
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
@Table(name = "signing_keys")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString(onlyExplicitlyIncluded = true)
public class SigningKey {

    @Id
    @GeneratedValue
    @UuidGenerator(style = UuidGenerator.Style.VERSION_7)
    @Column(name = "id", updatable = false, nullable = false)
    @EqualsAndHashCode.Include
    @ToString.Include
    private UUID id;

    @Column(name = "kid", length = 64, nullable = false, unique = true, updatable = false)
    @ToString.Include
    private String kid;

    @Column(name = "algorithm", length = 16, nullable = false, updatable = false)
    @Builder.Default
    @ToString.Include
    private String algorithm = "RS256";

    @Column(name = "key_use", length = 16, nullable = false, updatable = false)
    @Builder.Default
    @ToString.Include
    private String keyUse = "sig";

    @Column(name = "public_key_pem", nullable = false, columnDefinition = "TEXT", updatable = false)
    @ToString.Include
    private String publicKeyPem;

    @Column(name = "encrypted_private_key", nullable = false, columnDefinition = "TEXT", updatable = false)
    private String encryptedPrivateKey;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", length = 16, nullable = false)
    @Builder.Default
    @ToString.Include
    private KeyStatus status = KeyStatus.ACTIVE;

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
            this.status = KeyStatus.ACTIVE;
        }
        if (this.algorithm == null) {
            this.algorithm = "RS256";
        }
        if (this.keyUse == null) {
            this.keyUse = "sig";
        }
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = Instant.now();
    }
}
