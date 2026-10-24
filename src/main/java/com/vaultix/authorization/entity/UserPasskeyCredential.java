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
@Table(name = "user_credentials")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString(onlyExplicitlyIncluded = true)
public class UserPasskeyCredential {

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

    @Column(name = "credential_id", length = 512, nullable = false, unique = true, updatable = false)
    @EqualsAndHashCode.Include
    @ToString.Include
    private String credentialId;

    @Column(name = "user_entity_user_id", length = 256, nullable = false, updatable = false)
    @ToString.Include
    private String userEntityUserId;

    @Column(name = "public_key", nullable = false, updatable = false)
    private byte[] publicKey;

    @Column(name = "signature_count", nullable = false)
    @Builder.Default
    @ToString.Include
    private long signatureCount = 0L;

    @Column(name = "uv_initialized", nullable = false)
    @Builder.Default
    @ToString.Include
    private boolean uvInitialized = false;

    @Column(name = "backup_eligible", nullable = false)
    @Builder.Default
    @ToString.Include
    private boolean backupEligible = false;

    @Column(name = "backup_state", nullable = false)
    @Builder.Default
    @ToString.Include
    private boolean backupState = false;

    @Column(name = "authenticator_transports", length = 256)
    @ToString.Include
    private String authenticatorTransports;

    @Column(name = "public_key_credential_type", length = 64, nullable = false, updatable = false)
    @Builder.Default
    @ToString.Include
    private String publicKeyCredentialType = "public-key";

    @Column(name = "attestation_object", updatable = false)
    private byte[] attestationObject;

    @Column(name = "attestation_client_data_json", updatable = false)
    private byte[] attestationClientDataJson;

    @Column(name = "label", length = 128)
    @ToString.Include
    private String label;

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
        if (this.publicKeyCredentialType == null || this.publicKeyCredentialType.isBlank()) {
            this.publicKeyCredentialType = "public-key";
        }
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = Instant.now();
    }
}
