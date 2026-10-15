package com.vaultix.authorization.entity;

import java.time.Instant;
import java.util.UUID;

import org.hibernate.annotations.UuidGenerator;

import com.vaultix.authorization.entity.enums.PermissionStatus;

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
@Table(name = "permissions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@ToString(onlyExplicitlyIncluded = true)
public class Permission {

    @Id
    @GeneratedValue
    @UuidGenerator(style = UuidGenerator.Style.VERSION_7)
    @Column(name = "id", updatable = false, nullable = false)
    @EqualsAndHashCode.Include
    @ToString.Include
    private UUID id;

    @Column(name = "name", length = 128, nullable = false, unique = true)
    @ToString.Include
    private String name;

    @Column(name = "description", length = 256)
    @ToString.Include
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", length = 16, nullable = false)
    @Builder.Default
    @ToString.Include
    private PermissionStatus status = PermissionStatus.ENABLED;

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
            this.status = PermissionStatus.ENABLED;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = Instant.now();
    }
}
