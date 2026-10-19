package com.vaultix.authorization.repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.vaultix.authorization.entity.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, UUID> {

    @EntityGraph(attributePaths = {"permissions"})
    Page<Role> findAllWithPermissionsBy(Pageable pageable);

    @EntityGraph(attributePaths = {"permissions"})
    Optional<Role> findWithPermissionsById(UUID id);

    @EntityGraph(attributePaths = {"permissions"})
    Optional<Role> findWithPermissionsByName(String name);

    Optional<Role> findByName(String name);

    @Modifying
    @Query(value = """
            DELETE FROM roles
            WHERE id IN (
                SELECT id FROM roles
                WHERE status = 'DELETED'
                  AND updated_at < :threshold
                LIMIT :limit
            )
            """, nativeQuery = true)
    int deleteSoftDeletedRolesBatch(
            @Param("threshold") Instant threshold,
            @Param("limit") int limit);
}
