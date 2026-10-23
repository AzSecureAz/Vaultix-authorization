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

import com.vaultix.authorization.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    @EntityGraph(attributePaths = {"roles"})
    Page<User> findAllWithRolesBy(Pageable pageable);

    @EntityGraph(attributePaths = {"roles"})
    Optional<User> findWithRolesById(UUID id);

    @EntityGraph(attributePaths = {"roles"})
    Optional<User> findWithRolesByUsernameOrEmail(String username, String email);

    Optional<User> findByUsernameOrEmail(String username, String email);

    @EntityGraph(attributePaths = {"roles", "roles.permissions"})
    Optional<User> findWithRolesAndPermissionsByUsernameOrEmail(String username, String email);

    @EntityGraph(attributePaths = {"roles", "roles.permissions"})
    Optional<User> findWithRolesAndPermissionsByUsername(String username);

    @EntityGraph(attributePaths = {"roles", "roles.permissions"})
    Optional<User> findWithRolesAndPermissionsById(UUID id);

    Optional<User> findByEmail(String email);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByPhoneNumber(String phoneNumber);

    @Modifying
    @Query(value = """
            DELETE FROM users
            WHERE id IN (
                SELECT id FROM users
                WHERE status = 'DELETED'
                  AND updated_at < :threshold
                LIMIT :limit
            )
            """, nativeQuery = true)
    int deleteSoftDeletedUsersBatch(
            @Param("threshold") Instant threshold,
            @Param("limit") int limit);
}
