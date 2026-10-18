package com.vaultix.authorization.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
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

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);
}
