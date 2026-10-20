package com.vaultix.authorization.bootstrap;

import java.util.HashSet;
import java.util.Set;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.vaultix.authorization.config.properties.AdminBootstrapProperties;
import com.vaultix.authorization.entity.Role;
import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.entity.enums.UserStatus;
import com.vaultix.authorization.repository.RoleRepository;
import com.vaultix.authorization.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class AdminUserInitializer implements ApplicationRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AdminBootstrapProperties adminProps;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!adminProps.enabled()) {
            log.info("Admin user bootstrapping is disabled.");
            return;
        }

        if (userRepository.existsByUsername(adminProps.username())) {
            log.info("Admin user with username '{}' already exists. Skipping bootstrapping.", adminProps.username());
            return;
        }

        if (userRepository.existsByEmail(adminProps.email())) {
            log.info("Admin user with email '{}' already exists. Skipping bootstrapping.", adminProps.email());
            return;
        }

        Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                .orElseThrow(() -> new IllegalStateException("ROLE_ADMIN role not found. Ensure Flyway migrations have executed."));

        User admin = User.builder()
                .username(adminProps.username())
                .email(adminProps.email())
                .passwordHash(null)
                .fullName(adminProps.fullName())
                .status(UserStatus.ACTIVE)
                .emailVerified(true)
                .roles(new HashSet<>(Set.of(adminRole)))
                .build();

        userRepository.save(admin);

        log.info("Initial admin user '{}' ({}) successfully bootstrapped without password. Initial password must be set via password reset.",
                adminProps.username(), adminProps.email());
    }
}
