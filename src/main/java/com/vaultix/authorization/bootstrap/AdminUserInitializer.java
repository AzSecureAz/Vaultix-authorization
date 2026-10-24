package com.vaultix.authorization.bootstrap;

import java.util.HashSet;
import java.util.Locale;
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

        String cleanUsername = adminProps.username().strip().toLowerCase(Locale.ROOT);
        String cleanEmail = adminProps.email().strip().toLowerCase(Locale.ROOT);
        String cleanFullName = (adminProps.fullName() != null && !adminProps.fullName().isBlank())
                ? adminProps.fullName().strip()
                : null;

        if (userRepository.existsByUsername(cleanUsername)) {
            log.info("Admin user with username '{}' already exists. Skipping bootstrapping.", cleanUsername);
            return;
        }

        if (userRepository.existsByEmail(cleanEmail)) {
            log.info("Admin user with email '{}' already exists. Skipping bootstrapping.", cleanEmail);
            return;
        }

        Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                .orElseThrow(() -> new IllegalStateException("ROLE_ADMIN role not found. Ensure Flyway migrations have executed."));

        User admin = User.builder()
                .username(cleanUsername)
                .email(cleanEmail)
                .passwordHash(null)
                .fullName(cleanFullName)
                .status(UserStatus.ACTIVE)
                .emailVerified(true)
                .phoneNumberVerified(false)
                .roles(new HashSet<>(Set.of(adminRole)))
                .build();

        userRepository.save(admin);

        log.info("Initial admin user '{}' ({}) successfully bootstrapped without password. Initial password must be set via password reset.",
                cleanUsername, cleanEmail);
    }
}
