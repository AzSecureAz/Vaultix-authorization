package com.vaultix.authorization.security;

import java.util.Locale;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService, UserDetailsPasswordService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String identifier) throws UsernameNotFoundException {
        if (identifier == null || identifier.isBlank()) {
            throw new UsernameNotFoundException("Identifier cannot be null or blank");
        }

        String normalized = identifier.strip().toLowerCase(Locale.ROOT);
        User user = userRepository.findWithRolesAndPermissionsByUsernameOrEmail(normalized, normalized)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username or email: " + normalized));

        return new CustomUserDetails(user);
    }

    @Override
    @Transactional
    public UserDetails updatePassword(UserDetails userDetails, String newPasswordHash) {
        User user = userRepository.findWithRolesAndPermissionsByUsername(userDetails.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + userDetails.getUsername()));

        user.setPasswordHash(newPasswordHash);
        userRepository.save(user);

        return new CustomUserDetails(user);
    }
}
