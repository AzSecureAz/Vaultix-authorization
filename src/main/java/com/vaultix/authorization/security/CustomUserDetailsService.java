package com.vaultix.authorization.security;

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
        User user = userRepository.findWithRolesAndPermissionsByUsernameOrEmail(identifier, identifier)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username or email: " + identifier));

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
