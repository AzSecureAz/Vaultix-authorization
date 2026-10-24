package com.vaultix.authorization.security.webauthn;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.UUID;

import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.vaultix.authorization.entity.User;
import com.vaultix.authorization.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class JpaPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepository {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public PublicKeyCredentialUserEntity findById(Bytes id) {
        if (id == null) {
            return null;
        }

        UUID userId = bytesToUuid(id);
        if (userId == null) {
            return null;
        }

        return userRepository.findById(userId)
                .map(this::toUserEntity)
                .orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public PublicKeyCredentialUserEntity findByUsername(String username) {
        if (username == null || username.isBlank()) {
            return null;
        }

        String clean = username.strip().toLowerCase(Locale.ROOT);
        try {
            UUID userId = UUID.fromString(clean);
            var userOpt = userRepository.findById(userId);
            if (userOpt.isPresent()) {
                return toUserEntity(userOpt.get());
            }
        } catch (IllegalArgumentException ignored) {
            /* Not a UUID string, fallback to username or email lookup */
        }

        return userRepository.findByUsernameOrEmail(clean, clean)
                .map(this::toUserEntity)
                .orElse(null);
    }

    @Override
    @Transactional
    public void save(PublicKeyCredentialUserEntity userEntity) {
        /* User entity lifecycle is managed by core User and Auth services */
    }

    @Override
    @Transactional
    public void delete(Bytes id) {
        /* User entity lifecycle is managed by core User and Auth services */
    }

    private PublicKeyCredentialUserEntity toUserEntity(User user) {
        String displayName = user.getFullName() != null && !user.getFullName().isBlank()
                ? user.getFullName()
                : user.getUsername();

        return ImmutablePublicKeyCredentialUserEntity.builder()
                .name(user.getUsername())
                .displayName(displayName)
                .id(uuidToBytes(user.getId()))
                .build();
    }

    public static Bytes uuidToBytes(UUID uuid) {
        if (uuid == null) {
            return null;
        }
        ByteBuffer buffer = ByteBuffer.allocate(16);
        buffer.putLong(uuid.getMostSignificantBits());
        buffer.putLong(uuid.getLeastSignificantBits());
        return new Bytes(buffer.array());
    }

    public static UUID bytesToUuid(Bytes bytes) {
        if (bytes == null || bytes.getBytes() == null) {
            return null;
        }
        byte[] raw = bytes.getBytes();
        if (raw.length == 16) {
            ByteBuffer buffer = ByteBuffer.wrap(raw);
            return new UUID(buffer.getLong(), buffer.getLong());
        }
        try {
            return UUID.fromString(new String(raw, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }
}
