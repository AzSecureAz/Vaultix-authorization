package com.vaultix.authorization.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.vaultix.authorization.entity.UserSocialAccount;
import com.vaultix.authorization.entity.enums.SocialProvider;

@Repository
public interface UserSocialAccountRepository extends JpaRepository<UserSocialAccount, UUID> {

    Optional<UserSocialAccount> findByProviderAndProviderUserId(SocialProvider provider, String providerUserId);

    Optional<UserSocialAccount> findByUserIdAndProvider(UUID userId, SocialProvider provider);

    List<UserSocialAccount> findByUserIdOrderByCreatedAtDesc(UUID userId);

    boolean existsByProviderAndProviderUserId(SocialProvider provider, String providerUserId);

    long countByUserId(UUID userId);

    @Query("SELECT sa FROM UserSocialAccount sa JOIN FETCH sa.user u LEFT JOIN FETCH u.roles r LEFT JOIN FETCH r.permissions WHERE sa.provider = :provider AND sa.providerUserId = :providerUserId")
    Optional<UserSocialAccount> findWithUserByProviderAndProviderUserId(
            @Param("provider") SocialProvider provider,
            @Param("providerUserId") String providerUserId);
}
