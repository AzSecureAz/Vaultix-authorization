package com.vaultix.authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;

import com.vaultix.authorization.service.SigningKeyService;
import com.vaultix.common.constant.SecurityTopics;
import com.vaultix.common.security.PermissionRevocationService;
import com.vaultix.common.security.RoleRevocationService;
import com.vaultix.common.util.RedisPubSubHelper;

@Configuration
public class RedisPubSubConfig {

    @Bean
    public RedisMessageListenerContainer redisMessageListenerContainer(
            RedisConnectionFactory connectionFactory,
            SigningKeyService signingKeyService,
            PermissionRevocationService permissionRevocationService,
            RoleRevocationService roleRevocationService) {
        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);

        RedisPubSubHelper.subscribe(container, SigningKeyService.ROTATION_TOPIC, signingKeyService::handleRotationEvent);
        RedisPubSubHelper.subscribe(container, SigningKeyService.REVOCATION_TOPIC, signingKeyService::handleRevocationEvent);
        RedisPubSubHelper.subscribe(container, SecurityTopics.PERMISSION_REVOCATION, permissionRevocationService::handleRevocationEvent);
        RedisPubSubHelper.subscribe(container, SecurityTopics.ROLE_REVOCATION, roleRevocationService::handleRevocationEvent);

        return container;
    }
}
