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

        RedisPubSubHelper.builder()
                .container(container)
                .topicName(SigningKeyService.ROTATION_TOPIC)
                .onMessage(signingKeyService::handleRotationEvent)
                .build();

        RedisPubSubHelper.builder()
                .container(container)
                .topicName(SigningKeyService.REVOCATION_TOPIC)
                .onMessage(signingKeyService::handleRevocationEvent)
                .build();

        RedisPubSubHelper.builder()
                .container(container)
                .topicName(SecurityTopics.PERMISSION_REVOCATION)
                .onMessage(permissionRevocationService::handleRevocationEvent)
                .build();

        RedisPubSubHelper.builder()
                .container(container)
                .topicName(SecurityTopics.ROLE_REVOCATION)
                .onMessage(roleRevocationService::handleRevocationEvent)
                .build();

        return container;
    }
}
