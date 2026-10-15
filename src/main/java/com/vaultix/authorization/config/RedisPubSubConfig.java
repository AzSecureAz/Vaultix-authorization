package com.vaultix.authorization.config;

import java.nio.charset.StandardCharsets;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.data.redis.listener.RedisMessageListenerContainer;

import com.vaultix.authorization.service.SigningKeyService;

@Configuration
public class RedisPubSubConfig {

    @Bean
    public ChannelTopic signingKeyRotationTopic() {
        return new ChannelTopic(SigningKeyService.ROTATION_TOPIC);
    }

    @Bean
    public RedisMessageListenerContainer redisMessageListenerContainer(
            RedisConnectionFactory connectionFactory,
            SigningKeyService signingKeyService,
            ChannelTopic signingKeyRotationTopic) {
        RedisMessageListenerContainer container = new RedisMessageListenerContainer();
        container.setConnectionFactory(connectionFactory);
        container.addMessageListener((message, pattern) -> {
            String payload = new String(message.getBody(), StandardCharsets.UTF_8);
            signingKeyService.handleRotationEvent(payload);
        }, signingKeyRotationTopic);

        return container;
    }
}
