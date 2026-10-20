package com.vaultix.authorization.config;

import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.support.converter.JacksonJsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.vaultix.authorization.config.properties.AuthMessagingProperties;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

@Configuration
public class RabbitConfig {

    @Bean
    public MessageConverter jsonMessageConverter(ObjectMapper objectMapper) {
        if (objectMapper instanceof JsonMapper jsonMapper) {
            return new JacksonJsonMessageConverter(jsonMapper);
        }
        return new JacksonJsonMessageConverter();
    }

    @Bean
    public TopicExchange authExchange(AuthMessagingProperties properties) {
        return new TopicExchange(properties.exchange(), true, false);
    }
}
