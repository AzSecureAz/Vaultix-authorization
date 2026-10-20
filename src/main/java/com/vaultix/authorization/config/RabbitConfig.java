package com.vaultix.authorization.config;

import org.springframework.amqp.support.converter.JacksonJsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
}
