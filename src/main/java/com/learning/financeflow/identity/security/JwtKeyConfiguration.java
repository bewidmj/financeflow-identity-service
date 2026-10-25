package com.learning.financeflow.identity.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ResourceLoader;

@Configuration
public class JwtKeyConfiguration {

    @Bean
    JwtKeyProvider jwtKeyProvider(
            ResourceLoader resourceLoader,
            @Value("${app.jwt.private-key-location}") String privateKeyLocation,
            @Value("${app.jwt.key-id}") String keyId,
            @Value("${app.jwt.additional-public-keys:}") String additionalPublicKeys) {
        return new JwtKeyProvider(
                resourceLoader, privateKeyLocation, keyId, additionalPublicKeys);
    }
}
