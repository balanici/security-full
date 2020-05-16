package com.balanici.securityfull.jwt;

import io.jsonwebtoken.security.Keys;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@Configuration
public class JwtSecretKey {

    private final JwtConfigProperties jwtConfigProperties;

    public JwtSecretKey(JwtConfigProperties jwtConfigProperties) {
        this.jwtConfigProperties = jwtConfigProperties;
    }


    @Bean
    public SecretKey secretKey() {
        return Keys.hmacShaKeyFor(jwtConfigProperties.getSecretKey().getBytes());
    }
}
