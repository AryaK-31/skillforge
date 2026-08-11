package com.skillforge.authservice.security.jwt;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Getter
@Setter
@Component
@Validated
@ConfigurationProperties(prefix = "app.security.jwt")
public class JwtProperties {

    private String issuer;

    @NotBlank
    private String secret;

    @NotNull
    private Duration accessTokenExpiration;

    @NotNull
    private Duration refreshTokenExpiration;
}
