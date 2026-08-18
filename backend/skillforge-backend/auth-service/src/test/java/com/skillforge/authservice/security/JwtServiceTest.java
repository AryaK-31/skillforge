package com.skillforge.authservice.security;

import com.skillforge.authservice.security.jwt.JwtProperties;
import com.skillforge.authservice.security.jwt.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private JwtService jwtService;

    private UserDetails user;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("skillforge-production-secret-key-which-is-at-least-32-bytes-long");
        properties.setAccessTokenExpiration(Duration.ofMinutes(15));
        properties.setRefreshTokenExpiration(Duration.ofDays(7));

        jwtService = new JwtService(properties);

        user = User.builder()
                .username("aarav.sharma@example.com")
                .password("password")
                .authorities(new SimpleGrantedAuthority("ROLE_LEARNER"))
                .build();
    }

    @Test
    void generateAccessToken_shouldCreateValidToken() {
        String token = jwtService.generateAccessToken(user);

        assertThat(token).isNotBlank();
        assertThat(jwtService.extractUsername(token)).isEqualTo("aarav.sharma@example.com");
        assertThat(jwtService.isTokenValid(token, user)).isTrue();
    }

    @Test
    void generateRefreshToken_shouldCreateValidToken() {
        String token = jwtService.generateRefreshToken(user);

        assertThat(token).isNotBlank();
        assertThat(jwtService.extractUsername(token)).isEqualTo("aarav.sharma@example.com");
    }

    @Test
    void tokenShouldContainCorrectExpiration() {
        String token = jwtService.generateAccessToken(user);

        assertThat(jwtService.isTokenExpired(token)).isFalse();
    }

    @Test
    void invalidTokenShouldBeRejected() {
        assertThatThrownBy(() -> jwtService.extractUsername("invalid.jwt.token"))
                .isInstanceOf(Exception.class);
    }

    @Test
    void tokenForDifferentUserShouldBeInvalid() {
        String token = jwtService.generateAccessToken(user);
        UserDetails differentUser = User.builder()
                .username("other@example.com")
                .password("password")
                .authorities(new SimpleGrantedAuthority("ROLE_LEARNER"))
                .build();

        assertThat(jwtService.isTokenValid(token, differentUser)).isFalse();
    }
}
