package com.skillforge.authservice.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import lombok.RequiredArgsConstructor;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties properties;

    private SecretKey getSigningKey() {

        return Keys.hmacShaKeyFor(
                properties.getSecret()
                        .getBytes(StandardCharsets.UTF_8)
        );
    }

    public String generateAccessToken(UserDetails user) {

        Date now = new Date();

        Date expiry = new Date(
                now.getTime() + properties.getAccessTokenExpiration()
        );

        return Jwts.builder()

                .subject(user.getUsername())

                .issuedAt(now)

                .expiration(expiry)

                .signWith(getSigningKey())

                .compact();
    }

    public String extractUsername(String token) {

        return extractClaims(token).getSubject();
    }

    public boolean isTokenValid(String token, UserDetails user) {

        String username = extractUsername(token);

        return username.equals(user.getUsername())
                && !isTokenExpired(token);
    }

    public boolean isTokenExpired(String token) {

        return extractClaims(token)
                .getExpiration()
                .before(new Date());
    }

    private Claims extractClaims(String token) {

        return Jwts.parser()

                .verifyWith(getSigningKey())

                .build()

                .parseSignedClaims(token)

                .getPayload();
    }

}