package com.skillforge.authservice.config;

import com.skillforge.authservice.security.filter.JwtAuthenticationFilter;
import com.skillforge.authservice.security.userdetails.CustomUserDetailsService;

import lombok.RequiredArgsConstructor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;


    // =========================================================
    // PASSWORD ENCODER
    // =========================================================

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    // =========================================================
    // SECURITY FILTER CHAIN
    // =========================================================

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http)
            throws Exception {

        http

                // JWT based API → disable CSRF
                .csrf(csrf -> csrf.disable())

                // No HTTP sessions
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
                )

                .authorizeHttpRequests(auth -> auth

                        // =====================================
                        // PUBLIC AUTH APIs
                        // =====================================

                        .requestMatchers(
                                "/auth/register",
                                "/auth/login",
                                "/auth/refresh",
                                "/auth/verify-email",
                                "/auth/logout",
                                "/actuator/**"
                        ).permitAll()


                        // =====================================
                        // ADMIN
                        // =====================================

                        .requestMatchers(
                                "/admin/**"
                        ).hasAnyRole(
                                "ADMIN",
                                "SUPER_ADMIN"
                        )


                        // =====================================
                        // SUPER ADMIN
                        // =====================================

                        .requestMatchers(
                                "/super-admin/**"
                        ).hasRole(
                                "SUPER_ADMIN"
                        )


                        // =====================================
                        // INSTRUCTOR
                        // =====================================

                        .requestMatchers(
                                "/instructor/**"
                        ).hasAnyRole(
                                "INSTRUCTOR",
                                "ADMIN",
                                "SUPER_ADMIN"
                        )


                        // =====================================
                        // LEARNER
                        // =====================================

                        .requestMatchers(
                                "/learner/**"
                        ).hasAnyRole(
                                "LEARNER",
                                "ADMIN",
                                "SUPER_ADMIN"
                        )


                        // =====================================
                        // EVERYTHING ELSE
                        // =====================================

                        .anyRequest()
                        .authenticated()
                )

                // JWT filter runs before username/password filter
                .addFilterBefore(
                        jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }


    // =========================================================
    // AUTHENTICATION MANAGER
    // =========================================================

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration)
            throws Exception {

        return configuration.getAuthenticationManager();
    }


    // =========================================================
    // DAO AUTHENTICATION PROVIDER
    // =========================================================

    @Bean
    public DaoAuthenticationProvider authenticationProvider(
            CustomUserDetailsService service,
            PasswordEncoder encoder) {

        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider();

        provider.setUserDetailsService(service);

        provider.setPasswordEncoder(encoder);

        return provider;
    }
}