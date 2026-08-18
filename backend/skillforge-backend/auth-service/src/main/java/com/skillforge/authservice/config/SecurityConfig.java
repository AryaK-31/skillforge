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


    @Bean
    public PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http)
            throws Exception {

        http

                // REST API + JWT
                .csrf(csrf -> csrf.disable())

                // JWT authentication → no HTTP session
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
                )

                // Security headers
                .headers(headers -> headers

                        .contentSecurityPolicy(csp ->
                                csp.policyDirectives(
                                        "default-src 'self'"
                                )
                        )

                        .frameOptions(frame ->
                                frame.deny()
                        )

                        .contentTypeOptions(
                                contentType -> {
                                }
                        )
                )

                .authorizeHttpRequests(auth -> auth

                        // =====================================
                        // PUBLIC AUTH ENDPOINTS
                        // =====================================

                        .requestMatchers(
                                "/auth/register",
                                "/auth/login",
                                "/auth/refresh",
                                "/auth/verify-email",
                                "/auth/logout"
                        ).permitAll()


                        // =====================================
                        // ACTUATOR
                        // =====================================

                        .requestMatchers(
                                "/actuator/health"
                        ).permitAll()


                        // =====================================
                        // ADMIN
                        // =====================================

                        .requestMatchers("/admin/**")
                        .hasAnyRole(
                                "ADMIN",
                                "SUPER_ADMIN"
                        )


                        // =====================================
                        // SUPER ADMIN
                        // =====================================

                        .requestMatchers("/super-admin/**")
                        .hasRole("SUPER_ADMIN")


                        // =====================================
                        // INSTRUCTOR
                        // =====================================

                        .requestMatchers("/instructor/**")
                        .hasAnyRole(
                                "INSTRUCTOR",
                                "ADMIN",
                                "SUPER_ADMIN"
                        )


                        // =====================================
                        // LEARNER
                        // =====================================

                        .requestMatchers("/learner/**")
                        .hasAnyRole(
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

                // JWT filter
                .addFilterBefore(
                        jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }


    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration)
            throws Exception {

        return configuration.getAuthenticationManager();
    }


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