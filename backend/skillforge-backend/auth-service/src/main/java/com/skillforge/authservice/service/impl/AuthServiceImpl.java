package com.skillforge.authservice.service.impl;

import com.skillforge.authservice.dto.request.LoginRequest;
import com.skillforge.authservice.dto.request.RefreshTokenRequest;
import com.skillforge.authservice.dto.request.RegisterRequest;
import com.skillforge.authservice.dto.response.RegisterResponse;
import com.skillforge.authservice.dto.response.TokenResponse;
import com.skillforge.authservice.entity.RefreshToken;
import com.skillforge.authservice.entity.User;
import com.skillforge.authservice.mapper.AuthMapper;
import com.skillforge.authservice.repository.RefreshTokenRepository;
import com.skillforge.authservice.repository.UserRepository;
import com.skillforge.authservice.security.jwt.JwtService;
import com.skillforge.authservice.service.interfaces.AuthService;
import com.skillforge.authservice.dto.response.RegisterResponse;
import com.skillforge.authservice.entity.User;
import com.skillforge.authservice.util.RoleResolver;
import com.skillforge.authservice.util.UserStatusResolver;
import com.skillforge.common.enums.Role;

import com.skillforge.common.enums.UserStatus;
import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;

    private final RefreshTokenRepository refreshTokenRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;

    private final AuthMapper authMapper;

    private final UserStatusResolver userStatusResolver;

    private final RoleResolver roleResolver;

    @Override
    public RegisterResponse register(RegisterRequest request) {

        // Check if email already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already registered");
        }

        // DTO -> Entity
        User user = authMapper.toUser(request);

// Encrypt password
        user.setPassword(
                passwordEncoder.encode(request.getPassword())
        );


        Role role = roleResolver.resolveRole(
                request.getRole()
        );
        user.setRole(role);

// Initial Status
        user.setStatus(
                userStatusResolver.resolveInitialStatus(role)
        );

//// Save

        User savedUser = userRepository.save(user);

        return RegisterResponse.builder()
                .userId(savedUser.getId())
                .email(savedUser.getEmail())
                .role(savedUser.getRole())
                .message("User registered successfully")
                .build();
    }


    @Override
    public TokenResponse login(LoginRequest request) {
        return null;
    }

    @Override
    public TokenResponse refreshToken(RefreshTokenRequest request) {
        return null;
    }
}