package com.skillforge.authservice.service.impl;

import com.skillforge.authservice.dto.request.LoginRequest;
import com.skillforge.authservice.dto.request.RefreshTokenRequest;
import com.skillforge.authservice.dto.request.RegisterRequest;
import com.skillforge.authservice.dto.response.RegisterResponse;
import com.skillforge.authservice.dto.response.TokenResponse;
import com.skillforge.authservice.entity.EmailVerificationToken;
import com.skillforge.authservice.entity.RefreshToken;
import com.skillforge.authservice.entity.User;
import com.skillforge.authservice.exception.InvalidRefreshTokenException;
import com.skillforge.authservice.exception.TokenExpiredException;
import com.skillforge.authservice.mapper.AuthMapper;
import com.skillforge.authservice.repository.EmailVerificationTokenRepository;
import com.skillforge.authservice.repository.RefreshTokenRepository;
import com.skillforge.authservice.repository.UserRepository;
import com.skillforge.authservice.security.jwt.JwtProperties;
import com.skillforge.authservice.security.jwt.JwtService;
import com.skillforge.authservice.service.interfaces.AuthService;
import com.skillforge.authservice.util.RoleResolver;
import com.skillforge.authservice.util.UserStatusResolver;
import com.skillforge.common.enums.Role;
import com.skillforge.authservice.security.userdetails.UserPrincipal;
import com.skillforge.common.enums.UserStatus;
import com.skillforge.common.exception.ConflictException;
import com.skillforge.common.exception.InvalidTokenException;
import com.skillforge.common.exception.ResourceNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;

    private final RefreshTokenRepository refreshTokenRepository;

    private final EmailVerificationTokenRepository emailVerificationTokenRepository;

    private final PasswordEncoder passwordEncoder;

    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;

    private final AuthMapper authMapper;

    private final UserStatusResolver userStatusResolver;

    private final RoleResolver roleResolver;

    private final JwtProperties jwtProperties;

    @Override
    @Transactional
    public RegisterResponse register(RegisterRequest request) {

        // Check if email already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ConflictException("Email already registered");
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

        String verificationToken = generateVerificationToken();

        EmailVerificationToken tokenEntity =
                EmailVerificationToken.builder()
                        .token(verificationToken)
                        .expiryDate(Instant.now().plusSeconds(15 * 60))
                        .used(false)
                        .user(savedUser)
                        .build();

        emailVerificationTokenRepository.save(tokenEntity);

        String verificationUrl =
                "http://localhost:8081/auth/verify-email?token="
                        + verificationToken;

        System.out.println("EMAIL VERIFICATION URL: " + verificationUrl);

        return RegisterResponse.builder()
                .userId(savedUser.getId())
                .email(savedUser.getEmail())
                .role(savedUser.getRole())
                .message("Registration successful. Please verify your email.")
                .build();
    }


    @Override
    public TokenResponse login(LoginRequest request) {

        // Authenticate user
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // Fetch user
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() ->
                new ResourceNotFoundException("User not found")
                );

        // Validate account status
        userStatusResolver.validateLoginStatus(
                user.getStatus()
        );

        // Create UserPrincipal
        UserPrincipal principal = new UserPrincipal(user);

        // Generate tokens
        String accessToken =
                jwtService.generateAccessToken(principal);

        String refreshToken =
                jwtService.generateRefreshToken(principal);

        // Remove old refresh token (One token per user)
        refreshTokenRepository.findByUser(user)
                .ifPresent(refreshTokenRepository::delete);

        // Save new refresh token
        RefreshToken refreshTokenEntity =
                RefreshToken.builder()
                        .token(refreshToken)
                        .expiryDate(
                                Instant.now().plusMillis(
                                        jwtProperties.getRefreshTokenExpiration()
                                )
                        )
                        .user(user)
                        .build();

        refreshTokenRepository.save(refreshTokenEntity);

        // Return response
        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(
                        jwtProperties.getAccessTokenExpiration()
                )
                .build();
    }


    @Override
    public TokenResponse refreshToken(RefreshTokenRequest request) {

        RefreshToken storedToken = refreshTokenRepository
                .findByToken(request.getRefreshToken())
                .orElseThrow(() ->
                        new InvalidRefreshTokenException("Invalid refresh token"));

        if (storedToken.getExpiryDate().isBefore(Instant.now())) {

            refreshTokenRepository.delete(storedToken);

            throw new TokenExpiredException(
                    "Refresh token has expired");
        }

        User user = storedToken.getUser();

        UserPrincipal principal = new UserPrincipal(user);

        String newAccessToken =
                jwtService.generateAccessToken(principal);

        String newRefreshToken =
                jwtService.generateRefreshToken(principal);

        storedToken.setToken(newRefreshToken);

        storedToken.setExpiryDate(
                Instant.now().plusMillis(
                        jwtProperties.getRefreshTokenExpiration()
                )
        );

        refreshTokenRepository.save(storedToken);

        return TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtProperties.getAccessTokenExpiration())
                .build();
    }

    @Override
    @Transactional
    public void verifyEmail(String token) {

        EmailVerificationToken verificationToken =
                emailVerificationTokenRepository.findByToken(token)
                .orElseThrow(() ->
                        new InvalidTokenException(
                                "Invalid email verification token"
                        )
                );

        if (verificationToken.isUsed()) {
            throw new InvalidTokenException(
                    "Email verification token has already been used"
            );
        }

        if (verificationToken.getExpiryDate().isBefore(Instant.now())) {
            emailVerificationTokenRepository.delete(verificationToken);

            throw new TokenExpiredException(
                    "Email verification token has expired"
            );
        }

        User user = verificationToken.getUser();

        user.setEmailVerified(true);

        user.setStatus(UserStatus.ACTIVE);

        verificationToken.setUsed(true);

        userRepository.save(user);

        emailVerificationTokenRepository.save(verificationToken);
    }

    @Override
    public void logout(String refreshToken) {

        refreshTokenRepository.findByToken(refreshToken)
                .ifPresent(refreshTokenRepository::delete);
    }

    private String generateVerificationToken() {

        SecureRandom secureRandom = new SecureRandom();

        byte[] randomBytes = new byte[32];

        secureRandom.nextBytes(randomBytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(randomBytes);
    }
}
