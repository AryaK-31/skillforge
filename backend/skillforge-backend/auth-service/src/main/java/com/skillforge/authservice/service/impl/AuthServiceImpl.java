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
import com.skillforge.authservice.security.userdetails.UserPrincipal;
import com.skillforge.authservice.service.interfaces.AuthService;
import com.skillforge.authservice.util.RoleResolver;
import com.skillforge.authservice.util.UserStatusResolver;
import com.skillforge.common.enums.Role;
import com.skillforge.common.enums.UserStatus;
import com.skillforge.common.exception.ConflictException;
import com.skillforge.common.exception.InvalidTokenException;
import com.skillforge.common.exception.ResourceNotFoundException;

import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

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


    // =========================================================
    // REGISTER
    // =========================================================

    @Override
    @Transactional
    public RegisterResponse register(RegisterRequest request) {

        // 1. Check duplicate email
        if (userRepository.existsByEmail(request.getEmail())) {

            throw new ConflictException(
                    "Email already registered"
            );
        }

        // 2. DTO -> Entity
        User user = authMapper.toUser(request);

        // 3. Encrypt password
        user.setPassword(
                passwordEncoder.encode(request.getPassword())
        );

        // 4. Resolve role
        Role role = roleResolver.resolveRole(
                request.getRole()
        );

        user.setRole(role);

        // 5. Initial account status
        user.setStatus(
                userStatusResolver.resolveInitialStatus(role)
        );

        // 6. Email initially not verified
        user.setEmailVerified(false);

        // 7. Save user
        User savedUser = userRepository.save(user);

        // 8. Generate email verification token
        String verificationToken =
                generateVerificationToken();

        // 9. Save verification token
        EmailVerificationToken tokenEntity =
                EmailVerificationToken.builder()
                        .token(verificationToken)
                        .expiryDate(
                                Instant.now().plusSeconds(15 * 60)
                        )
                        .used(false)
                        .user(savedUser)
                        .build();

        emailVerificationTokenRepository.save(tokenEntity);

        // 10. Verification URL
        String verificationUrl =
                "http://localhost:8081/auth/verify-email?token="
                        + verificationToken;

        /*
         * DEVELOPMENT ONLY
         *
         * Later this URL will be sent through Email Service.
         */
        System.out.println(
                "=========================================="
        );

        System.out.println(
                "EMAIL VERIFICATION URL:"
        );

        System.out.println(
                verificationUrl
        );

        System.out.println(
                "=========================================="
        );

        // 11. Response
        return RegisterResponse.builder()
                .userId(savedUser.getId())
                .email(savedUser.getEmail())
                .role(savedUser.getRole())
                .message(
                        "Registration successful. " +
                                "Please verify your email."
                )
                .build();
    }


    // =========================================================
    // LOGIN
    // =========================================================

    @Override
    public TokenResponse login(LoginRequest request) {

        // 1. Authenticate email + password
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // 2. Fetch user
        User user = userRepository
                .findByEmail(request.getEmail())
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "User not found"
                        )
                );

        // 3. Validate account status
        userStatusResolver.validateLoginStatus(
                user.getStatus()
        );

        // 4. Create principal
        UserPrincipal principal =
                new UserPrincipal(user);

        // 5. Generate access token
        String accessToken =
                jwtService.generateAccessToken(principal);

        // 6. Generate refresh token
        String refreshToken =
                jwtService.generateRefreshToken(principal);

        // 7. Delete old refresh token
        refreshTokenRepository
                .findByUser(user)
                .ifPresent(refreshTokenRepository::delete);

        // 8. Create refresh token entity
        RefreshToken refreshTokenEntity =
                RefreshToken.builder()
                        .token(refreshToken)
                        .expiryDate(
                        Instant.now().plusMillis(
                                jwtProperties
                                                .getRefreshTokenExpiration()
                                                .toMillis()
                        )
                        )
                        .user(user)
                        .build();

        // 9. Save refresh token
        refreshTokenRepository.save(
                refreshTokenEntity
        );

        // 10. Return tokens
        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(
                        jwtProperties
                                .getAccessTokenExpiration()
                                .toMillis()
                )
                .build();
    }


    // =========================================================
    // REFRESH TOKEN
    // =========================================================

    @Override
    @Transactional
    public TokenResponse refreshToken(
            RefreshTokenRequest request) {

        // 1. Find refresh token
        RefreshToken storedToken =
                refreshTokenRepository
                        .findByToken(
                                request.getRefreshToken()
                        )
                        .orElseThrow(() ->
                                new InvalidRefreshTokenException(
                                        "Invalid refresh token"
                                )
                        );

        // 2. Check expiry
        if (storedToken
                .getExpiryDate()
                .isBefore(Instant.now())) {

            refreshTokenRepository.delete(
                    storedToken
            );

            throw new TokenExpiredException(
                    "Refresh token has expired"
            );
        }

        // 3. Get user
        User user =
                storedToken.getUser();

        // 4. Create principal
        UserPrincipal principal =
                new UserPrincipal(user);

        // 5. Generate new access token
        String newAccessToken =
                jwtService.generateAccessToken(
                        principal
                );

        // 6. Generate new refresh token
        String newRefreshToken =
                jwtService.generateRefreshToken(
                        principal
                );

        // 7. Rotate refresh token
        storedToken.setToken(
                newRefreshToken
        );

        storedToken.setExpiryDate(
                Instant.now().plusMillis(
                        jwtProperties
                                .getRefreshTokenExpiration()
                                .toMillis()
                )
        );

        // 8. Save rotated token
        refreshTokenRepository.save(
                storedToken
        );

        // 9. Return
        return TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresIn(
                        jwtProperties
                                .getAccessTokenExpiration()
                                .toMillis()
                )
                .build();
    }


    // =========================================================
    // EMAIL VERIFICATION
    // =========================================================

    @Override
    @Transactional
    public void verifyEmail(String token) {

        // 1. Find token
        EmailVerificationToken verificationToken =
                emailVerificationTokenRepository
                        .findByToken(token)
                        .orElseThrow(() ->
                                new InvalidTokenException(
                                        "Invalid email verification token"
                                )
                        );

        // 2. Check if already used
        if (verificationToken.isUsed()) {

            throw new InvalidTokenException(
                    "Email verification token has already been used"
            );
        }

        // 3. Check expiry
        if (verificationToken
                .getExpiryDate()
                .isBefore(Instant.now())) {

            emailVerificationTokenRepository.delete(
                    verificationToken
            );

            throw new TokenExpiredException(
                    "Email verification token has expired"
            );
        }

        // 4. Get user
        User user =
                verificationToken.getUser();

        // 5. Verify email
        user.setEmailVerified(true);

        // 6. Activate account
        user.setStatus(
                UserStatus.ACTIVE
        );

        // 7. Mark token used
        verificationToken.setUsed(true);

        // 8. Save changes
        userRepository.save(user);

        emailVerificationTokenRepository.save(
                verificationToken
        );
    }


    // =========================================================
    // LOGOUT
    // =========================================================

    @Override
    @Transactional
    public void logout(String refreshToken) {

        refreshTokenRepository
                .findByToken(refreshToken)
                .ifPresent(
                        refreshTokenRepository::delete
                );
    }


    // =========================================================
    // TOKEN GENERATION
    // =========================================================

    private String generateVerificationToken() {

        SecureRandom secureRandom =
                new SecureRandom();

        byte[] randomBytes =
                new byte[32];

        secureRandom.nextBytes(
                randomBytes
        );

        return Base64
                .getUrlEncoder()
                .withoutPadding()
                .encodeToString(
                        randomBytes
                );
    }
}
