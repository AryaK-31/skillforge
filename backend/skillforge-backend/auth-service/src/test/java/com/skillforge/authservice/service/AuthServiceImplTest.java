package com.skillforge.authservice.service;

import com.skillforge.authservice.dto.request.LoginRequest;
import com.skillforge.authservice.dto.request.RefreshTokenRequest;
import com.skillforge.authservice.dto.request.RegisterRequest;
import com.skillforge.authservice.dto.response.RegisterResponse;
import com.skillforge.authservice.dto.response.TokenResponse;
import com.skillforge.authservice.entity.EmailVerificationToken;
import com.skillforge.authservice.entity.RefreshToken;
import com.skillforge.authservice.entity.User;
import com.skillforge.authservice.exception.EmailNotVerifiedException;
import com.skillforge.authservice.exception.InvalidRefreshTokenException;
import com.skillforge.authservice.exception.TokenExpiredException;
import com.skillforge.authservice.mapper.AuthMapper;
import com.skillforge.authservice.repository.EmailVerificationTokenRepository;
import com.skillforge.authservice.repository.RefreshTokenRepository;
import com.skillforge.authservice.repository.UserRepository;
import com.skillforge.authservice.security.jwt.JwtProperties;
import com.skillforge.authservice.security.jwt.JwtService;
import com.skillforge.authservice.security.userdetails.UserPrincipal;
import com.skillforge.authservice.service.impl.AuthServiceImpl;
import com.skillforge.authservice.util.RoleResolver;
import com.skillforge.authservice.util.UserStatusResolver;
import com.skillforge.common.enums.Role;
import com.skillforge.common.enums.UserStatus;
import com.skillforge.common.exception.ConflictException;
import com.skillforge.common.exception.InvalidTokenException;
import com.skillforge.common.exception.ResourceNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private EmailVerificationTokenRepository emailVerificationTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtService jwtService;

    @Mock
    private AuthMapper authMapper;

    @Mock
    private UserStatusResolver userStatusResolver;

    @Mock
    private RoleResolver roleResolver;

    @Mock
    private JwtProperties jwtProperties;

    @InjectMocks
    private AuthServiceImpl authService;

    private User user;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(UUID.randomUUID())
                .firstName("Aarav")
                .lastName("Sharma")
                .email("aarav.sharma@example.com")
                .password("encoded-password")
                .role(Role.ROLE_LEARNER)
                .status(UserStatus.ACTIVE)
                .emailVerified(true)
                .enabled(true)
                .accountNonLocked(true)
                .build();
    }

    @Test
    void register_shouldRegisterUserSuccessfully() {
        RegisterRequest request = registerRequest();

        when(userRepository.existsByEmail(request.getEmail())).thenReturn(false);
        when(authMapper.toUser(request)).thenReturn(user);
        when(passwordEncoder.encode(request.getPassword())).thenReturn("encoded-password");
        when(roleResolver.resolveRole(request.getRole())).thenReturn(Role.ROLE_LEARNER);
        when(userStatusResolver.resolveInitialStatus(Role.ROLE_LEARNER))
                .thenReturn(UserStatus.PENDING_VERIFICATION);
        when(userRepository.save(user)).thenReturn(user);

        RegisterResponse response = authService.register(request);

        assertThat(response).isNotNull();
        assertThat(response.getEmail()).isEqualTo("aarav.sharma@example.com");
        assertThat(response.getRole()).isEqualTo(Role.ROLE_LEARNER);
        assertThat(user.getPassword()).isEqualTo("encoded-password");
        assertThat(user.getStatus()).isEqualTo(UserStatus.PENDING_VERIFICATION);
        assertThat(user.getEmailVerified()).isFalse();

        verify(userRepository).existsByEmail("aarav.sharma@example.com");
        verify(userRepository).save(user);
        verify(emailVerificationTokenRepository).save(any(EmailVerificationToken.class));
    }

    @Test
    void register_shouldRejectDuplicateEmail() {
        RegisterRequest request = registerRequest();
        when(userRepository.existsByEmail(request.getEmail())).thenReturn(true);

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(ConflictException.class)
                .hasMessage("Email already registered");

        verify(userRepository, never()).save(any());
        verify(emailVerificationTokenRepository, never()).save(any());
    }

    @Test
    void login_shouldReturnTokensSuccessfully() {
        LoginRequest request = LoginRequest.builder()
                .email("aarav.sharma@example.com")
                .password("Password@123")
                .build();

        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(user));
        when(jwtService.generateAccessToken(any(UserPrincipal.class))).thenReturn("access-token");
        when(jwtService.generateRefreshToken(any(UserPrincipal.class))).thenReturn("refresh-token");
        when(jwtProperties.getRefreshTokenExpiration()).thenReturn(Duration.ofDays(1));
        when(jwtProperties.getAccessTokenExpiration()).thenReturn(Duration.ofMinutes(15));
        when(refreshTokenRepository.findByUser(user)).thenReturn(Optional.empty());

        TokenResponse response = authService.login(request);

        assertThat(response.getAccessToken()).isEqualTo("access-token");
        assertThat(response.getRefreshToken()).isEqualTo("refresh-token");
        assertThat(response.getTokenType()).isEqualTo("Bearer");
        assertThat(response.getExpiresIn()).isEqualTo(900000L);

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void login_shouldFailWhenUserDoesNotExist() {
        LoginRequest request = LoginRequest.builder()
                .email("unknown@example.com")
                .password("Password@123")
                .build();

        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(ResourceNotFoundException.class);

        verify(jwtService, never()).generateAccessToken(any());
    }

    @Test
    void login_shouldRejectUnverifiedUser() {
        LoginRequest request = LoginRequest.builder()
                .email("aarav.sharma@example.com")
                .password("Password@123")
                .build();
        user.setStatus(UserStatus.PENDING_VERIFICATION);

        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(user));
        doThrow(new EmailNotVerifiedException("Please verify your email first."))
                .when(userStatusResolver)
                .validateLoginStatus(UserStatus.PENDING_VERIFICATION);

        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(EmailNotVerifiedException.class);

        verify(jwtService, never()).generateAccessToken(any());
    }

    @Test
    void refreshToken_shouldGenerateNewTokens() {
        RefreshTokenRequest request = RefreshTokenRequest.builder()
                .refreshToken("old-refresh-token")
                .build();
        RefreshToken storedToken = RefreshToken.builder()
                .id(UUID.randomUUID())
                .token("old-refresh-token")
                .expiryDate(Instant.now().plusSeconds(3600))
                .user(user)
                .build();

        when(refreshTokenRepository.findByToken("old-refresh-token"))
                .thenReturn(Optional.of(storedToken));
        when(jwtService.generateAccessToken(any(UserPrincipal.class))).thenReturn("new-access-token");
        when(jwtService.generateRefreshToken(any(UserPrincipal.class))).thenReturn("new-refresh-token");
        when(jwtProperties.getRefreshTokenExpiration()).thenReturn(Duration.ofDays(1));
        when(jwtProperties.getAccessTokenExpiration()).thenReturn(Duration.ofMinutes(15));

        TokenResponse response = authService.refreshToken(request);

        assertThat(response.getAccessToken()).isEqualTo("new-access-token");
        assertThat(response.getRefreshToken()).isEqualTo("new-refresh-token");
        assertThat(storedToken.getToken()).isEqualTo("new-refresh-token");
        verify(refreshTokenRepository).save(storedToken);
    }

    @Test
    void refreshToken_shouldRejectInvalidToken() {
        RefreshTokenRequest request = RefreshTokenRequest.builder()
                .refreshToken("invalid-token")
                .build();
        when(refreshTokenRepository.findByToken("invalid-token")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refreshToken(request))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void refreshToken_shouldRejectExpiredToken() {
        RefreshTokenRequest request = RefreshTokenRequest.builder()
                .refreshToken("expired-token")
                .build();
        RefreshToken storedToken = RefreshToken.builder()
                .id(UUID.randomUUID())
                .token("expired-token")
                .expiryDate(Instant.now().minusSeconds(60))
                .user(user)
                .build();

        when(refreshTokenRepository.findByToken("expired-token"))
                .thenReturn(Optional.of(storedToken));

        assertThatThrownBy(() -> authService.refreshToken(request))
                .isInstanceOf(TokenExpiredException.class);

        verify(refreshTokenRepository).delete(storedToken);
    }

    @Test
    void verifyEmail_shouldActivateUser() {
        user.setEmailVerified(false);
        user.setStatus(UserStatus.PENDING_VERIFICATION);
        EmailVerificationToken token = EmailVerificationToken.builder()
                .id(UUID.randomUUID())
                .token("verification-token")
                .expiryDate(Instant.now().plusSeconds(900))
                .used(false)
                .user(user)
                .build();

        when(emailVerificationTokenRepository.findByToken("verification-token"))
                .thenReturn(Optional.of(token));

        authService.verifyEmail("verification-token");

        assertThat(user.getEmailVerified()).isTrue();
        assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
        assertThat(token.isUsed()).isTrue();
        verify(userRepository).save(user);
        verify(emailVerificationTokenRepository).save(token);
    }

    @Test
    void verifyEmail_shouldRejectInvalidToken() {
        when(emailVerificationTokenRepository.findByToken("invalid-token"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.verifyEmail("invalid-token"))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void verifyEmail_shouldRejectUsedToken() {
        EmailVerificationToken token = EmailVerificationToken.builder()
                .token("used-token")
                .expiryDate(Instant.now().plusSeconds(900))
                .used(true)
                .user(user)
                .build();
        when(emailVerificationTokenRepository.findByToken("used-token"))
                .thenReturn(Optional.of(token));

        assertThatThrownBy(() -> authService.verifyEmail("used-token"))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void verifyEmail_shouldRejectExpiredToken() {
        EmailVerificationToken token = EmailVerificationToken.builder()
                .token("expired-token")
                .expiryDate(Instant.now().minusSeconds(60))
                .used(false)
                .user(user)
                .build();
        when(emailVerificationTokenRepository.findByToken("expired-token"))
                .thenReturn(Optional.of(token));

        assertThatThrownBy(() -> authService.verifyEmail("expired-token"))
                .isInstanceOf(TokenExpiredException.class);

        verify(emailVerificationTokenRepository).delete(token);
    }

    @Test
    void logout_shouldDeleteRefreshToken() {
        RefreshToken token = RefreshToken.builder()
                .token("refresh-token")
                .user(user)
                .expiryDate(Instant.now().plusSeconds(3600))
                .build();
        when(refreshTokenRepository.findByToken("refresh-token"))
                .thenReturn(Optional.of(token));

        authService.logout("refresh-token");

        verify(refreshTokenRepository).delete(token);
    }

    @Test
    void logout_shouldDoNothingForUnknownToken() {
        when(refreshTokenRepository.findByToken("unknown-token"))
                .thenReturn(Optional.empty());

        authService.logout("unknown-token");

        verify(refreshTokenRepository, never()).delete(any());
    }

    private RegisterRequest registerRequest() {
        RegisterRequest request = new RegisterRequest();
        request.setFirstName("Aarav");
        request.setLastName("Sharma");
        request.setEmail("aarav.sharma@example.com");
        request.setPassword("Password@123");
        request.setRole(Role.ROLE_LEARNER);
        return request;
    }
}
