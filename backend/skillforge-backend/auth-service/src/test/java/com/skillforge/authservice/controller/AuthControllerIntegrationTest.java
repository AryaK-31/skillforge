package com.skillforge.authservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.skillforge.authservice.config.SecurityConfig;
import com.skillforge.authservice.dto.request.LoginRequest;
import com.skillforge.authservice.dto.request.RefreshTokenRequest;
import com.skillforge.authservice.dto.request.RegisterRequest;
import com.skillforge.authservice.dto.response.RegisterResponse;
import com.skillforge.authservice.dto.response.TokenResponse;
import com.skillforge.authservice.security.filter.JwtAuthenticationFilter;
import com.skillforge.authservice.security.userdetails.CustomUserDetailsService;
import com.skillforge.authservice.service.interfaces.AuthService;
import com.skillforge.common.enums.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(
        controllers = AuthController.class,
        properties = "spring.cloud.config.enabled=false"
)
@Import(SecurityConfig.class)
class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @MockitoBean
    private CustomUserDetailsService customUserDetailsService;

    @MockitoBean
    private AuthenticationManager authenticationManager;

    @BeforeEach
    void setUp() throws Exception {
        doAnswer(invocation -> {
            invocation.getArgument(2, jakarta.servlet.FilterChain.class)
                    .doFilter(invocation.getArgument(0), invocation.getArgument(1));
            return null;
        }).when(jwtAuthenticationFilter).doFilter(any(), any(), any());
    }

    @Test
    void register_shouldReturnSuccess() throws Exception {
        RegisterRequest request = registerRequest();
        RegisterResponse response = RegisterResponse.builder()
                .userId(UUID.randomUUID())
                .email("aarav.sharma@example.com")
                .role(Role.ROLE_LEARNER)
                .message("Registration successful. Please verify your email.")
                .build();

        when(authService.register(any(RegisterRequest.class))).thenReturn(response);

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("aarav.sharma@example.com"))
                .andExpect(jsonPath("$.role").value("ROLE_LEARNER"));

        verify(authService).register(any(RegisterRequest.class));
    }

    @Test
    void register_shouldRejectInvalidPayloadBeforeService() throws Exception {
        RegisterRequest request = registerRequest();
        request.setEmail("not-an-email");

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void login_shouldReturnTokens() throws Exception {
        LoginRequest request = LoginRequest.builder()
                .email("aarav.sharma@example.com")
                .password("Password@123")
                .build();
        TokenResponse response = TokenResponse.builder()
                .accessToken("access-token")
                .refreshToken("refresh-token")
                .tokenType("Bearer")
                .expiresIn(900000L)
                .build();

        when(authService.login(any(LoginRequest.class))).thenReturn(response);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("access-token"))
                .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    void refresh_shouldReturnNewTokens() throws Exception {
        RefreshTokenRequest request = RefreshTokenRequest.builder()
                .refreshToken("old-refresh-token")
                .build();
        TokenResponse response = TokenResponse.builder()
                .accessToken("new-access-token")
                .refreshToken("new-refresh-token")
                .tokenType("Bearer")
                .expiresIn(900000L)
                .build();

        when(authService.refreshToken(any(RefreshTokenRequest.class))).thenReturn(response);

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"));
    }

    @Test
    void verifyEmail_shouldReturnSuccess() throws Exception {
        doNothing().when(authService).verifyEmail("verification-token");

        mockMvc.perform(get("/auth/verify-email")
                        .param("token", "verification-token"))
                .andExpect(status().isOk())
                .andExpect(content().string("Email verified successfully. You can now login."));

        verify(authService).verifyEmail("verification-token");
    }

    @Test
    void logout_shouldReturnSuccess() throws Exception {
        RefreshTokenRequest request = RefreshTokenRequest.builder()
                .refreshToken("refresh-token")
                .build();

        doNothing().when(authService).logout("refresh-token");

        mockMvc.perform(post("/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(content().string("Logged out successfully."));

        verify(authService).logout("refresh-token");
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
