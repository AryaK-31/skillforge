package com.skillforge.authservice.controller;

import com.skillforge.authservice.dto.request.LoginRequest;
import com.skillforge.authservice.dto.request.RefreshTokenRequest;
import com.skillforge.authservice.dto.request.RegisterRequest;
import com.skillforge.authservice.dto.response.RegisterResponse;
import com.skillforge.authservice.dto.response.TokenResponse;
import com.skillforge.authservice.service.interfaces.AuthService;

import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;


    // =========================================================
    // REGISTER
    // =========================================================

    @PostMapping("/register")
    public RegisterResponse register(
            @Valid @RequestBody RegisterRequest request) {

        return authService.register(request);
    }


    // =========================================================
    // LOGIN
    // =========================================================

    @PostMapping("/login")
    public TokenResponse login(
            @Valid @RequestBody LoginRequest request) {

        return authService.login(request);
    }


    // =========================================================
    // REFRESH TOKEN
    // =========================================================

    @PostMapping("/refresh")
    public TokenResponse refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {

        return authService.refreshToken(request);
    }


    // =========================================================
    // EMAIL VERIFICATION
    // =========================================================

    @GetMapping("/verify-email")
    public String verifyEmail(
            @RequestParam("token") String token) {

        authService.verifyEmail(token);

        return "Email verified successfully. You can now login.";
    }


    // =========================================================
    // LOGOUT
    // =========================================================

    @PostMapping("/logout")
    public String logout(
            @Valid @RequestBody RefreshTokenRequest request) {

        authService.logout(
                request.getRefreshToken()
        );

        return "Logged out successfully.";
    }
}