package com.skillforge.authservice.service.interfaces;


import com.skillforge.authservice.dto.request.LoginRequest;
import com.skillforge.authservice.dto.request.RefreshTokenRequest;
import com.skillforge.authservice.dto.request.RegisterRequest;
import com.skillforge.authservice.dto.response.RegisterResponse;
import com.skillforge.authservice.dto.response.TokenResponse;

public interface AuthService {

    RegisterResponse register(RegisterRequest request);

    TokenResponse login(LoginRequest request);

    TokenResponse refreshToken(RefreshTokenRequest request);
}