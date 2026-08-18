package com.skillforge.authservice.dto.response;

import com.skillforge.common.enums.Role;
import lombok.*;

import java.util.UUID;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterResponse {

    private UUID userId;

    private String email;

    private String message;

    private Role role;
}