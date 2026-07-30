package com.safedjio.authservice.dto;

import com.safedjio.authservice.entity.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    @NotNull(message = "userId is required")
    private Long userId;

    @NotBlank(message = "login must not be blank")
    @Size(max = 255)
    private String login;

    @NotBlank(message = "password must not be blank")
    @Size(min = 8, max = 72, message = "password must be 8-72 characters")
    private String password;

    @NotNull(message = "role is required")
    private Role role;
}
