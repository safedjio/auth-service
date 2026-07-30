package com.safedjio.authservice.controller;

import com.safedjio.authservice.dto.RegisterRequest;
import com.safedjio.authservice.entity.Role;
import com.safedjio.authservice.service.CredentialService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AuthAdminController {

    private final CredentialService credentialService;

    @PostMapping("/credentials")
    public ResponseEntity<Void> registerWithRole(@Valid @RequestBody RegisterRequest request) {
        credentialService.registerWithRole(request, request.getRole() != null ? request.getRole() : Role.USER);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PatchMapping("/credentials/{userId}/status")
    public ResponseEntity<Void> setActive(@PathVariable Long userId,
                                          @RequestParam boolean active) {
        credentialService.setActive(userId, active);
        return ResponseEntity.noContent().build();
    }
}