package com.safedjio.authservice.service;

import com.safedjio.authservice.dto.*;
import com.safedjio.authservice.entity.Credential;
import com.safedjio.authservice.entity.Role;
import com.safedjio.authservice.exception.InvalidCredentialsException;
import com.safedjio.authservice.exception.UserAlreadyExistsException;
import com.safedjio.authservice.repository.CredentialRepository;
import com.safedjio.authservice.security.JwtService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CredentialService {

    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Transactional
    public void register(RegisterRequest request) {
        log.info("Registering credentials for userId={}", request.getUserId());

        if (credentialRepository.existsByLogin(request.getLogin())) {
            log.warn("Registration rejected, login already taken: {}", request.getLogin());
            throw new UserAlreadyExistsException("Login already in use");
        }
        if (credentialRepository.existsByUserId(request.getUserId())) {
            log.warn("Registration rejected, credentials already exist for userId={}", request.getUserId());
            throw new UserAlreadyExistsException("Credentials already exist for this user");
        }

        Credential credential = Credential.builder()
                .userId(request.getUserId())
                .login(request.getLogin())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .active(true)
                .build();

        credentialRepository.save(credential);
        log.info("Credentials stored for userId={}", request.getUserId());
    }

    public TokenResponse login(LoginRequest request) {
        log.info("Login attempt for login={}", request.getLogin());

        Credential credential = credentialRepository.findByLogin(request.getLogin())
                .orElseThrow(() -> {
                    log.warn("Login failed, unknown login={}", request.getLogin());
                    return new InvalidCredentialsException("Invalid login or password");
                });

        if (!credential.isActive()) {
            log.warn("Login rejected, account deactivated, userId={}", credential.getUserId());
            throw new InvalidCredentialsException("Account is deactivated");
        }

        if (!passwordEncoder.matches(request.getPassword(), credential.getPasswordHash())) {
            log.warn("Login failed, password mismatch, userId={}", credential.getUserId());
            throw new InvalidCredentialsException("Invalid login or password");
        }

        log.info("Login succeeded, userId={}", credential.getUserId());
        return issueTokens(credential.getUserId(), credential.getRole());
    }

    public TokenResponse refresh(TokenRequest request) {
        Claims claims = jwtService.parseRefreshTokenClaims(request.getToken());
        Long userId = jwtService.extractUserId(claims);

        Credential credential = credentialRepository.findByUserId(userId)
                .orElseThrow(() -> {
                    log.warn("Refresh failed, no credentials for userId={}", userId);
                    return new InvalidCredentialsException("Unknown user");
                });

        if (!credential.isActive()) {
            log.warn("Refresh rejected, account deactivated, userId={}", userId);
            throw new InvalidCredentialsException("Account is deactivated");
        }

        log.info("Refreshing tokens for userId={}", userId);
        return issueTokens(credential.getUserId(), credential.getRole());
    }

    public Map<String, Object> validate(TokenRequest request) {
        Claims claims = jwtService.parseAccessTokenClaims(request.getToken());
        Map<String, Object> result = new HashMap<>();
        result.put("valid", true);
        result.put("userId", jwtService.extractUserId(claims));
        result.put("role", jwtService.extractRole(claims));
        return result;
    }

    private TokenResponse issueTokens(Long userId, Role role) {
        return TokenResponse.builder()
                .accessToken(jwtService.generateAccessToken(userId, role))
                .refreshToken(jwtService.generateRefreshToken(userId, role))
                .build();
    }
}
