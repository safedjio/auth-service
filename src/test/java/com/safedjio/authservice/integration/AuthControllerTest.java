package com.safedjio.authservice.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.safedjio.authservice.entity.Role;
import com.safedjio.authservice.repository.CredentialRepository;
import com.safedjio.authservice.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
public class AuthControllerTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CredentialRepository repository;

    @Autowired
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    void shouldRegisterLoginAndValidateToken() throws Exception {
        String registerJson = """
                {
                    "userId": 99,
                    "login": "test_user",
                    "password": "secret_password",
                    "role": "ADMIN"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson))
                .andExpect(status().isCreated());

        String loginJson = """
                {
                    "login": "test_user",
                    "password": "secret_password"
                }
                """;

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andReturn();

        String responseBody = loginResult.getResponse().getContentAsString();
        ObjectMapper mapper = new ObjectMapper();
        String accessToken = mapper.readTree(responseBody).get("accessToken").asText();

        String validateJson = String.format("{\"token\": \"%s\"}", accessToken);

        mockMvc.perform(post("/api/v1/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validateJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.userId").value(99))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void shouldRejectAdminEndpointWithoutToken() throws Exception {
        String registerJson = """
                {
                    "userId": 100,
                    "login": "no_token_admin",
                    "password": "secret_password",
                    "role": "ADMIN"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/admin/credentials")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectAdminEndpointForUserRole() throws Exception {
        String userToken = jwtService.generateAccessToken(1L, Role.USER);

        String registerJson = """
                {
                    "userId": 101,
                    "login": "escalation_attempt",
                    "password": "secret_password",
                    "role": "ADMIN"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/admin/credentials")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson))
                .andExpect(status().isForbidden());
    }

    @Test
    void shouldRegisterAdminThroughAdminEndpoint() throws Exception {
        String adminToken = jwtService.generateAccessToken(1L, Role.ADMIN);

        String registerJson = """
                {
                    "userId": 102,
                    "login": "new_admin",
                    "password": "secret_password",
                    "role": "ADMIN"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/admin/credentials")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson))
                .andExpect(status().isCreated());

        String loginJson = """
                {
                    "login": "new_admin",
                    "password": "secret_password"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isOk());
    }

    @Test
    void shouldRejectValidateAfterDeactivation() throws Exception {
        String adminToken = jwtService.generateAccessToken(1L, Role.ADMIN);

        String registerJson = """
                {
                    "userId": 103,
                    "login": "to_deactivate",
                    "password": "secret_password"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson))
                .andExpect(status().isCreated());

        String loginJson = """
                {
                    "login": "to_deactivate",
                    "password": "secret_password"
                }
                """;

        MvcResult loginResult = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isOk())
                .andReturn();

        String accessToken = new ObjectMapper()
                .readTree(loginResult.getResponse().getContentAsString())
                .get("accessToken").asText();

        mockMvc.perform(patch("/api/v1/auth/admin/credentials/103/status")
                        .header("Authorization", "Bearer " + adminToken)
                        .param("active", "false"))
                .andExpect(status().isNoContent());

        String validateJson = String.format("{\"token\": \"%s\"}", accessToken);

        mockMvc.perform(post("/api/v1/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validateJson))
                .andExpect(status().isUnauthorized());
    }
}