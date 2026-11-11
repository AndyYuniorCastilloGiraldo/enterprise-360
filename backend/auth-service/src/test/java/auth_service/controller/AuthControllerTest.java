package auth_service.controller;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import auth_service.dto.LoginRequest;
import auth_service.dto.LoginResponse;
import auth_service.exception.InvalidCredentialsException;
import auth_service.exception.ApiExceptionHandler;
import auth_service.service.AuthService;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private AuthService authService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new AuthController(authService))
                .setControllerAdvice(new ApiExceptionHandler())
                .build();
    }

    @Test
    void loginRespondeConTokenBearer() throws Exception {
        LoginResponse response = new LoginResponse(
                "signed.jwt.token", "refresh-token", "Bearer", 3600, 604800, null, null, List.of());
        when(authService.login(new LoginRequest(
                "20123456789", "ana@example.com", "Secure-passphrase-2026!")))
                .thenReturn(response);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "ruc": "20123456789",
                                  "email": "ana@example.com",
                                  "password": "Secure-passphrase-2026!"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("signed.jwt.token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresInSeconds").value(3600));

        verify(authService).login(new LoginRequest(
                "20123456789", "ana@example.com", "Secure-passphrase-2026!"));
    }

    @Test
    void loginRechazaDatosInvalidosConBadRequest() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "ruc": "123",
                                  "email": "no-es-email",
                                  "password": "corta"
                                }
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void credencialesInvalidasRespondenUnauthorized() throws Exception {
        when(authService.login(new LoginRequest(
                "20123456789", "ana@example.com", "Secure-passphrase-2026!")))
                .thenThrow(new InvalidCredentialsException());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "ruc": "20123456789",
                                  "email": "ana@example.com",
                                  "password": "Secure-passphrase-2026!"
                                }
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void cambioDeContrasenaRechazaContrasenasDemasiadoCortas() throws Exception {
        mockMvc.perform(post("/api/auth/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "currentPassword": "current",
                                  "newPassword": "short"
                                }
                                """))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(authService);
    }
}
