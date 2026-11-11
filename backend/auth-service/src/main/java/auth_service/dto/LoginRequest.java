package auth_service.dto;

import java.nio.charset.StandardCharsets;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Credenciales para iniciar sesión en una empresa.")
public record LoginRequest(
        @Schema(description = "RUC de la empresa", example = "20123456789")
        @NotBlank @Size(min = 11, max = 11) String ruc,
        @Schema(description = "Correo del usuario dentro de la empresa", example = "usuario@empresa.com")
        @NotBlank @Email @Size(max = 150) String email,
        @Schema(description = "Contraseña de la cuenta", format = "password", writeOnly = true)
        @NotBlank @Size(max = 72) String password) {

    @AssertTrue(message = "La contraseña no puede superar los 72 bytes UTF-8 admitidos por BCrypt.")
    public boolean isPasswordWithinBcryptLimit() {
        return password == null || password.getBytes(StandardCharsets.UTF_8).length <= 72;
    }
}
