package auth_service.dto;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record UsuarioCreateRequest(
        @NotNull UUID empresaId,
        @NotBlank @Size(max = 100) String nombres,
        @NotBlank @Size(max = 100) String apellidos,
        @NotBlank @Email @Size(max = 150) String email,
        @NotBlank @Size(min = 12, max = 72) String password) {

    @AssertTrue(message = "La contraseña no puede superar los 72 bytes UTF-8 admitidos por BCrypt.")
    public boolean isPasswordWithinBcryptLimit() {
        return password == null || password.getBytes(StandardCharsets.UTF_8).length <= 72;
    }
}
