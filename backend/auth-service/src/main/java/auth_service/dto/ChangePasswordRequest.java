package auth_service.dto;

import java.nio.charset.StandardCharsets;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Cambio de contraseña de la sesión autenticada.")
public record ChangePasswordRequest(
        @Schema(format = "password", writeOnly = true)
        @NotBlank @Size(max = 72) String currentPassword,
        @Schema(format = "password", writeOnly = true)
        @NotBlank @Size(min = 12, max = 72) String newPassword) {

    @AssertTrue(message = "La contraseña actual no puede superar los 72 bytes UTF-8 admitidos por BCrypt.")
    public boolean isCurrentPasswordWithinBcryptLimit() {
        return currentPassword == null
                || currentPassword.getBytes(StandardCharsets.UTF_8).length <= 72;
    }

    @AssertTrue(message = "La nueva contraseña no puede superar los 72 bytes UTF-8 admitidos por BCrypt.")
    public boolean isNewPasswordWithinBcryptLimit() {
        return newPassword == null
                || newPassword.getBytes(StandardCharsets.UTF_8).length <= 72;
    }
}
