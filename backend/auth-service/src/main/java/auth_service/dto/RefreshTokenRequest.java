package auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Refresh token opaco vigente para rotar la sesión.")
public record RefreshTokenRequest(
        @Schema(format = "password", writeOnly = true)
        @NotBlank @Size(max = 128) String refreshToken) {
}
