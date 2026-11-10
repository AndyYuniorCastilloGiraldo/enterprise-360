package auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RolCreateRequest(
        @NotBlank @Size(max = 50) String nombre,
        @Size(max = 150) String descripcion) {
}
