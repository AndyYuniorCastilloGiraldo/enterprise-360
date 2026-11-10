package auth_service.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record EmpresaCreateRequest(
        @NotBlank @Size(max = 150) String razonSocial,
        @Size(max = 11) String ruc) {
}
