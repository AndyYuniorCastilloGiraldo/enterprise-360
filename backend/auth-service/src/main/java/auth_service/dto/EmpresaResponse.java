package auth_service.dto;

import java.time.OffsetDateTime;
import java.util.UUID;

public record EmpresaResponse(
        UUID id,
        String razonSocial,
        String ruc,
        Boolean activo,
        OffsetDateTime createdAt) {
}
