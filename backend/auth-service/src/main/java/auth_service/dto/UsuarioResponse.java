package auth_service.dto;

import java.time.OffsetDateTime;
import java.util.UUID;

public record UsuarioResponse(
        UUID id,
        UUID empresaId,
        String nombres,
        String apellidos,
        String email,
        Boolean activo,
        OffsetDateTime createdAt) {
}
