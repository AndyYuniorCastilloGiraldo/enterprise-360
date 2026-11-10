package auth_service.dto;

import java.util.UUID;

public record RolResponse(UUID id, String nombre, String descripcion) {
}
