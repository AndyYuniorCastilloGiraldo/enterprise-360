package auth_service.dto;

import java.util.List;

public record SessionInfoResponse(
        UsuarioResponse usuario,
        EmpresaResponse empresa,
        List<RolResponse> roles) {
}
