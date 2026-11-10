package auth_service.service;

import java.util.List;
import java.util.UUID;

import auth_service.dto.RolResponse;
import auth_service.dto.UsuarioCreateRequest;
import auth_service.dto.UsuarioResponse;

public interface UsuarioService {

    UsuarioResponse registrar(UsuarioCreateRequest request);

    UsuarioResponse obtenerPorId(UUID usuarioId, UUID empresaId);

    UsuarioResponse buscarPorEmailYEmpresa(String email, UUID empresaId);

    List<UsuarioResponse> listarPorEmpresa(UUID empresaId);

    UsuarioResponse cambiarEstado(UUID usuarioId, UUID empresaId, boolean activo);

    List<RolResponse> asignarRol(UUID usuarioId, UUID empresaId, UUID rolId);

    List<RolResponse> listarRoles(UUID usuarioId, UUID empresaId);
}
