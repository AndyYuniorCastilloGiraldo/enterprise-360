package auth_service.service;

import java.util.List;
import java.util.UUID;

import auth_service.dto.RolCreateRequest;
import auth_service.dto.RolResponse;

public interface RolService {

    RolResponse crear(RolCreateRequest request);

    RolResponse obtenerPorId(UUID rolId);

    RolResponse buscarPorNombre(String nombre);

    List<RolResponse> listar();
}
