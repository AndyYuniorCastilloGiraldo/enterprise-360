package auth_service.service;

import java.util.UUID;

import auth_service.dto.EmpresaCreateRequest;
import auth_service.dto.EmpresaResponse;

public interface EmpresaService {

    EmpresaResponse registrar(EmpresaCreateRequest request);

    EmpresaResponse obtenerPorId(UUID empresaId);

    EmpresaResponse buscarPorRuc(String ruc);
}
