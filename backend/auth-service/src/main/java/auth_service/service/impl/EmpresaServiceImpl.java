package auth_service.service.impl;

import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import auth_service.dto.EmpresaCreateRequest;
import auth_service.dto.EmpresaResponse;
import auth_service.entity.Empresa;
import auth_service.exception.BusinessConflictException;
import auth_service.exception.ResourceNotFoundException;
import auth_service.repository.EmpresaRepository;
import auth_service.service.EmpresaService;

@Service
@Transactional
public class EmpresaServiceImpl implements EmpresaService {

    private final EmpresaRepository empresaRepository;

    public EmpresaServiceImpl(EmpresaRepository empresaRepository) {
        this.empresaRepository = empresaRepository;
    }

    @Override
    public EmpresaResponse registrar(EmpresaCreateRequest request) {
        if (request.ruc() != null && empresaRepository.findByRuc(request.ruc()).isPresent()) {
            throw new BusinessConflictException("Ya existe una empresa con el RUC indicado.");
        }

        Empresa empresa = Empresa.builder()
                .razonSocial(request.razonSocial())
                .ruc(request.ruc())
                .activo(true)
                .build();
        return toResponse(empresaRepository.save(empresa));
    }

    @Override
    @Transactional(readOnly = true)
    public EmpresaResponse obtenerPorId(UUID empresaId) {
        return empresaRepository.findById(empresaId)
                .map(EmpresaServiceImpl::toResponse)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "No se encontró la empresa con ID " + empresaId));
    }

    @Override
    @Transactional(readOnly = true)
    public EmpresaResponse buscarPorRuc(String ruc) {
        return empresaRepository.findByRuc(ruc)
                .map(EmpresaServiceImpl::toResponse)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "No se encontró una empresa con el RUC indicado."));
    }

    private static EmpresaResponse toResponse(Empresa empresa) {
        return new EmpresaResponse(
                empresa.getId(),
                empresa.getRazonSocial(),
                empresa.getRuc(),
                empresa.getActivo(),
                empresa.getCreatedAt());
    }
}
