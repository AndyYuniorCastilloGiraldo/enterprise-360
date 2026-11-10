package auth_service.service.impl;

import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import auth_service.dto.RolCreateRequest;
import auth_service.dto.RolResponse;
import auth_service.entity.Rol;
import auth_service.exception.BusinessConflictException;
import auth_service.exception.ResourceNotFoundException;
import auth_service.repository.RolRepository;
import auth_service.service.RolService;

@Service
@Transactional
public class RolServiceImpl implements RolService {

    private final RolRepository rolRepository;

    public RolServiceImpl(RolRepository rolRepository) {
        this.rolRepository = rolRepository;
    }

    @Override
    public RolResponse crear(RolCreateRequest request) {
        if (rolRepository.existsByNombre(request.nombre())) {
            throw new BusinessConflictException("Ya existe un rol con el nombre indicado.");
        }

        Rol rol = Rol.builder()
                .nombre(request.nombre())
                .descripcion(request.descripcion())
                .build();
        return toResponse(rolRepository.save(rol));
    }

    @Override
    @Transactional(readOnly = true)
    public RolResponse obtenerPorId(UUID rolId) {
        return rolRepository.findById(rolId)
                .map(RolServiceImpl::toResponse)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "No se encontró el rol con ID " + rolId));
    }

    @Override
    @Transactional(readOnly = true)
    public RolResponse buscarPorNombre(String nombre) {
        return rolRepository.findByNombre(nombre)
                .map(RolServiceImpl::toResponse)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "No se encontró un rol con el nombre indicado."));
    }

    @Override
    @Transactional(readOnly = true)
    public List<RolResponse> listar() {
        return rolRepository.findAll().stream()
                .map(RolServiceImpl::toResponse)
                .toList();
    }

    private static RolResponse toResponse(Rol rol) {
        return new RolResponse(rol.getId(), rol.getNombre(), rol.getDescripcion());
    }
}
