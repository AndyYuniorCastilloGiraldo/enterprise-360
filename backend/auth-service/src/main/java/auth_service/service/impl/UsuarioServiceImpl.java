package auth_service.service.impl;

import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import auth_service.dto.RolResponse;
import auth_service.dto.UsuarioCreateRequest;
import auth_service.dto.UsuarioResponse;
import auth_service.entity.Empresa;
import auth_service.entity.Rol;
import auth_service.entity.Usuario;
import auth_service.entity.UsuarioRol;
import auth_service.entity.UsuarioRolId;
import auth_service.exception.BusinessConflictException;
import auth_service.exception.ResourceNotFoundException;
import auth_service.repository.EmpresaRepository;
import auth_service.repository.RolRepository;
import auth_service.repository.UsuarioRepository;
import auth_service.repository.UsuarioRolRepository;
import auth_service.service.UsuarioService;

@Service
@Transactional
public class UsuarioServiceImpl implements UsuarioService {

    private final UsuarioRepository usuarioRepository;
    private final EmpresaRepository empresaRepository;
    private final RolRepository rolRepository;
    private final UsuarioRolRepository usuarioRolRepository;

    public UsuarioServiceImpl(
            UsuarioRepository usuarioRepository,
            EmpresaRepository empresaRepository,
            RolRepository rolRepository,
            UsuarioRolRepository usuarioRolRepository) {
        this.usuarioRepository = usuarioRepository;
        this.empresaRepository = empresaRepository;
        this.rolRepository = rolRepository;
        this.usuarioRolRepository = usuarioRolRepository;
    }

    @Override
    public UsuarioResponse registrar(UsuarioCreateRequest request) {
        Empresa empresa = empresaRepository.findById(request.empresaId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "No se encontró la empresa con ID " + request.empresaId()));

        if (usuarioRepository.existsByEmailAndEmpresa_Id(request.email(), request.empresaId())) {
            throw new BusinessConflictException("Ya existe un usuario con ese email en la empresa.");
        }

        Usuario usuario = Usuario.builder()
                .empresa(empresa)
                .nombres(request.nombres())
                .apellidos(request.apellidos())
                .email(request.email())
                .passwordHash(request.passwordHash())
                .activo(true)
                .build();
        return toResponse(usuarioRepository.save(usuario));
    }

    @Override
    @Transactional(readOnly = true)
    public UsuarioResponse obtenerPorId(UUID usuarioId, UUID empresaId) {
        return usuarioRepository.findByIdAndEmpresa_Id(usuarioId, empresaId)
                .map(UsuarioServiceImpl::toResponse)
                .orElseThrow(() -> usuarioNotFound(usuarioId, empresaId));
    }

    @Override
    @Transactional(readOnly = true)
    public UsuarioResponse buscarPorEmailYEmpresa(String email, UUID empresaId) {
        return usuarioRepository.findByEmailAndEmpresa_Id(email, empresaId)
                .map(UsuarioServiceImpl::toResponse)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "No se encontró el usuario con el email indicado en la empresa."));
    }

    @Override
    @Transactional(readOnly = true)
    public List<UsuarioResponse> listarPorEmpresa(UUID empresaId) {
        requireEmpresa(empresaId);
        return usuarioRepository.findAllByEmpresa_Id(empresaId).stream()
                .map(UsuarioServiceImpl::toResponse)
                .toList();
    }

    @Override
    public UsuarioResponse cambiarEstado(UUID usuarioId, UUID empresaId, boolean activo) {
        Usuario usuario = findUsuario(usuarioId, empresaId);
        usuario.setActivo(activo);
        return toResponse(usuarioRepository.save(usuario));
    }

    @Override
    public List<RolResponse> asignarRol(UUID usuarioId, UUID empresaId, UUID rolId) {
        Usuario usuario = findUsuario(usuarioId, empresaId);
        Rol rol = rolRepository.findById(rolId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "No se encontró el rol con ID " + rolId));
        UsuarioRolId id = new UsuarioRolId(usuarioId, rolId);
        if (usuarioRolRepository.existsById(id)) {
            throw new BusinessConflictException("El usuario ya tiene asignado ese rol.");
        }

        usuarioRolRepository.save(UsuarioRol.builder()
                .id(id)
                .usuario(usuario)
                .rol(rol)
                .build());
        return listarRoles(usuarioId, empresaId);
    }

    @Override
    @Transactional(readOnly = true)
    public List<RolResponse> listarRoles(UUID usuarioId, UUID empresaId) {
        findUsuario(usuarioId, empresaId);
        return usuarioRolRepository.findAllByUsuarioId(usuarioId).stream()
                .map(usuarioRol -> {
                    Rol rol = usuarioRol.getRol();
                    return new RolResponse(rol.getId(), rol.getNombre(), rol.getDescripcion());
                })
                .toList();
    }

    private Usuario findUsuario(UUID usuarioId, UUID empresaId) {
        return usuarioRepository.findByIdAndEmpresa_Id(usuarioId, empresaId)
                .orElseThrow(() -> usuarioNotFound(usuarioId, empresaId));
    }

    private void requireEmpresa(UUID empresaId) {
        if (!empresaRepository.existsById(empresaId)) {
            throw new ResourceNotFoundException("No se encontró la empresa con ID " + empresaId);
        }
    }

    private static ResourceNotFoundException usuarioNotFound(UUID usuarioId, UUID empresaId) {
        return new ResourceNotFoundException(
                "No se encontró el usuario con ID " + usuarioId + " en la empresa " + empresaId);
    }

    private static UsuarioResponse toResponse(Usuario usuario) {
        return new UsuarioResponse(
                usuario.getId(),
                usuario.getEmpresa().getId(),
                usuario.getNombres(),
                usuario.getApellidos(),
                usuario.getEmail(),
                usuario.getActivo(),
                usuario.getCreatedAt());
    }
}
