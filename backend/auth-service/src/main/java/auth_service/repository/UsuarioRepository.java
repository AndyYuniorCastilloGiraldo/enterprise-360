package auth_service.repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import auth_service.entity.Usuario;

public interface UsuarioRepository extends JpaRepository<Usuario, UUID> {

    Optional<Usuario> findByEmailAndEmpresa_Id(String email, UUID empresaId);

    Optional<Usuario> findByIdAndEmpresa_Id(UUID id, UUID empresaId);

    List<Usuario> findAllByEmpresa_Id(UUID empresaId);

    boolean existsByEmailAndEmpresa_Id(String email, UUID empresaId);
}
