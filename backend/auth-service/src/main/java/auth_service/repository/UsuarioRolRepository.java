package auth_service.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import auth_service.entity.UsuarioRol;
import auth_service.entity.UsuarioRolId;

public interface UsuarioRolRepository extends JpaRepository<UsuarioRol, UsuarioRolId> {

    @Query("""
            select usuarioRol
            from UsuarioRol usuarioRol
            join fetch usuarioRol.rol
            where usuarioRol.usuario.id = :usuarioId
            """)
    List<UsuarioRol> findAllByUsuarioId(@Param("usuarioId") UUID usuarioId);
}
