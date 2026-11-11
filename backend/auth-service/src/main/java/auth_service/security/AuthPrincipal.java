package auth_service.security;

import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Stream;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Claims de identidad verificados criptográficamente.
 *
 * <p>Los permisos futuros pueden publicarse como autoridades {@code PERM_*} y
 * comprobarse con expresiones de método como {@code hasAuthority("PERM_...")}.
 */
public record AuthPrincipal(
        UUID usuarioId,
        UUID empresaId,
        UUID sessionId,
        List<String> roles,
        List<String> permissions) implements Principal {

    public AuthPrincipal {
        Objects.requireNonNull(usuarioId);
        Objects.requireNonNull(empresaId);
        Objects.requireNonNull(sessionId);
        roles = List.copyOf(roles);
        permissions = List.copyOf(permissions);
    }

    public AuthPrincipal(
            UUID usuarioId,
            UUID empresaId,
            UUID sessionId,
            List<String> roles) {
        this(usuarioId, empresaId, sessionId, roles, List.of());
    }

    @Override
    public String getName() {
        return usuarioId.toString();
    }

    public Collection<? extends GrantedAuthority> authorities() {
        return Stream.concat(
                        roles.stream().map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role),
                        permissions.stream().map(permission ->
                                permission.startsWith("PERM_") ? permission : "PERM_" + permission))
                .distinct()
                .map(SimpleGrantedAuthority::new)
                .toList();
    }
}
