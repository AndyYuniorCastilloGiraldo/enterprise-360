package auth_service.security;

import java.io.IOException;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import auth_service.service.SessionTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.jsonwebtoken.JwtException;

/**
 * Filtro que intercepta cada petición HTTP, extrae el token JWT del encabezado
 * {@code Authorization: Bearer <token>} y, si es válido, establece la
 * autenticación en el {@link SecurityContextHolder}.
 *
 * <p>Si el encabezado está ausente o el token no es válido, la petición continúa
 * sin autenticación (Spring Security aplicará las reglas de acceso configuradas
 * en {@link SecurityConfiguration}).
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String AUTH_HEADER = "Authorization";
    private static final int MAX_ACCESS_TOKEN_LENGTH = 8_192;
    private final JwtService jwtService;
    private final SessionTokenService sessionTokenService;

    public JwtAuthenticationFilter(
            JwtService jwtService,
            SessionTokenService sessionTokenService) {
        this.jwtService = jwtService;
        this.sessionTokenService = sessionTokenService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader(AUTH_HEADER);

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(BEARER_PREFIX.length());
        if (token.isBlank() || token.length() > MAX_ACCESS_TOKEN_LENGTH) {
            filterChain.doFilter(request, response);
            return;
        }

        AuthPrincipal principal;
        try {
            principal = jwtService.parsearPrincipal(token);
        } catch (JwtException | IllegalArgumentException exception) {
            filterChain.doFilter(request, response);
            return;
        }

        if (!sessionTokenService.isActive(principal)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            principal, null, principal.authorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }

}
