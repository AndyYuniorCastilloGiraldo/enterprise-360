package auth_service.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import auth_service.security.JwtAuthenticationFilter;

/**
 * Configuración central de Spring Security.
 *
 * <ul>
 *   <li>Sesiones STATELESS: no se crean sesiones HTTP.
 *   <li>CSRF desactivado (API REST sin estado).
 *   <li>Endpoints públicos de autenticación: {@code /api/auth/**} y
 *       Actuator ({@code /actuator/health}, {@code /actuator/info}).
 *   <li>Cualquier otra petición requiere autenticación válida mediante JWT.
 * </ul>
 *
 * <h3>Registro único del filtro JWT</h3>
 * {@link JwtAuthenticationFilter} es un {@code @Component} de Spring, lo que
 * hace que Spring Boot Auto-Configuration lo registre automáticamente como
 * filtro del servlet container <em>además</em> de que
 * {@link #securityFilterChain} lo añade al {@code SecurityFilterChain}.
 * Para evitar esa doble ejecución se declara un
 * {@link FilterRegistrationBean} con {@code enabled = false}: el bean sigue
 * existiendo en el contexto de Spring (y puede inyectarse), pero <strong>no</strong>
 * se registra en el {@code ServletContext}; sólo actúa dentro de la cadena de
 * seguridad.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfiguration(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    /**
     * Suprime el registro automático de {@link JwtAuthenticationFilter} en el
     * servlet container. El filtro sigue siendo un bean de Spring y se añade
     * manualmente al {@link SecurityFilterChain} mediante
     * {@code addFilterBefore}.
     */
    @Bean
    FilterRegistrationBean<JwtAuthenticationFilter> jwtFilterRegistration() {
        FilterRegistrationBean<JwtAuthenticationFilter> registration =
                new FilterRegistrationBean<>(jwtAuthenticationFilter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/api/auth/login",
                    "/api/auth/refresh",
                    "/v3/api-docs/**",
                    "/swagger-ui/**",
                    "/swagger-ui.html").permitAll()
                // Actuator: health e info públicos
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                .requestMatchers("/api/auth/**").authenticated()
                .anyRequest().authenticated())
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((request, response, exception) ->
                    response.setStatus(jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED))
                .accessDeniedHandler((request, response, exception) ->
                    response.setStatus(jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN)))
            .addFilterBefore(jwtAuthenticationFilter,
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
