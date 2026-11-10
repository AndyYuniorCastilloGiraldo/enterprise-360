package auth_service.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
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
 *   <li>Endpoints públicos: {@code /api/auth/**} (registro y login futuros) y
 *       Actuator ({@code /actuator/**}).
 *   <li>Cualquier otra petición requiere autenticación válida mediante JWT.
 * </ul>
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfiguration(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                // Endpoints de autenticación (registro y login: implementación futura)
                .requestMatchers("/api/auth/**").permitAll()
                // Actuator: health e info públicos
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                // Todo lo demás requiere JWT válido
                .anyRequest().authenticated())
            .addFilterBefore(jwtAuthenticationFilter,
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}

