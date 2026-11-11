package auth_service.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collection;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;

import auth_service.security.JwtAuthenticationFilter;
import jakarta.servlet.Filter;

/**
 * Verifica que {@link JwtAuthenticationFilter} no se registra dos veces:
 * <ul>
 *   <li>Existe exactamente un bean del filtro en el contexto de Spring.
 *   <li>El {@link FilterRegistrationBean} asociado está deshabilitado, por lo
 *       que Spring Boot <em>no</em> lo registra en el servlet container.
 *   <li>El filtro sigue siendo inyectable (el bean existe y es funcional).
 * </ul>
 */
@SpringBootTest
@ActiveProfiles("test")
class JwtFilterRegistrationTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private SecurityFilterChain securityFilterChain;

    @Autowired
    private FilterRegistrationBean<JwtAuthenticationFilter> jwtFilterRegistration;

    @Autowired
    private Collection<FilterRegistrationBean<?>> allRegistrations;

    /**
     * El bean del filtro existe y es inyectable desde el contexto de Spring.
     */
    @Test
    void jwtFilterEsBeanDeSpring() {
        assertThat(jwtAuthenticationFilter).isNotNull();
        assertThat(applicationContext.getBeansOfType(JwtAuthenticationFilter.class))
                .hasSize(1);
    }

    /**
     * El {@link FilterRegistrationBean} tiene {@code enabled = false}, lo que
     * impide que Spring Boot lo registre automáticamente en el servlet container.
     */
    @Test
    void filterRegistrationBeanEstaDeshabilitado() {
        assertThat(jwtFilterRegistration.isEnabled()).isFalse();
    }

    /**
     * El filtro envuelto en el {@link FilterRegistrationBean} es exactamente la
     * misma instancia que el bean {@link JwtAuthenticationFilter}.
     */
    @Test
    void filterRegistrationBeanEnvuelveElFiltroCorrecto() {
        Filter filtroEnvuelto = jwtFilterRegistration.getFilter();
        assertThat(filtroEnvuelto).isSameAs(jwtAuthenticationFilter);
    }

    /**
     * El filtro se incorpora exactamente una vez a la cadena de Spring Security.
     */
    @Test
    void filtroSeAgregaUnaSolaVezALaCadenaDeSeguridad() {
        assertThat(securityFilterChain.getFilters().stream()
                .filter(filter -> filter == jwtAuthenticationFilter))
                .hasSize(1);
    }

    /**
     * No existe ningún otro {@link FilterRegistrationBean} habilitado que
     * envuelva al {@link JwtAuthenticationFilter}, garantizando un único punto
     * de registro.
     */
    @Test
    void noExisteRegistrationBeanHabilitadoParaJwtFilter() {
        long habilitadosParaJwt = allRegistrations.stream()
                .filter(FilterRegistrationBean::isEnabled)
                .filter(r -> r.getFilter() instanceof JwtAuthenticationFilter)
                .count();

        assertThat(habilitadosParaJwt)
                .as("No debe haber FilterRegistrationBean habilitado para JwtAuthenticationFilter")
                .isZero();
    }
}
