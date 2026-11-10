package auth_service.config;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

class PasswordEncoderConfigurationTest {

    @Test
    void configuraBCryptComoPasswordEncoder() {
        try (AnnotationConfigApplicationContext context =
                new AnnotationConfigApplicationContext(PasswordEncoderConfiguration.class)) {
            assertInstanceOf(BCryptPasswordEncoder.class, context.getBean(PasswordEncoder.class));
        }
    }
}
