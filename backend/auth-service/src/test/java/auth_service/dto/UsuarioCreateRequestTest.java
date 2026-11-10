package auth_service.dto;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;

class UsuarioCreateRequestTest {

    private static ValidatorFactory validatorFactory;
    private static Validator validator;

    @BeforeAll
    static void setUpValidator() {
        validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @AfterAll
    static void closeValidator() {
        validatorFactory.close();
    }

    @Test
    void aceptaContrasenaValida() {
        assertTrue(validator.validate(request("Secure-passphrase-2026!")).isEmpty());
    }

    @Test
    void rechazaContrasenaDemasiadoCorta() {
        assertFalse(validator.validate(request("short")).isEmpty());
    }

    @Test
    void rechazaContrasenaQueSuperaLimiteUtf8DeBcrypt() {
        assertFalse(validator.validate(request("界".repeat(25))).isEmpty());
    }

    private static UsuarioCreateRequest request(String password) {
        return new UsuarioCreateRequest(
                UUID.randomUUID(), "Ana", "Pérez", "ana@example.com", password);
    }
}
