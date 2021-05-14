package learning.micronaut.security.authentication.client;

import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.inject.Inject;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.*;

@MicronautTest
public class DeclarativeHttpClientWithJwtSpec {

    @Inject
    AppClient appClient;

    @Test
    void verifyJwtAuthenticationWorksWithDeclarativeClient() throws ParseException {
        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("sherlock", "password");
        BearerAccessRefreshToken bearerAccessRefreshToken = appClient.login(credentials);

        assertNotNull(bearerAccessRefreshToken);
        assertNotNull(bearerAccessRefreshToken.getAccessToken());
        assertTrue(JWTParser.parse(bearerAccessRefreshToken.getAccessToken()) instanceof SignedJWT);

        String message = appClient.home("Bearer "+bearerAccessRefreshToken.getAccessToken());
        assertEquals("sherlock", message);
    }
}
