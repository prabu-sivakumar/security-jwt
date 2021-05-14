package learning.micronaut.security.authentication;

import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.MediaType;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.client.exceptions.HttpClientResponseException;
import io.micronaut.security.authentication.UsernamePasswordCredentials;
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import org.junit.jupiter.api.Test;

import javax.inject.Inject;

import java.text.ParseException;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@MicronautTest
public class JwtAuthenticationSpec {

    @Inject
    @Client("/")
    HttpClient httpClient;

    @Test
    void accessSecuredUrlWithoutAuthenticatingReturnsUnauthorized() {
        HttpClientResponseException httpClientResponseException = assertThrows(HttpClientResponseException.class, () -> {
            httpClient.toBlocking().exchange(HttpRequest.GET("/").accept(MediaType.TEXT_PLAIN));
        });
        assertEquals(httpClientResponseException.getStatus(), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void uponSuccessfulAuthenticationAJsonWebTokenIsIssuedToTheUser() throws ParseException {
        UsernamePasswordCredentials credentials = new UsernamePasswordCredentials("sherlock", "password");
        HttpRequest request = HttpRequest.POST("/login", credentials);
        HttpResponse<BearerAccessRefreshToken> response = httpClient.toBlocking().exchange(request, BearerAccessRefreshToken.class);
        assertEquals(HttpStatus.OK, response.getStatus());

        BearerAccessRefreshToken bearerAccessRefreshToken = response.body();
        assertEquals("sherlock", bearerAccessRefreshToken.getUsername());
        assertNotNull(bearerAccessRefreshToken.getAccessToken());
        assertTrue(JWTParser.parse(bearerAccessRefreshToken.getAccessToken()) instanceof SignedJWT);

        String accessToken = bearerAccessRefreshToken.getAccessToken();
        HttpRequest requestWithAuthorization = HttpRequest.GET("/")
                .accept(MediaType.TEXT_PLAIN)
                .bearerAuth(accessToken);
        HttpResponse<String> httpResponse = httpClient.toBlocking().exchange(requestWithAuthorization, String.class);
        assertEquals(HttpStatus.OK, httpResponse.getStatus());
        Optional<String> payload = httpResponse.getBody();
        if (payload.isPresent())
            assertEquals("sherlock", payload.get());
    }

}