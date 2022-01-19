package ee.ria.govsso.session;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.restassured.RestAssured;
import io.restassured.builder.ResponseSpecBuilder;
import io.restassured.filter.log.ResponseLoggingFilter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static io.restassured.config.RedirectConfig.redirectConfig;
import static java.util.List.of;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT)
public abstract class BaseTest {

    private static final Map<String, Object> EXPECTED_RESPONSE_HEADERS = new HashMap<>() {{
        put("X-XSS-Protection", "0");
        put("X-Content-Type-Options", "nosniff");
        put("X-Frame-Options", "DENY");
        put("Content-Security-Policy", "connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content");
        put("Pragma", "no-cache");
        put("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        put("Expires", "0");
    }};

    protected static final WireMockServer wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpsPort(9877)
            .notifier(new ConsoleNotifier(true))
    );
    protected static final RSAKey taraJWK = setUpTaraJwk();
    @LocalServerPort
    protected int port;

    @SneakyThrows
    static RSAKey setUpTaraJwk() {
        return new RSAKeyGenerator(4096)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
    }

    @BeforeAll
    static void setUpAll() {
        configureRestAssured();
        ((LoggerContext) LoggerFactory.getILoggerFactory()).getLogger("wiremock").setLevel(Level.OFF);
        wireMockServer.start();
        setUpTaraMetadataMocks();
    }

    private static void configureRestAssured() {
        RestAssured.filters(new ResponseLoggingFilter());
        RestAssured.config = RestAssured.config().redirect(redirectConfig().followRedirects(false));
    }

    protected static void setUpTaraMetadataMocks() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata.json");
    }

    @SneakyThrows
    protected static void setUpTaraMetadataMocks(String metadataBodyFile) {
        JWKSet jwkSet = new JWKSet(of(taraJWK));

        wireMockServer.stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/" + metadataBodyFile)));

        wireMockServer.stubFor(get(urlEqualTo("/oidc/jwks"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(jwkSet.toPublicJWKSet().toString())));
    }

    @BeforeEach
    public void beforeEachTest() {
        RestAssured.responseSpecification = new ResponseSpecBuilder().expectHeaders(EXPECTED_RESPONSE_HEADERS).build();
        RestAssured.port = port;
        wireMockServer.resetAll();
    }

    protected String decodeCookieFromBase64(String cookie) {
        byte[] decodedBytes = Base64.getDecoder().decode(cookie);
        return new String(decodedBytes);
    }
}
