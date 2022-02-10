package ee.ria.govsso.session;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.jwk.RSAKey;
import ee.ria.govsso.session.service.tara.TaraTestSetup;
import io.restassured.RestAssured;
import io.restassured.builder.ResponseSpecBuilder;
import io.restassured.filter.log.ResponseLoggingFilter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.LoggerFactory;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;

import java.util.HashMap;
import java.util.Map;

import static io.restassured.config.RedirectConfig.redirectConfig;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT)
@Import({BuildProperties.class})
public abstract class BaseTest {

    protected static final String MOCK_CSRF_TOKEN = "d1341bfc-052d-448b-90f0-d7a7a9e4b842";
    private static final Map<String, Object> EXPECTED_RESPONSE_HEADERS = new HashMap<>() {{
        put("X-XSS-Protection", "0");
        put("X-Content-Type-Options", "nosniff");
        put("X-Frame-Options", "DENY");
        put("Content-Security-Policy", "connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self'; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content");
        put("Pragma", "no-cache");
        put("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        put("Expires", "0");
        // TODO: Returned during actual application run but for some reason not returned during tests
//        put("Strict-Transport-Security", "max-age=16070400 ; includeSubDomains");
    }};

    protected static final String GATEWAY_MOCK_URL = "https://gateway.localhost:8000";
    protected static final String HYDRA_MOCK_URL = "https://hydra.localhost:9000";
    protected static final String TARA_MOCK_URL = "https://tara.localhost:10000";

    protected static final WireMockServer HYDRA_MOCK_SERVER = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(9000)
            .keystorePath("src/test/resources/hydra.localhost.keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .notifier(new ConsoleNotifier(true))
    );

    protected static final WireMockServer TARA_MOCK_SERVER = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(10000)
            .keystorePath("src/test/resources/tara.localhost.keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .notifier(new ConsoleNotifier(true))
    );

    protected static final RSAKey TARA_JWK = TaraTestSetup.generateJWK();
    @LocalServerPort
    protected int port;

    @BeforeAll
    static void setUpAll() {
        configureRestAssured();
        ((LoggerContext) LoggerFactory.getILoggerFactory()).getLogger("wiremock").setLevel(Level.OFF);
        HYDRA_MOCK_SERVER.start();
        setUpTaraMetadataMocks();
    }

    private static void configureRestAssured() {
        RestAssured.filters(new ResponseLoggingFilter());
        RestAssured.config = RestAssured.config().redirect(redirectConfig().followRedirects(false));
    }

    protected static void setUpTaraMetadataMocks() {
        TARA_MOCK_SERVER.start();
        setUpTaraMetadataMocks("mock_tara_oidc_metadata.json");
    }

    @SneakyThrows
    protected static void setUpTaraMetadataMocks(String metadataBodyFile) {
        TaraTestSetup.setUpMetadataMocks(TARA_MOCK_SERVER, metadataBodyFile, TARA_JWK);
    }

    @BeforeEach
    public void beforeEachTest() {
        // TODO GSSO-245 Consider using custom RequestSpecification/ResponseSpecification for common CORS header assertion
        RestAssured.responseSpecification = new ResponseSpecBuilder().expectHeaders(EXPECTED_RESPONSE_HEADERS).build();
        RestAssured.port = port;
        HYDRA_MOCK_SERVER.resetAll();
    }
}
