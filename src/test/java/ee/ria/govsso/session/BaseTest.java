package ee.ria.govsso.session;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.jwk.RSAKey;
import ee.ria.govsso.session.service.tara.TaraTestSetup;
import io.restassured.RestAssured;
import io.restassured.builder.RequestSpecBuilder;
import io.restassured.builder.ResponseSpecBuilder;
import io.restassured.filter.log.ResponseLoggingFilter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;

import java.util.HashMap;
import java.util.Map;

import static io.restassured.config.RedirectConfig.redirectConfig;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN;
import static org.springframework.http.HttpHeaders.ORIGIN;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT)
@Import({BuildProperties.class})
public abstract class BaseTest extends BaseTestLoggingAssertion {

    protected static final String TEST_LOGIN_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";

    public static final Map<String, Object> EXPECTED_RESPONSE_HEADERS_WITHOUT_CORS = new HashMap<>() {{
        put("X-XSS-Protection", "0");
        put("X-Content-Type-Options", "nosniff");
        put("X-Frame-Options", "DENY");
        put("Content-Security-Policy", "connect-src 'self'; default-src 'none'; font-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; block-all-mixed-content");
        put("Pragma", "no-cache");
        put("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        put("Expires", "0");
        put(ACCESS_CONTROL_ALLOW_ORIGIN, null);
        put(ACCESS_CONTROL_ALLOW_CREDENTIALS, null);
        // TODO: Use HTTPS for API tests. Given header only returned over https.
//        put("Strict-Transport-Security", "max-age=16070400 ; includeSubDomains");
    }};
    public static final Map<String, Object> EXPECTED_RESPONSE_HEADERS_WITH_CORS = new HashMap<>() {{
        putAll(EXPECTED_RESPONSE_HEADERS_WITHOUT_CORS);
        put(ACCESS_CONTROL_ALLOW_ORIGIN, "https://clienta.localhost:11443");
        put(ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
    }};
    protected static final String MOCK_CSRF_TOKEN = "d1341bfc-052d-448b-90f0-d7a7a9e4b842";
    protected static final String INPROXY_MOCK_URL = "https://inproxy.localhost:8000";
    protected static final String HYDRA_MOCK_URL = "https://hydra.localhost:9000";
    protected static final String TARA_MOCK_URL = "https://tara.localhost:10000";
    protected static final String ADMIN_MOCK_URL = "https://admin.localhost:11000";
    protected static final String PAASUKE_MOCK_URL = "https://paasuke.localhost:12000";
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
    protected static final WireMockServer ADMIN_MOCK_SERVER = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(11000)
            .keystorePath("src/test/resources/admin.localhost.keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .notifier(new ConsoleNotifier(true))
    );
    protected static final WireMockServer PAASUKE_MOCK_SERVER = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(12000)
            .keystorePath("src/test/resources/paasuke.localhost.keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .needClientAuth(true)
            .trustStorePath("src/test/resources/paasuke.localhost.client.truststore.p12")
            .trustStorePassword("changeit")
            .notifier(new ConsoleNotifier(true))
    );

    protected static final RSAKey TARA_JWK = TaraTestSetup.generateJWK();
    @LocalServerPort
    protected int port;

    @BeforeAll
    static void setUpAll() {
        configureRestAssured();
        HYDRA_MOCK_SERVER.start();
        ADMIN_MOCK_SERVER.start();
        PAASUKE_MOCK_SERVER.start();
        TARA_MOCK_SERVER.start();
        // TODO: Move to @BeforeEach?
        setUpTaraMetadataMocks();
    }

    @BeforeEach
    public void beforeEachTest() {
        RestAssured.requestSpecification.port(port);
        RestAssured.responseSpecification = new ResponseSpecBuilder()
                .expectHeaders(EXPECTED_RESPONSE_HEADERS_WITHOUT_CORS).build();
        HYDRA_MOCK_SERVER.resetAll();
        // TODO: Do not reset admin mock for now as it seems to create issued with scheduled update task
        // ADMIN_MOCK_SERVER.resetAll();
        PAASUKE_MOCK_SERVER.resetAll();
        // TODO: Do not reset TARA mock for now as it seems to create issued with scheduled update task
        // TARA_MOCK_SERVER.resetAll();
        // setUpTaraMetadataMocks();
    }

    private static void configureRestAssured() {
        RestAssured.filters(new ResponseLoggingFilter());
        RestAssured.config = RestAssured.config().redirect(redirectConfig().followRedirects(false));
        RestAssured.requestSpecification = new RequestSpecBuilder()
                .addHeader(ORIGIN, "https://clienta.localhost:11443")
                .build();
    }

    protected static void setUpTaraMetadataMocks() {
        setUpTaraMetadataMocks("mock_tara_oidc_metadata.json");
    }

    @SneakyThrows
    protected static void setUpTaraMetadataMocks(String metadataBodyFile) {
        TaraTestSetup.setUpMetadataMocks(TARA_MOCK_SERVER, metadataBodyFile, TARA_JWK);
    }
}
