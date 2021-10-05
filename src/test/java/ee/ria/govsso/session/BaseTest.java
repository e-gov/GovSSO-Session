package ee.ria.govsso.session;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import io.restassured.RestAssured;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;

import java.util.Base64;

import static io.restassured.config.RedirectConfig.redirectConfig;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT)
public abstract class BaseTest {

    protected static final WireMockServer wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpsPort(9877)
            .notifier(new ConsoleNotifier(true))
    );

    @LocalServerPort
    protected int port;

    @BeforeAll
    static void setUpAll() {
        ((LoggerContext) LoggerFactory.getILoggerFactory()).getLogger("wiremock").setLevel(Level.OFF);
        RestAssured.config = RestAssured.config().redirect(redirectConfig().followRedirects(false));
        wireMockServer.start();
    }

    @BeforeEach
    public void beforeEachTest() {
        RestAssured.port = port;
        wireMockServer.resetAll();
    }

    protected String decodeCookieFromBase64(String cookie) {
        byte[] decodedBytes = Base64.getDecoder().decode(cookie);
        return new String(decodedBytes);
    }

}
