package ee.ria.govsso.session;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import io.restassured.RestAssured;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT)
public abstract class BaseTest {

    protected static final WireMockServer wireMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(9877)
            .notifier(new ConsoleNotifier(true))
    );

    @LocalServerPort
    protected int port;

    @BeforeAll
    static void setUpAll() {
        wireMockServer.start();
    }

    @BeforeEach
    public void beforeEachTest() {
        RestAssured.port = port;
        wireMockServer.resetAll();
    }

}
