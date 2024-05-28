package ee.ria.govsso.session.service.hydra;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import ee.ria.govsso.session.Application;
import ee.ria.govsso.session.MockPropertyBeanConfiguration;
import lombok.RequiredArgsConstructor;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.web.reactive.function.client.WebClientRequestException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Import({BuildProperties.class})
@SpringBootTest(properties = "govsso.hydra.admin-url=https://hydra.localhost:9001",
        classes = {Application.class, MockPropertyBeanConfiguration.class})
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class HydraServiceTLSValidationTest {

    private final HydraService hydraService;

    private final WireMockServer hydraMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(9001)
            .keystorePath("src/test/resources/tara.localhost.keystore.p12") // TARA (invalid) keystore passed instead of Hydra
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .notifier(new ConsoleNotifier(true))
    );

    @Test
    void fetchLoginRequestInfo_WhenUnableToFindValidCertificationPath_ThrowsWebClientRequestException() {
        hydraMockServer.start();
        WebClientRequestException exception = assertThrows(WebClientRequestException.class, () -> {
            hydraService.fetchLoginRequestInfo("loginChallenge123");
        });

        assertThat(exception.getCause().getCause().getCause().getMessage(),
                Matchers.equalTo("unable to find valid certification path to requested target"));
    }
}
