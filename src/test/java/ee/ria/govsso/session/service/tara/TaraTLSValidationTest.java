package ee.ria.govsso.session.service.tara;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import ee.ria.govsso.session.error.exceptions.SsoException;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.net.ssl.SSLHandshakeException;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Disabled // TODO: Does not work since @Retryable exceptions are not thrown out of method.
@SpringBootTest(properties = "govsso.tara.issuer-url=https://tara.localhost:10001")
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class TaraTLSValidationTest {

    private final TaraMetadataService taraMetadataService;

    private final WireMockServer taraMockServer = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(10001)
            .keystorePath("src/test/resources/hydra.localhost.keystore.p12") // Hydra (invalid) keystore passed instead of TARA
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .notifier(new ConsoleNotifier(true))
    );

    @Test
    void updateMetadata_WhenUnableToFindValidCertificationPath_ThrowsSSLHandshakeException() {
        try {
            taraMockServer.start();
            TaraTestSetup.setUpMetadataMocks(taraMockServer, "mock_tara_oidc_metadata.json", TaraTestSetup.generateJWK());
            taraMetadataService.updateMetadata();
            fail("Exception expected");
        } catch (SsoException ex) {
            assertTrue(ex.getCause() instanceof SSLHandshakeException);
            assertThat("unable to find valid certification path to requested target",
                    equalTo(ex.getCause().getCause().getCause().getCause().getMessage()));
        } catch (Exception ex) {
            fail("Unexpected exception thrown");
        }
    }
}
