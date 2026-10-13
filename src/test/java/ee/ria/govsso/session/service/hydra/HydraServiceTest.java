package ee.ria.govsso.session.service.hydra;

import ch.qos.logback.classic.Level;
import ee.ria.govsso.session.BaseTest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class HydraServiceTest extends BaseTest {

    private final HydraService hydraService;

    @Test
    void fetchLoginRequestInfo_logoIsMaskedInResponseLog() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(TEST_LOGIN_CHALLENGE);

        assertThat(loginRequestInfo.getClient().getMetadata().getOidcClient().getLogo(), equalTo("test-logo"));

        assertMessageWithMarkerIsLoggedOnce(HydraService.class, Level.INFO, "HYDRA request",
                "http.request.method=GET, url.full=https://hydra.localhost:9000/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE);
        assertMessageWithMarkerIsLoggedOnce(HydraService.class, Level.INFO, "HYDRA response",
                "http.response.status_code=200, http.response.body.content={" +
                        "\"challenge\":\"" + TEST_LOGIN_CHALLENGE + "\"," +
                        "\"client\":{" +
                            "\"audience\":[]," +
                            "\"client_id\":\"openIdDemo\"," +
                            "\"client_name\":\"\"," +
                            "\"metadata\":{" +
                                "\"display_user_consent\":false," +
                                "\"oidc_client\":{" +
                                    "\"institution\":{" +
                                        "\"registry_code\":\"70000001\"," +
                                        "\"sector\":\"public\"" +
                                    "}," +
                                    "\"logo\":\"[9] chars\","
        );
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://inproxy.localhost:8000",
            "https://inproxy.localhost:8000/",
            "https://inproxy.localhost:8000/some/path",
            "https://inproxy.localhost",
            "https://inproxy.localhost:443/",
            "HTTPS://INPROXY.LOCALHOST:8000/",
            "http://inproxy.localhost:8000/"
    })
    void hasGovSsoAsAudience_WhenAudienceHostIsGovSsoHost_ReturnsTrue(String audience) {
        assertThat(hydraService.hasGovSsoAsAudience(List.of("https://test1", audience)), equalTo(true));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://test1",
            "https://inproxy.localhost.example.com:8000/",
            "https://example.com/inproxy.localhost:8000",
            "https://example.com/?redirect=https://inproxy.localhost:8000",
            "urn:example:api",
            "my-api",
            "not a valid uri"
    })
    void hasGovSsoAsAudience_WhenAudienceHostIsNotGovSsoHost_ReturnsFalse(String audience) {
        assertThat(hydraService.hasGovSsoAsAudience(List.of(audience)), equalTo(false));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void hasGovSsoAsAudience_WhenAudienceIsNullOrEmpty_ReturnsFalse(List<String> audience) {
        assertThat(hydraService.hasGovSsoAsAudience(audience), equalTo(false));
    }
}
