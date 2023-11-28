package ee.ria.govsso.session.service.hydra;

import ch.qos.logback.classic.Level;
import ee.ria.govsso.session.BaseTest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

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
                "http.request.method=GET, url.full=https://hydra.localhost:9000/admin/oauth2/auth/requests/login?login_challenge=abcdeff098aadfccabcdeff098aadfcc");
        assertMessageWithMarkerIsLoggedOnce(HydraService.class, Level.INFO, "HYDRA response",
                "http.response.status_code=200, http.response.body.content={" +
                        "\"challenge\":\"abcdeff098aadfccabcdeff098aadfcc\"," +
                        "\"client\":{" +
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
}
