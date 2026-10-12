package ee.ria.govsso.session.service.hydra;

import ch.qos.logback.classic.Level;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class HydraServiceTest extends BaseTest {

    private static final String TEST_AUTH_HANDOVER_TOKEN = "test-auth-handover-token";

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

    @Test
    void consumeAuthHandoverToken_noContent_ok() {
        HYDRA_MOCK_SERVER.stubFor(post(urlEqualTo("/admin/oauth2/auth/handover/consume"))
                .withHeader("Content-Type", containing("application/x-www-form-urlencoded"))
                .withFormParam("token", com.github.tomakehurst.wiremock.client.WireMock.equalTo(TEST_AUTH_HANDOVER_TOKEN))
                .willReturn(aResponse()
                        .withStatus(204)));

        hydraService.consumeAuthHandoverToken(TEST_AUTH_HANDOVER_TOKEN);

        HYDRA_MOCK_SERVER.verify(1, postRequestedFor(urlEqualTo("/admin/oauth2/auth/handover/consume")));
    }

    @Test
    void consumeAuthHandoverToken_conflict_throwsUserInput() {
        HYDRA_MOCK_SERVER.stubFor(post(urlEqualTo("/admin/oauth2/auth/handover/consume"))
                .willReturn(aResponse()
                        .withStatus(409)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("{\"error\":\"invalid_request\"}")));

        SsoException ex = assertThrows(SsoException.class,
                () -> hydraService.consumeAuthHandoverToken(TEST_AUTH_HANDOVER_TOKEN));

        assertThat(ex.getErrorCode(), equalTo(ErrorCode.USER_INPUT));
        assertThat(ex.getMessage(), equalTo("Auth handover token has already been consumed, revoked or expired"));
        assertThat(ex.getCause(), nullValue());
    }

    @Test
    void consumeAuthHandoverToken_serverError_throwsTechnicalGeneral() {
        HYDRA_MOCK_SERVER.stubFor(post(urlEqualTo("/admin/oauth2/auth/handover/consume"))
                .willReturn(aResponse()
                        .withStatus(500)));

        SsoException ex = assertThrows(SsoException.class,
                () -> hydraService.consumeAuthHandoverToken(TEST_AUTH_HANDOVER_TOKEN));

        assertThat(ex.getErrorCode(), equalTo(ErrorCode.TECHNICAL_GENERAL));
    }

    @Test
    void consumeAuthHandoverToken_connectionFault_throwsTechnicalGeneral() {
        HYDRA_MOCK_SERVER.stubFor(post(urlEqualTo("/admin/oauth2/auth/handover/consume"))
                .willReturn(aResponse()
                        .withFault(com.github.tomakehurst.wiremock.http.Fault.CONNECTION_RESET_BY_PEER)));

        SsoException ex = assertThrows(SsoException.class,
                () -> hydraService.consumeAuthHandoverToken(TEST_AUTH_HANDOVER_TOKEN));

        assertThat(ex.getErrorCode(), equalTo(ErrorCode.TECHNICAL_GENERAL));
        assertThat(ex.getMessage(), equalTo("Failed to consume Hydra auth handover token"));
        // Reactor Netty prefixes this message with the connection id, so match by content instead of prefix.
        assertMessageIsLogged(e -> e.getLevel() == Level.WARN && e.getFormattedMessage().contains("The connection observed an error"), "[");
    }
}
