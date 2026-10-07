package ee.ria.govsso.session.service.hydra;

import ch.qos.logback.classic.Level;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Instant;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class HydraServiceTest extends BaseTest {

    private static final String TEST_LOGIN_SESSION_ID = "e56cbaf9-81e9-4473-a733-261e8dd38e95";

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
    void fetchLoginSessionInfo_ok() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/login?sid=" + TEST_LOGIN_SESSION_ID))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_session.json")));

        LoginSessionInfo loginSessionInfo = hydraService.fetchLoginSessionInfo(TEST_LOGIN_SESSION_ID);

        assertThat(loginSessionInfo.getAcr(), equalTo("high"));
        assertThat(loginSessionInfo.getAmr(), equalTo(List.of("mID")));
        assertThat(loginSessionInfo.getAuthTime(), equalTo(Instant.ofEpochSecond(1530267052)));
        assertThat(loginSessionInfo.getBirthdate(), equalTo("2000-01-01"));
        assertThat(loginSessionInfo.getFamilyName(), equalTo("O'CONNEŽ-ŠUSLIK"));
        assertThat(loginSessionInfo.getGivenName(), equalTo("MARY ÄNN"));
        assertThat(loginSessionInfo.getPhoneNumber(), equalTo("+37200000766"));
        assertThat(loginSessionInfo.getPhoneNumberVerified(), equalTo(true));
        assertThat(loginSessionInfo.getSubject(), equalTo("EE60001019906"));
    }

    @Test
    void fetchLoginSessionInfo_emptyBody_allFieldsNull() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/login?sid=" + TEST_LOGIN_SESSION_ID))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("{}")));

        LoginSessionInfo loginSessionInfo = hydraService.fetchLoginSessionInfo(TEST_LOGIN_SESSION_ID);

        assertThat(loginSessionInfo, equalTo(new LoginSessionInfo()));
    }

    @Test
    void fetchLoginSessionInfo_notFound_throwsUserInput() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/login?sid=" + TEST_LOGIN_SESSION_ID))
                .willReturn(aResponse()
                        .withStatus(404)));

        SsoException ex = assertThrows(SsoException.class,
                () -> hydraService.fetchLoginSessionInfo(TEST_LOGIN_SESSION_ID));

        assertThat(ex.getErrorCode(), equalTo(ErrorCode.USER_INPUT));
    }

    @Test
    void fetchLoginSessionInfo_serverError_throwsTechnicalGeneral() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/login?sid=" + TEST_LOGIN_SESSION_ID))
                .willReturn(aResponse()
                        .withStatus(500)));

        SsoException ex = assertThrows(SsoException.class,
                () -> hydraService.fetchLoginSessionInfo(TEST_LOGIN_SESSION_ID));

        assertThat(ex.getErrorCode(), equalTo(ErrorCode.TECHNICAL_GENERAL));
    }

    @Test
    void fetchLoginSessionInfo_noResponseBody_throwsTechnicalGeneral() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/login?sid=" + TEST_LOGIN_SESSION_ID))
                .willReturn(aResponse()
                        .withStatus(200)));

        SsoException ex = assertThrows(SsoException.class,
                () -> hydraService.fetchLoginSessionInfo(TEST_LOGIN_SESSION_ID));

        assertThat(ex.getErrorCode(), equalTo(ErrorCode.TECHNICAL_GENERAL));
    }
}
