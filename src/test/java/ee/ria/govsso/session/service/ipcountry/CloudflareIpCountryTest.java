package ee.ria.govsso.session.service.ipcountry;

import ee.ria.govsso.session.BaseTest;
import io.restassured.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.absent;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.putRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.session.configuration.SecurityConfiguration.COOKIE_NAME_XSRF_TOKEN;
import static ee.ria.govsso.session.controller.ContinueSessionController.AUTH_VIEW_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

@RequiredArgsConstructor(onConstructor_ = @Autowired)
@TestPropertySource(properties = "govsso.ip-country.provider=CLOUDFLARE")
class CloudflareIpCountryTest extends BaseTest {

    private final Cookie MOCK_OIDC_SESSION_COOKIE = new Cookie.Builder(
            "__Host-ory_hydra_session",
            "MDAwMDAwMDAwMHxaR0YwWVRFeU16UTFOamM0T1RBZ1pUVTJZMkpoWmprdE9ERmxPUzAwTkRjekxXRTNNek10TWpZeFpUaGtaRE00WlRrMUlHUmhkR0V4TWpNME5UWTNPRGt3fGludmFsaWRfaGFzaA=="
    ).build();

    @Test
    void continueSession_WhenCloudflareProviderAndCountryHeaderIsSet_ContextContainsIpCountry() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .header("CF-IPCountry", "EE")
                .formParam("_csrf", XORED_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", containsString("/auth/login/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(
                urlEqualTo("/admin/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .withRequestBody(matchingJsonPath("$.context.ip_country", equalTo("EE"))));
    }

    @Test
    void continueSession_WhenCloudflareProviderAndUnsupportedCountryHeaderIsSet_ContextDoesNotContainIpCountry() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/admin/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .header("CF-IPCountry", "XX")
                .formParam("_csrf", XORED_CSRF_TOKEN)
                .formParam("loginChallenge", TEST_LOGIN_CHALLENGE)
                .when()
                .post(AUTH_VIEW_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", containsString("/auth/login/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(
                urlEqualTo("/admin/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .withRequestBody(matchingJsonPath("$.context.ip_country", absent())));
    }
}
