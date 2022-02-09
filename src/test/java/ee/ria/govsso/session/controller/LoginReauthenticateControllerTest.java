package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieSigner;
import io.restassured.matcher.RestAssuredMatchers;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Date;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.session.controller.LoginReauthenticateController.LOGIN_REAUTHENTICATE_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static java.util.Collections.emptyMap;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.HttpHeaders.ORIGIN;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class LoginReauthenticateControllerTest extends BaseTest {

    private static final String TEST_LOGIN_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";
    private final SsoCookieSigner ssoCookieSigner;

    @Test
    void loginReauthenticate_WhenLoginReauthenticateIsSuccessful_Redirects() {
        SsoCookie ssoCookie = createSsoCookie();

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(204)));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/login/e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(204)));

        given()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.equalTo("http://localhost:14443/oauth2/auth?scope=openid&prompt=consent&response_type=code&client_id=openIdDemo&redirect_uri=https://localhost:11443/oauth/response&state=049d71ea-30cd-4a74-8dcd-47156055d364&nonce=5210b42a-2362-420b-bb81-54796da8c814&ui_locales=et"));
    }

    @Test
    void loginReauthenticate_WhenSsoCookieMissing_ThrowsUserInputError() {

        given()
                .when()
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_COOKIE_MISSING"));
    }

    @Test
    void loginReauthenticate_WhenDeleteConsentReturns400_ThrowsTechnicalGeneralError() {
        SsoCookie ssoCookie = createSsoCookie();

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(400)));

        given()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Test
    void loginReauthenticate_WhenLoginRequestInfoSubjectEmpty_ThrowsTechnicalGeneralError() {
        SsoCookie ssoCookie = createSsoCookie();

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        given()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginReauthenticate_WhenDeleteLoginReturns400_ThrowsTechnicalGeneralError() {
        SsoCookie ssoCookie = createSsoCookie();

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(204)));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/login/e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(400)));

        given()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Test
    void loginReauthenticate_IfHydraSessionCookieExists_HydraSessionCookieIsDeleted() {
        SsoCookie ssoCookie = createSsoCookie();

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(204)));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/login/e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(204)));

        given()
                .cookie("oauth2_authentication_session_insecure", "test1234")
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .cookie("oauth2_authentication_session_insecure", RestAssuredMatchers.detailedCookie().maxAge(0).value("test1234").path("/").expiryDate(new Date(10000)));
    }

    @Test
    void loginReauthenticate_WhenOriginHeaderIsSet_NoCorsResponseHeadersAreSet() {
        SsoCookie ssoCookie = createSsoCookie();

        wireMockServer.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(204)));

        wireMockServer.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/login/e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(204)));

        given()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .header(ORIGIN, "https://clienta.localhost:11443")
                .when()
                .post(LOGIN_REAUTHENTICATE_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .headers(emptyMap())
                .header("Location", Matchers.equalTo("http://localhost:14443/oauth2/auth?scope=openid&prompt=consent&response_type=code&client_id=openIdDemo&redirect_uri=https://localhost:11443/oauth/response&state=049d71ea-30cd-4a74-8dcd-47156055d364&nonce=5210b42a-2362-420b-bb81-54796da8c814&ui_locales=et"));
    }

    private SsoCookie createSsoCookie() {
        return SsoCookie.builder()
                .loginChallenge(TEST_LOGIN_CHALLENGE)
                .build();
    }
}
