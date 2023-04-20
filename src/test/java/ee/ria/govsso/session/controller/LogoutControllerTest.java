package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieSigner;
import io.restassured.http.ContentType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.deleteRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.exactly;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static ee.ria.govsso.session.configuration.SecurityConfiguration.COOKIE_NAME_XSRF_TOKEN;
import static ee.ria.govsso.session.controller.LogoutController.LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.LogoutController.LOGOUT_END_SESSION_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.LogoutController.LOGOUT_INIT_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesRegex;
import static org.hamcrest.Matchers.not;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class LogoutControllerTest extends BaseTest {
    public static final String TEST_LOGOUT_CHALLENGE = "3c3ef85a-3d8b-4ea2-bb53-b66bc5bd1931";

    private final SsoCookieSigner ssoCookieSigner;

    @Test
    void logoutInit_WhenValidLogoutRequestWithOneClientConsents_ReturnsRedirect() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_one_client.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/accept?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", "https://clienta.localhost:11443");
    }

    @Test
    void logoutInit_WhenValidMultipleClientLogoutRequest_ReturnsLogoutView() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/sessions/consent?client=client-a&subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a&all=false&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));


        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("Olete välja logitud <span translate=\"no\">Teenusenimi A&lt;1&gt;2&amp;3</span> teenusest"))
                .body(matchesRegex("(?:.*\\r*\\n*)*Olete jätkuvalt sisse logitud järgnevatesse teenustesse:(?:.*\\r*\\n*)*Teenusenimi B(?:.*\\r*\\n*)*"))
                .body(containsString("data:image/svg+xml;base64,testlogo"));
    }

    @Test
    void logoutInit_WhenValidMultipleClientLogoutRequestWithoutLogo_ReturnsLogoutView() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_without_logo.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/sessions/consent?client=client-a&subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a&all=false&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));


        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("Olete välja logitud <span translate=\"no\">Teenusenimi A</span> teenusest"))
                .body(matchesRegex("(?:.*\\r*\\n*)*Olete jätkuvalt sisse logitud järgnevatesse teenustesse:(?:.*\\r*\\n*)*Teenusenimi B(?:.*\\r*\\n*)*"))
                .body(not(containsString("data:image/svg+xml;base64")));
    }

    @Test
    void logoutInit_WhenLocaleFromHydraIsRussian_OpensViewInRussian() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/sessions/consent?client=client-a&subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a&all=false&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("Вы вышли из услуги <span translate=\"no\">Название службы A</span>"))
                .body(matchesRegex("(?:.*\\r*\\n*)*Вы авторизованы в следующих услугах:(?:.*\\r*\\n*)*Название службы B(?:.*\\r*\\n*)*"))
                .body(containsString("html lang=\"ru\""));

    }

    @Test
    void logoutInit_WhenLocaleFromHydraIsRussian_ErrorMessageIsInRussian() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Ошибка аутентификации."))
                .body(containsString("Технический сбой услуги. Пожалуйста, попробуйте позже."))
                .body(containsString("html lang=\"ru\""));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
    }

    @Test
    void logoutInit_WhenLocaleFromCookieIsEnglishAndLocaleFromHydraIsRussian_OpensViewInRussian() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/sessions/consent?client=client-a&subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a&all=false&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie("__Host-LOCALE", "en")
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("Вы вышли из услуги <span translate=\"no\">Название службы A</span>"))
                .body(matchesRegex("(?:.*\\r*\\n*)*Вы авторизованы в следующих услугах:(?:.*\\r*\\n*)*Название службы B(?:.*\\r*\\n*)*"))
                .body(containsString("html lang=\"ru\""));

    }

    @Test
    void logoutInit_WhenLocaleFromCookieIsEnglishAndLocaleFromHydraIsRussian_ErrorMessageIsInRussian() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .cookie("__Host-LOCALE", "en")
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Ошибка аутентификации."))
                .body(containsString("Технический сбой услуги. Пожалуйста, попробуйте позже."))
                .body(containsString("html lang=\"ru\""));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
    }

    @Test
    void logoutInit_WhenLocaleFromParameterIsEnglishAndLocaleFromCookieIsEstonianAndLocaleFromHydraIsRussian_OpensViewInEnglish() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/sessions/consent?client=client-a&subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a&all=false&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .param("lang", "en")
                .when()
                .cookie("__Host-LOCALE", "et")
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("You have been logged out from <span translate=\"no\">Service name A</span>"))
                .body(matchesRegex("(?:.*\\r*\\n*)*You are still logged in to the following services:(?:.*\\r*\\n*)*Service name B(?:.*\\r*\\n*)*"))
                .body(containsString("html lang=\"en\""));

    }

    @Test
    void logoutInit_WhenLocaleFromParameterIsEnglishAndLocaleFromCookieIsEstonianAndLocaleFromHydraIsRussian_ErrorMessageIsInEnglish() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .param("lang", "en")
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .cookie("__Host-LOCALE", "et")
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Authentication error."))
                .body(containsString("An unexpected error occurred. Please try again later."))
                .body(containsString("html lang=\"en\""));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
    }

    @Test
    void logoutInit_WhenLocaleFromParameterIsUnknownAndLocaleFromCookieIsUnknownAndLocaleFromHydraIsUnknown_OpensViewInEstonian() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_unknown_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/sessions/consent?client=client-a&subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a&all=false&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .param("lang", "unknown")
                .when()
                .cookie("__Host-LOCALE", "unknown")
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("Olete välja logitud <span translate=\"no\">Teenusenimi A</span> teenusest"))
                .body(matchesRegex("(?:.*\\r*\\n*)*Olete jätkuvalt sisse logitud järgnevatesse teenustesse:(?:.*\\r*\\n*)*Teenusenimi B(?:.*\\r*\\n*)*"))
                .body(containsString("html lang=\"et\""));
    }

    @Test
    void logoutInit_WhenLocaleFromParameterIsUnknownAndLocaleFromCookieIsUnknownAndLocaleFromHydraIsUnknown_ErrorMessageIsInEstonian() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_unknown_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .param("lang", "unknown")
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .cookie("__Host-LOCALE", "unknown")
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Kasutaja tuvastamine ebaõnnestus."))
                .body(containsString("Protsess ebaõnnestus tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body(containsString("html lang=\"et\""));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
    }

    @Test
    void logoutInit_WhenMultipleLocalesFromHydra_OpensViewInRussian() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_multiple_locales.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/sessions/consent?client=client-a&subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a&all=false&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("Вы вышли из услуги <span translate=\"no\">Название службы A</span>"))
                .body(matchesRegex("(?:.*\\r*\\n*)*Вы авторизованы в следующих <strong>1</strong> услугах:(?:.*\\r*\\n*)*Название службы B(?:.*\\r*\\n*)*"))
                .body(containsString("html lang=\"ru\""));
    }

    @Test
    void logoutInit_WhenLocaleFromHydraIsUnknownAndLocaleFromCookieIsEnglish_OpensViewInEnglish() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_unknown_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/sessions/consent?client=client-a&subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a&all=false&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie("__Host-LOCALE", "en")
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("You have been logged out from <span translate=\"no\">Service name A</span>"))
                .body(matchesRegex("(?:.*\\r*\\n*)*You are still logged in to the following services:(?:.*\\r*\\n*)*Service name B(?:.*\\r*\\n*)*"))
                .body(containsString("html lang=\"en\""));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "mock_sso_oidc_logout_request_with_empty_locale.json",
            "mock_sso_oidc_logout_request_with_missing_locale_value.json"
    })
    void logoutInit_WhenLocaleFromHydraIsEmpty_OpensViewInEstonian(String logoutRequestMockFile) {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/" + logoutRequestMockFile)));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/sessions/consent?client=client-a&subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a&all=false&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .param("lang", "unknown")
                .when()
                .cookie("__Host-LOCALE", "unknown")
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("Olete välja logitud <span translate=\"no\">Teenusenimi A</span> teenusest"))
                .body(matchesRegex("(?:.*\\r*\\n*)*Olete jätkuvalt sisse logitud järgnevatesse teenustesse:(?:.*\\r*\\n*)*Teenusenimi B(?:.*\\r*\\n*)*"))
                .body(containsString("html lang=\"et\""));
    }

    @Test
    void logoutInit_WhenUnorderedDuplicateListOfConsents_ReturnsLogoutViewWithOrderedSessionNames() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_duplicate_unordered_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/sessions/consent?client=client-a&subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a&all=false&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));


        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("Olete välja logitud <span translate=\"no\">Teenusenimi A&lt;1&gt;2&amp;3</span> teenusest"))
                .body(matchesRegex("(?:.*\\r*\\n*)*Olete jätkuvalt sisse logitud järgnevatesse teenustesse:(?:.*\\r*\\n*)*Teenusenimi B(?:.*\\r*\\n*)*Teenusenimi C(?:.*\\r*\\n*)*"));
        // For some reason <ul>[\n\r\s]*<li>[\n\r\s]*<strong>[\n\r\s]*Teenusenimi B[\n\r\s]*<\/strong>[\n\r\s]*<\/li>[\n\r\s]*<li>[\n\r\s]*<strong>[\n\r\s]*Teenusenimi C[\n\r\s]*<\/strong>[\n\r\s]*<\/li>[\n\r\s]*<\/ul> does not work
    }

    @Test
    void logoutInit_WhenNotRelyingPartyInitiatedLogoutRequest_ThrowsUserInputError() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_rp_initiated_false.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Logout not initiated by relying party");
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "blank"})
    void logoutInit_WhenFetchLogoutRequestInfoReturnsInvalidPostLogoutRedirectUri_ThrowsUserInputError(String postLogoutRedirectUri) {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_%s_post_logout_redirect_uri.json".formatted(postLogoutRedirectUri))));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Invalid post logout redirect URI");
    }

    @Test
    void logoutInit_WhenMultiplePostLogoutRedirectUris_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_multiple_post_logout_redirect_uris.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Request URL contains more than 1 post logout redirect uri");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "......", "00000000-1111-2222-3333-4444444444445", "00000000-1111-2222-3333444444444444", "3C3EF85A-3D8B-4EA2-BB53-B66BC5BD1931"})
    void logoutInit_WhenLogoutChallengeInvalid_ThrowsUserInputError(String logoutChallenge) {
        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("logout_challenge", logoutChallenge)
                .when()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: logoutInit.logoutChallenge: must match \"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$\"");
    }

    @Test
    void logoutInit_WhenLogoutChallengeParamIsDuplicate_ThrowsUserInputError() {
        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .param("logout_challenge", "abcdeff098aadfccabcdeff098aadfca")
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("Duplicate parameters not allowed in request. Found multiple parameters with name: logout_challenge");
    }

    @Test
    void logoutInit_WhenLogoutChallengeMissing_ThrowsUserInputError() {
        given()
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: Required request parameter 'logout_challenge' for method parameter type String is not present");
    }

    @Test
    void logoutInit_WhenFetchLogoutRequestInfoRespondsWith404_ThrowsUserInputError() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra logout request info --> 404 Not Found from GET");
    }

    @Test
    void logoutInit_WhenFetchLogoutRequestInfoRespondsWith410_ThrowsUserInputError() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(410)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra logout request info --> 410 Gone from GET");
    }

    @Test
    void logoutInit_WhenFetchLogoutRequestInfoRespondsWith500_ThrowsTechnicalGeneralError() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra logout request info --> 500 Internal Server Error from GET");
    }

    @Test
    void logoutInit_WhenGetConsentsReturnsEmptyList_ReturnsRedirect() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_missing.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/accept?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", "https://clienta.localhost:11443");
    }

    @Test
    void logoutInit_WhenGetConsentsReturnsNoRequestClientConsent_PerformsNoDeleteConsentRequest() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_client_b.json")));
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_one_client.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("Olete välja logitud <span translate=\"no\">Teenusenimi B</span> teenusest"))
                .body(matchesRegex("(?:.*\\r*\\n*)*Olete jätkuvalt sisse logitud järgnevatesse teenustesse:(?:.*\\r*\\n*)*Teenusenimi A(?:.*\\r*\\n*)*"))
                .body(containsString("data:image/svg+xml;base64,testlogo"));

        HYDRA_MOCK_SERVER.verify(exactly(0), deleteRequestedFor(urlPathMatching("/oauth2/auth/sessions/consent")));
    }

    @Test
    void logoutInit_WhenGetConsentsReturnsRequestClientConsent_PerformsDeleteConsentRequest() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_client_b.json")));
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_consents.json")));
        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/sessions/consent?client=client-b&subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a&all=false&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .body(containsString("Olete välja logitud <span translate=\"no\">Teenusenimi B</span> teenusest"))
                .body(matchesRegex("(?:.*\\r*\\n*)*Olete jätkuvalt sisse logitud järgnevatesse teenustesse:(?:.*\\r*\\n*)*Teenusenimi A(?:.*\\r*\\n*)*"));
    }

    @Test
    void logoutInit_WhenGetConsentsRespondsWith500_ThrowsTechnicalGeneralError() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
    }

    @Test
    void logoutInit_WhenAcceptLogoutRespondsWith404_ThrowsUserInputError() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_one_client.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/accept?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Failed to accept Hydra logout request --> 404 Not Found from PUT");
    }

    @Test
    void logoutInit_WhenAcceptLogoutRespondsWith500_ThrowsTechnicalGeneralError() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=Isikukood3&login_session_id=97f38419-c541-40e9-8d55-ad223ea1f46a"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_one_client.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/accept?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("logout_challenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .get(LOGOUT_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: Failed to accept Hydra logout request --> 500 Internal Server Error from PUT");
    }

    @Test
    void endSession_WhenLogoutAccepted_ReturnsRedirect() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/accept?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_accept.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_END_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", "https://clienta.localhost:11443");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "......", "00000000-1111-2222-3333-4444444444445", "00000000-1111-2222-3333444444444444", "3C3EF85A-3D8B-4EA2-BB53-B66BC5BD1931"})
    void endSession_WhenLogoutChallengeInvalid_ThrowsUserInputError(String logoutChallenge) {

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", logoutChallenge)
                .when()
                .post(LOGOUT_END_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: endSession.logoutChallenge: must match \"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$\"");
    }

    @Test
    void endSession_WhenNotRelyingPartyInitiatedLogoutRequest_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_rp_initiated_false.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_END_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Logout not initiated by relying party");
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "blank"})
    void endSession_WhenFetchLogoutRequestInfoReturnsInvalidPostLogoutRedirectUri_ThrowsUserInputError(String postLogoutRedirectUri) {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_%s_post_logout_redirect_uri.json".formatted(postLogoutRedirectUri))));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_END_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Invalid post logout redirect URI");
    }

    @Test
    void endSession_WhenAcceptLogoutRespondsWith404_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/accept?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_END_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Failed to accept Hydra logout request --> 404 Not Found from PUT");
    }

    @Test
    void endSession_WhenAcceptLogoutRespondsWith500_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/accept?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_END_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: Failed to accept Hydra logout request --> 500 Internal Server Error from PUT");
    }

    @Test
    void continueSession_WhenLogoutAccepted_ReturnsRedirect() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/reject?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(201)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", "https://clienta.localhost:11443/logout");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "......", "00000000-1111-2222-3333-4444444444445", "00000000-1111-2222-3333444444444444", "3C3EF85A-3D8B-4EA2-BB53-B66BC5BD1931"})
    void continueSession_WhenLogoutChallengeInvalid_ThrowsUserInputError(String logoutChallenge) {

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", logoutChallenge)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: continueSession.logoutChallenge: must match \"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$\"");
    }

    @Test
    void continueSession_WhenNotRelyingPartyInitiatedLogoutRequest_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_rp_initiated_false.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Logout not initiated by relying party");
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "blank"})
    void continueSession_WhenFetchLogoutRequestInfoReturnsInvalidPostLogoutRedirectUri_ThrowsUserInputError(String postLogoutRedirectUri) {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request_with_%s_post_logout_redirect_uri.json".formatted(postLogoutRedirectUri))));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Invalid post logout redirect URI");
    }

    @Test
    void continueSession_WhenFetchLogoutRequestInfoRespondsWith404_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra logout request info --> 404 Not Found from GET");
    }

    @Test
    void continueSession_WhenFetchLogoutRequestInfoRespondsWith410_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(410)));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra logout request info --> 410 Gone from GET");
    }

    @Test
    void continueSession_WhenFetchLogoutRequestInfoRespondsWith500_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra logout request info --> 500 Internal Server Error from GET");
    }

    @Test
    void continueSession_WhenRejectLogoutRespondsWith404_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/reject?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Failed to reject Hydra logout request --> 404 Not Found from PUT");
    }

    @Test
    void continueSession_WhenRejectLogoutRespondsWith500_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/logout?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_logout_request.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/logout/reject?logout_challenge=" + TEST_LOGOUT_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .formParam("_csrf", MOCK_CSRF_TOKEN)
                .formParam("logoutChallenge", TEST_LOGOUT_CHALLENGE)
                .when()
                .post(LOGOUT_CONTINUE_SESSION_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: Failed to reject Hydra logout request --> 500 Internal Server Error from PUT");
    }

    private SsoCookie createSsoCookie() {
        return SsoCookie.builder()
                .loginChallenge(TEST_LOGIN_CHALLENGE)
                .build();
    }
}
