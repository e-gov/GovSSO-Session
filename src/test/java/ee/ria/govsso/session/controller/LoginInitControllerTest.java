package ee.ria.govsso.session.controller;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.configuration.properties.SecurityConfigurationProperties;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieSigner;
import io.restassured.http.ContentType;
import io.restassured.http.Cookie;
import io.restassured.matcher.DetailedCookieMatcher;
import io.restassured.matcher.RestAssuredMatchers;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.NestedTestConfiguration;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static ee.ria.govsso.session.configuration.SecurityConfiguration.COOKIE_NAME_XSRF_TOKEN;
import static ee.ria.govsso.session.controller.LoginInitController.LOGIN_INIT_REQUEST_MAPPING;
import static ee.ria.govsso.session.session.SsoCookie.COOKIE_NAME_GOVSSO;
import static io.restassured.RestAssured.given;
import static java.util.Collections.emptyMap;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS;
import static org.springframework.http.HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN;
import static org.springframework.http.HttpHeaders.ORIGIN;
import static org.springframework.test.context.NestedTestConfiguration.EnclosingConfiguration.OVERRIDE;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class LoginInitControllerTest extends BaseTest {

    private static final String TEST_LOGIN_CHALLENGE = "abcdeff098aadfccabcdeff098aadfcc";
    private final SsoCookieSigner ssoCookieSigner;
    private final SecurityConfigurationProperties securityConfigurationProperties;

    @Test
    void loginInit_WhenFetchLoginRequestInfoIsSuccessful_CreatesSessionAndRedirects() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        String ssoCookieValue = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.matchesRegex("https:\\/\\/tara.localhost:10000\\/oidc\\/authorize\\?ui_locales=et&scope=openid&acr_values=high&response_type=code&redirect_uri=https%3A%2F%2Fgateway.localhost%3A8000%2Flogin%2Ftaracallback&state=.*&nonce=.*&client_id=testclient123"))
                .extract().cookie(COOKIE_NAME_GOVSSO);

        SsoCookie ssoCookie = ssoCookieSigner.parseAndVerifyCookie(ssoCookieValue);
        assertThat(ssoCookie.getLoginChallenge(), equalTo(TEST_LOGIN_CHALLENGE));
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoAcrIsSubstantial_CreatesSessionAndRedirects() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_substantial_acr.json")));

        String ssoCookieValue = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.matchesRegex("https:\\/\\/tara.localhost:10000\\/oidc\\/authorize\\?ui_locales=et&scope=openid&acr_values=substantial&response_type=code&redirect_uri=https%3A%2F%2Fgateway.localhost%3A8000%2Flogin%2Ftaracallback&state=.*&nonce=.*&client_id=testclient123"))
                .extract().cookie(COOKIE_NAME_GOVSSO);

        SsoCookie ssoCookie = ssoCookieSigner.parseAndVerifyCookie(ssoCookieValue);

        assertThat(ssoCookie.getLoginChallenge(), equalTo(TEST_LOGIN_CHALLENGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "mock_sso_oidc_login_request_with_subject.json",
            "mock_sso_oidc_login_request_with_subject_without_acr.json"})
    void loginInit_WhenFetchLoginRequestInfoWithSubjectIsSuccessful_CreatesSessionAndOpensView(String loginRequestMockFile) {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/" + loginRequestMockFile)));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("kasutab ühekordse sisselogimise"))
                .body(containsString("Eesnimi3"))
                .body(containsString("test1234"))
                .body(containsString("Perekonnanimi3"))
                .body(containsString("1961-07-12"));
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsRussian_OpensViewInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .param("lang", "fr")
                .when()
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("использует решение единого входа (SSO)."));
    }

    @Test
    void loginInit_WhenLocaleIsSetToRussian_ErrorMessageIsInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .param("lang", "fr")
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Ошибка аутентификации."))
                .body(containsString("произошла непредвиденная ошибка. Пожалуйста, попробуйте позже."));
    }

    @Test
    void loginInit_WhenLocaleFromCookieIsRussian_OpensViewInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .cookie("__Host-LOCALE", "fr")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("использует решение единого входа (SSO)."));
    }

    @Test
    void loginInit_WhenLocaleFromCookieIsRussian_ErrorMessageIsInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .cookie("__Host-LOCALE", "fr")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Ошибка аутентификации."))
                .body(containsString("произошла непредвиденная ошибка. Пожалуйста, попробуйте позже."));
    }

    @Test
    void loginInit_WhenLocaleFromCookieIsUnknown_OpensViewInEstonian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .cookie("__Host-LOCALE", "unknown")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("kasutab ühekordse sisselogimise"));
    }

    @Test
    void loginInit_WhenLocaleFromCookieIsUnknown_ErrorMessageIsInEstonian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .cookie("__Host-LOCALE", "unknown")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Kasutaja tuvastamine ebaõnnestus."))
                .body(containsString("Protsess ebaõnnestus tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    void loginInit_WhenLocaleFromHydraIsRussian_OpensViewInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("использует решение единого входа (SSO)."));
    }

    @Test
    void loginInit_WhenLocaleFromHydraIsRussian_ErrorMessageIsInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Ошибка аутентификации."))
                .body(containsString("произошла непредвиденная ошибка. Пожалуйста, попробуйте позже."));
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsEnglishAndLocaleFromCookieIsEstonianAndLocaleFromHydraIsRussian_OpensViewInEnglish() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .param("lang", "en")
                .cookie("__Host-LOCALE", "et")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("service uses a single sign-on (SSO) solution"));
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsEnglishAndLocaleFromCookieIsEstonianAndLocaleFromHydraIsRussian_ErrorMessageIsInEnglish() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .param("lang", "en")
                .cookie("__Host-LOCALE", "et")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Authentication error."))
                .body(containsString("An unexpected error occurred. Please try again later."));
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsUnknownAndLocaleFromCookieIsUnknownAndLocaleFromHydraIsUnknown_OpensViewInEstonian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .param("lang", "unknown")
                .cookie("__Host-LOCALE", "unknown")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("kasutab ühekordse sisselogimise"));
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsUnknownAndLocaleFromCookieIsUnknownAndLocaleFromHydraIsUnknown_ErrorMessageIsInEstonian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .param("lang", "unknown")
                .cookie("__Host-LOCALE", "unknown")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Kasutaja tuvastamine ebaõnnestus."))
                .body(containsString("Protsess ebaõnnestus tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    void loginInit_WhenLocaleFromHydraIsRussianAndLocaleFromParameterIsEstonian_OpensViewInEstonian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .param("lang", "et")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("kasutab ühekordse sisselogimise"));
    }

    @Test
    void loginInit_WhenLocaleFromHydraIsRussianAndLocaleFromParameterIsEstonian_ErrorMessageIsInEstonian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .param("lang", "et")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Kasutaja tuvastamine ebaõnnestus."))
                .body(containsString("Protsess ebaõnnestus tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    void loginInit_WhenLocaleFromHydraIsRussianAndLocaleFromCookieIsEstonian_OpensViewInEstonian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .cookie("__Host-LOCALE", "et")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("kasutab ühekordse sisselogimise"));
    }

    @Test
    void loginInit_WhenLocaleFromHydraIsRussianAndLocaleFromCookieIsEstonian_ErrorMessageIsInEstonian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .cookie("__Host-LOCALE", "et")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Kasutaja tuvastamine ebaõnnestus."))
                .body(containsString("Protsess ebaõnnestus tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsUnknown_OpensViewInEstonian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .param("lang", "unknown")
                .when()
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("kasutab ühekordse sisselogimise"));
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsUnknown_ErrorMessageIsInEstonian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .param("lang", "unknown")
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Kasutaja tuvastamine ebaõnnestus."))
                .body(containsString("Protsess ebaõnnestus tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."));
    }

    @Test
    void loginInit_WhenLocaleFromCookieIsRussianAndLocaleFromParameterIsUndefined_ErrorMessageIsInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie("__Host-LOCALE", "fr")
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .when()
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Ошибка аутентификации."))
                .body(containsString("произошла непредвиденная ошибка. Пожалуйста, попробуйте позже."));
    }

    @Test
    void loginInit_WhenConsentsAreNotIdentical_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_not_identical.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap())
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Test
    void loginInit_WhenConsentsIdTokenAcrValueLowerThanLoginRequestInfoAcrValue_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_first_acr_value_low.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap())
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Test
    void loginInit_WhenConsentsHaveUnrecognizedLoginSessionIds_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_unrecognized_login_session_ids.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap())
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Test
    void loginInit_WhenContinueSessionAndConsentsAreMissing_ReAuthenticate() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_missing.json")));
        HYDRA_MOCK_SERVER.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(204)));
        HYDRA_MOCK_SERVER.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/login/e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(204)));
        Cookie hydraCookie = new Cookie.Builder("oauth2_authentication_session_insecure", "a77cbaf9-77e9-5573-a711-919e8dd38a11")
                .setMaxAge(1000)
                .build();

        Cookie invalidatedHydraCookie = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(hydraCookie)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", equalTo("https://hydra.localhost:9000/oauth2/auth?scope=openid&prompt=consent&response_type=code&client_id=openIdDemo&redirect_uri=https://hydra.localhost:9000/oauth/response&state=049d71ea-30cd-4a74-8dcd-47156055d364&nonce=5210b42a-2362-420b-bb81-54796da8c814&ui_locales=et"))
                .extract().detailedCookie("oauth2_authentication_session_insecure");

        assertThat(invalidatedHydraCookie.getMaxAge(), equalTo(0));
    }

    @Test
    void loginInit_WhenUpdateSessionAndConsentsAreMissing_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_id_token_hint.json")));
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_missing.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap())
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Test
    void loginInit_WhenConsentsRequestRespondsWith500_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap())
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "......", "123456789012345678901234567890123456789012345678900"})
    void loginInit_WhenLoginChallengeInvalid_ThrowsUserInputError(String loginChallenge) {
        given()
                .param("login_challenge", loginChallenge)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenLoginChallengeParamIsDuplicate_ThrowsUserInputError() {
        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .param("login_challenge", "abcdeff098aadfccabcdeff098aadfca")
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenLoginChallengeMissing_ThrowsUserInputError() {
        given()
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoRespondsWith404_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoRespondsWith410_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(410)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoRespondsWith500_ThrowsTechincalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/oidc/mock_sso_oidc_login_request.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap())
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Test
    void loginInit_WhenLoginResponseRequestUrlDoesntContainPromptConsent_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_url_without_prompt_consent.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap());
    }

    @Test
    void loginInit_WhenLoginResponseRequestScopeWithoutOpenid_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_scope_without_openid.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap());
    }

    @Test
    void loginInit_WhenLoginResponseRequestScopeWithMoreThanOpenid_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_scope_with_more_than_openid.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap());
    }

    @Test
    void loginInit_WhenLoginResponseRequestIdTokenHintClaimIsNonEmpty_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_id_token_hint_claim_non_empty.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap());
    }

    @Test
    void loginInit_WhenLoginResponseRequestSubjectIsEmptyAndSkipIsTrue_ThrowsTechnicalGeneralError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_skip_true.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap());
    }

    @Test
    void loginInit_WhenLoginResponseRequestSubjectIsNotEmptyAndSkipIsFalse_ThrowsTechnicalGeneralError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_skip_false.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap());
    }

    @Test
    void loginInit_WhenLoginResponseRequestHasMoreThanOneAcrValue_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_more_than_one_acr.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenLoginResponseRequestHasOneIncorrectAcrValue_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_one_incorrect_acr.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenLoginResponseRequestHasOneCapitalizedAcrValue_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_capitalized_acr.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenOriginHeaderIsSet_SetsCorsResponseHeaders() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .header(ORIGIN, "https://clienta.localhost:11443")
                .when()
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.matchesRegex("https:\\/\\/tara.localhost:10000\\/oidc\\/authorize\\?ui_locales=et&scope=openid&acr_values=high&response_type=code&redirect_uri=https%3A%2F%2Fgateway.localhost%3A8000%2Flogin%2Ftaracallback&state=.*&nonce=.*&client_id=testclient123"))
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "https://clienta.localhost:11443")
                .header(ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
    }

    @Test
    void loginInit_WhenNoCSRFCookieIsSet_SetsCSRFCookie() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        DetailedCookieMatcher detailedCookieMatcher = RestAssuredMatchers.detailedCookie();

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.matchesRegex("https:\\/\\/tara.localhost:10000\\/oidc\\/authorize\\?ui_locales=et&scope=openid&acr_values=high&response_type=code&redirect_uri=https%3A%2F%2Fgateway.localhost%3A8000%2Flogin%2Ftaracallback&state=.*&nonce=.*&client_id=testclient123"))
                .cookie(COOKIE_NAME_XSRF_TOKEN, detailedCookieMatcher
                        .httpOnly(true)
                        .secured(true)
                        .path("/")
                        .maxAge(securityConfigurationProperties.getCookieMaxAgeSeconds()));
    }

    // TODO This test will stop working on 2038-xx-xx. Change it to be independent of current time.
    @Test
    void loginInit_WhenPromptNone_ExtendSession() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .cookies(emptyMap())
                .header("Location", Matchers.matchesRegex("https://clienta.localhost:11443/auth/login/test"));
    }

    @Test
    void loginInit_WhenPromptNone_SubjectEmpty_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none_subject_empty.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenPromptNone_OidcContextMissing_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none_oidc_context_missing.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenPromptNone_TokenMissing_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none_token_missing.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenPromptNone_AudienceDoesNotMatchRequestClientId_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none_mismatching_client_id.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenPromptNone_TokenSessionIdDoesNotMatchWithRequestSessionId_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none_mismatching_token_session_id.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenPromptNone_TokenExpired_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none_token_expired.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));
    }

    @Test
    void loginInit_WhenPromptNone_WhenConsentsIdTokenAcrValueLowerThanLoginRequestInfoAcrValue_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_prompt_none.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_first_acr_value_low.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .cookies(emptyMap())
                .body("error", equalTo("TECHNICAL_GENERAL"));
    }

    @Nested
    @NestedTestConfiguration(OVERRIDE)
    @TestPropertySource(properties = {"govsso.session-max-duration-hours=1"})
    class MaxSessionDurationOneHourTests extends BaseTest {

        @Test
        @SneakyThrows
        void loginInit_WhenConsentIdTokenExpired10SecondsAgo_ThrowsTechnicalGeneralError() {
            SignedJWT jwt = createIdTokenWithAgeInSeconds(3610);
            String responseBody = createConsentsResponseBodyWithIdToken(jwt);

            HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json; charset=UTF-8")
                            .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

            HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json; charset=UTF-8")
                            .withBody(responseBody)));

            given()
                    .param("login_challenge", TEST_LOGIN_CHALLENGE)
                    .when()
                    .get("/login/init")
                    .then()
                    .assertThat()
                    .statusCode(500)
                    .body("error", equalTo("TECHNICAL_GENERAL"));
        }

        @Test
        @SneakyThrows
        void loginInit_WhenConsentIdTokenLasts10MoreSeconds_Returns200() {

            SignedJWT jwt = createIdTokenWithAgeInSeconds(3590);
            String responseBody = createConsentsResponseBodyWithIdToken(jwt);

            HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json; charset=UTF-8")
                            .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

            HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=test1234"))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json; charset=UTF-8")
                            .withBody(responseBody)));

            given()
                    .param("login_challenge", TEST_LOGIN_CHALLENGE)
                    .when()
                    .get("/login/init")
                    .then()
                    .assertThat()
                    .statusCode(200);
        }

        private String createConsentsResponseBodyWithIdToken(SignedJWT jwt) {
            String consentsResponseBody = """
                    [
                      {
                        "consent_request": {
                          "context": {
                            "tara_id_token": "%s"
                          },
                          "login_session_id": "e56cbaf9-81e9-4473-a733-261e8dd38e95"
                        }
                      }
                    ]
                    """;

            return String.format(consentsResponseBody, jwt.serialize());
        }

        private SignedJWT createIdTokenWithAgeInSeconds(int ageInSeconds) throws JOSEException {
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .notBeforeTime(Date.from(Instant.now().minusSeconds(ageInSeconds)))
                    .claim("profile_attributes", Map.of("given_name", "test1", "family_name", "test2"))
                    .claim("acr", "high")
                    .build();
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(RS256).keyID(TARA_JWK.getKeyID()).build(), claimsSet);
            JWSSigner signer = new RSASSASigner(TARA_JWK);
            jwt.sign(signer);
            return jwt;
        }
    }
}
