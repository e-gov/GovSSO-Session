package ee.ria.govsso.session.controller;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.configuration.properties.SecurityConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieSigner;
import io.restassured.RestAssured;
import io.restassured.builder.ResponseSpecBuilder;
import io.restassured.http.ContentType;
import io.restassured.http.Cookie;
import io.restassured.matcher.DetailedCookieMatcher;
import io.restassured.matcher.RestAssuredMatchers;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.NestedTestConfiguration;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.stream.Stream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.putRequestedFor;
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
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.springframework.test.context.NestedTestConfiguration.EnclosingConfiguration.OVERRIDE;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
public class LoginInitControllerTest extends BaseTest {
    private final Cookie MOCK_OIDC_SESSION_COOKIE = new Cookie.Builder("oauth2_authentication_session_insecure", "MDAwMDAwMDAwMHxaR0YwWVRFeU16UTFOamM0T1RBZ1pUVTJZMkpoWmprdE9ERmxPUzAwTkRjekxXRTNNek10TWpZeFpUaGtaRE00WlRrMUlHUmhkR0V4TWpNME5UWTNPRGt3fGludmFsaWRfaGFzaA==").build();
    private final SsoCookieSigner ssoCookieSigner;
    private final SecurityConfigurationProperties securityConfigurationProperties;
    private final SsoConfigurationProperties ssoConfigurationProperties;

    static Stream<Arguments> contextHeaders() {
        return Stream.of(
                arguments("X-Forwarded-For", "111.111.111.111", "$.context.ip_address"),
                arguments("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36", "$.context.user_agent")
        );
    }

    @BeforeEach
    public void setupExpectedResponseSpec() {
        RestAssured.responseSpecification = new ResponseSpecBuilder()
                .expectHeaders(EXPECTED_RESPONSE_HEADERS_WITH_CORS).build();
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoIsSuccessful_CreatesSessionAndRedirects() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
                .header("Location", Matchers.matchesRegex("https:\\/\\/tara.localhost:10000\\/oidc\\/authorize\\?ui_locales=et&scope=openid\\+phone&acr_values=high&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&redirect_uri=https%3A%2F%2Finproxy.localhost%3A8000%2Flogin%2Ftaracallback&state=.*&nonce=.*&client_id=testclient123"))
                .extract().cookie(COOKIE_NAME_GOVSSO);

        SsoCookie ssoCookie = ssoCookieSigner.parseAndVerifyCookie(ssoCookieValue);
        assertThat(ssoCookie.getLoginChallenge(), equalTo(TEST_LOGIN_CHALLENGE));
    }

    @Test
    void loginInit_WhenPromptEncoded_CreatesSessionAndRedirects() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_encoded_prompt.json")));

        String ssoCookieValue = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.matchesRegex("https:\\/\\/tara.localhost:10000\\/oidc\\/authorize\\?ui_locales=et&scope=openid\\+phone&acr_values=high&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&redirect_uri=https%3A%2F%2Finproxy.localhost%3A8000%2Flogin%2Ftaracallback&state=.*&nonce=.*&client_id=testclient123"))
                .extract().cookie(COOKIE_NAME_GOVSSO);

        SsoCookie ssoCookie = ssoCookieSigner.parseAndVerifyCookie(ssoCookieValue);
        assertThat(ssoCookie.getLoginChallenge(), equalTo(TEST_LOGIN_CHALLENGE));
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoAcrIsSubstantial_CreatesSessionAndRedirects() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
                .header("Location", Matchers.matchesRegex("https:\\/\\/tara.localhost:10000\\/oidc\\/authorize\\?ui_locales=et&scope=openid\\+phone&acr_values=substantial&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&redirect_uri=https%3A%2F%2Finproxy.localhost%3A8000%2Flogin%2Ftaracallback&state=.*&nonce=.*&client_id=testclient123"))
                .extract().cookie(COOKIE_NAME_GOVSSO);

        SsoCookie ssoCookie = ssoCookieSigner.parseAndVerifyCookie(ssoCookieValue);

        assertThat(ssoCookie.getLoginChallenge(), equalTo(TEST_LOGIN_CHALLENGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "mock_sso_oidc_login_request_with_subject.json",
            "mock_sso_oidc_login_request_with_subject_without_acr.json"})
    void loginInit_WhenFetchLoginRequestInfoWithSubjectIsSuccessful_CreatesSessionAndOpensView(String loginRequestMockFile) {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/" + loginRequestMockFile)));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <span translate=\"no\">Teenusenimi A&lt;1&gt;2&amp;3</span> sisselogimine"))
                .body(containsString("kasutab ühekordse sisselogimise"))
                .body(containsString("Eesnimi3"))
                .body(containsString("test1234"))
                .body(containsString("Perekonnanimi3"))
                .body(containsString("12.07.1961"))
                .body(not(containsString("12345")))
                .body(containsString("data:image/svg+xml;base64,testlogo"))
                .body(containsString("Teil on aktiivne seanss ainult selles seadmes."))
                .body(not(containsString("Teil on aktiivseid seansse veel 1 seadmes.")))
                .body(containsString(ssoConfigurationProperties.getSelfServiceUrl() + "?lang=et"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "mock_sso_oidc_login_request_with_subject.json",
            "mock_sso_oidc_login_request_with_subject_without_acr.json"})
    void loginInit_WhenFetchLoginRequestInfoWithMultipleSessionsIsSuccessful_CreatesSessionAndOpensView(String loginRequestMockFile) {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/" + loginRequestMockFile)));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_sessions.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_sessions.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_sessions.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <span translate=\"no\">Teenusenimi A&lt;1&gt;2&amp;3</span> sisselogimine"))
                .body(containsString("kasutab ühekordse sisselogimise"))
                .body(containsString("Eesnimi3"))
                .body(containsString("test1234"))
                .body(containsString("Perekonnanimi3"))
                .body(containsString("12.07.1961"))
                .body(not(containsString("12345")))
                .body(containsString("data:image/svg+xml;base64,testlogo"))
                .body(not(containsString("Teil on aktiivne seanss ainult selles seadmes.")))
                .body(containsString("Teil on aktiivseid seansse veel 1 seadmes."))
                .body(containsString(ssoConfigurationProperties.getSelfServiceUrl() + "?lang=et"));
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoWithSubjectAndPhoneScopeIsSuccessful_CreatesSessionAndOpensViewWIthPhoneNumber() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_scope_with_openid_and_phone.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_idtoken_with_phone.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <span translate=\"no\">Teenusenimi A</span> sisselogimine"))
                .body(containsString("kasutab ühekordse sisselogimise"))
                .body(containsString("Eesnimi3"))
                .body(containsString("test1234"))
                .body(containsString("Perekonnanimi3"))
                .body(containsString("12.07.1961"))
                .body(containsString("12345"))
                .body(containsString("data:image/svg+xml;base64,testlogo"));
    }

    @Test
    void loginInit_WhenTaraIdTokenContainsPhoneNumberAndPhoneScopeIsNotPresent_CreatesSessionAndOpensViewWithoutPhoneNumber() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_with_phone.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <span translate=\"no\">Teenusenimi A&lt;1&gt;2&amp;3</span> sisselogimine"))
                .body(containsString("kasutab ühekordse sisselogimise"))
                .body(containsString("Eesnimi3"))
                .body(containsString("test1234"))
                .body(containsString("Perekonnanimi3"))
                .body(containsString("12.07.1961"))
                .body(not(containsString("12345")))
                .body(containsString("data:image/svg+xml;base64,testlogo"));
    }

    @Test
    void loginInit_WhenTaraIdTokenContainsPhoneNumberAndPhoneScopeIsPresent_CreatesSessionAndOpensViewWithPhoneNumber() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_scope_with_openid_and_phone.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_with_phone.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <span translate=\"no\">Teenusenimi A</span> sisselogimine"))
                .body(containsString("kasutab ühekordse sisselogimise"))
                .body(containsString("Eesnimi3"))
                .body(containsString("test1234"))
                .body(containsString("Perekonnanimi3"))
                .body(containsString("12.07.1961"))
                .body(containsString("12345"))
                .body(containsString("data:image/svg+xml;base64,testlogo"));
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoWithoutLogoIsSuccessful_CreatesSessionAndOpensView() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject_without_logo.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <span translate=\"no\">Teenusenimi A</span> sisselogimine"))
                .body(containsString("kasutab ühekordse sisselogimise"))
                .body(containsString("Eesnimi3"))
                .body(containsString("test1234"))
                .body(containsString("Perekonnanimi3"))
                .body(containsString("12.07.1961"))
                .body(not(containsString("data:image/svg+xml;base64")));
    }

    @Test
    void loginInit_WhenLocaleFromHydraIsRussian_OpensViewInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .when()
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Вход в услугу <span translate=\"no\">Название службы A</span>"))
                .body(containsString("применяет технологию единого входа (<span lang=\"en\" translate=\"no\">SSO - <i>single sign-on</i></span>)"))
                .body(containsString("12.07.1961"))
                .body(containsString("html lang=\"ru\""))
                .body(containsString(ssoConfigurationProperties.getSelfServiceUrl() + "?lang=ru"));
    }

    @Test
    void loginInit_WhenLocaleFromHydraIsRussian_ErrorMessageIsInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Ошибка аутентификации."))
                .body(containsString("Технический сбой услуги. Пожалуйста, попробуйте позже."))
                .body(containsString("html lang=\"ru\""));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsEnglishAndLocaleFromCookieIsEstonianAndLocaleFromHydraIsRussian_OpensViewInEnglish() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .when()
                .param("lang", "en")
                .cookie("__Host-LOCALE", "et")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Logging in to <span translate=\"no\">Service name A</span>"))
                .body(containsString("service uses a single sign-on (<span translate=\"no\">SSO</span>) solution"))
                .body(containsString("7/12/1961"))
                .body(containsString("html lang=\"en\""))
                .body(containsString(ssoConfigurationProperties.getSelfServiceUrl() + "?lang=en"));
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsEnglishAndLocaleFromCookieIsEstonianAndLocaleFromHydraIsRussian_ErrorMessageIsInEnglish() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
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
                .body(containsString("An unexpected error occurred. Please try again later."))
                .body(containsString("html lang=\"en\""));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsUnknownAndLocaleFromCookieIsUnknownAndLocaleFromHydraIsUnknown_OpensViewInEstonian() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_unknown_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .when()
                .param("lang", "unknown")
                .cookie("__Host-LOCALE", "unknown")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("kasutab ühekordse sisselogimise"))
                .body(containsString("html lang=\"et\""));
    }

    @Test
    void loginInit_WhenLocaleFromParameterIsUnknownAndLocaleFromCookieIsUnknownAndLocaleFromHydraIsUnknown_ErrorMessageIsInEstonian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_unknown_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
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
                .body(containsString("Protsess ebaõnnestus tehnilise vea tõttu. Palun proovige mõne aja pärast uuesti."))
                .body(containsString("html lang=\"et\""));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
    }

    @Test
    void loginInit_WhenLocaleFromCookieIsEnglishAndLocaleFromHydraIsRussian_OpensViewInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .when()
                .cookie("__Host-LOCALE", "en")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("применяет технологию единого входа (<span lang=\"en\" translate=\"no\">SSO - <i>single sign-on</i></span>)"))
                .body(containsString("html lang=\"ru\""));
    }

    @Test
    void loginInit_WhenLocaleFromCookieIsEnglishAndLocaleFromHydraIsRussian_ErrorMessageIsInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_russian_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .header(HttpHeaders.ACCEPT, ContentType.HTML)
                .cookie("__Host-LOCALE", "en")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(500)
                .body(containsString("Ошибка аутентификации."))
                .body(containsString("Технический сбой услуги. Пожалуйста, попробуйте позже."))
                .body(containsString("html lang=\"ru\""));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
    }

    @Test
    void loginInit_WhenMultipleLocalesFromHydra_OpensViewInRussian() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_multiple_locales.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .when()
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Вход в услугу <span translate=\"no\">Название службы A</span>"))
                .body(containsString("применяет технологию единого входа (<span lang=\"en\" translate=\"no\">SSO - <i>single sign-on</i></span>)"))
                .body(containsString("12.07.1961"))
                .body(containsString("html lang=\"ru\""));
    }

    @Test
    void loginInit_WhenLocaleFromHydraIsUnknownAndLocaleFromCookieIsEnglish_OpensViewInEnglish() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_unknown_locale.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .when()
                .cookie("__Host-LOCALE", "en")
                .get("/login/init")
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Logging in to <span translate=\"no\">Service name A</span>"))
                .body(containsString("service uses a single sign-on (<span translate=\"no\">SSO</span>)"))
                .body(containsString("7/12/1961"))
                .body(containsString("html lang=\"en\""));
    }

    @Test
    void loginInit_WhenConsentsAreNotIdentical_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
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

        assertErrorIsLogged("SsoException: Valid consents did not have identical tara_id_token values");
    }

    @Test
    void loginInit_WhenConsentsIdTokenAcrValueLowerThanLoginRequestInfoAcrValue_OpensAcrView() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_first_acr_value_low.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
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
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <strong translate=\"no\">Teenusenimi A&lt;1&gt;2&amp;3</strong> sisselogimine"))
                .body(containsString("Teenusesse <strong translate=\"no\">Teenusenimi A&lt;1&gt;2&amp;3</strong> sisselogimine nõuab kõrgema tasemega autentimisvahendiga uuesti autentimist."))
                .body(containsString("data:image/svg+xml;base64,testlogo"))
                .body(containsString("Teil on aktiivne seanss ainult selles seadmes."))
                .body(not(containsString("Teil on aktiivseid seansse veel 1 seadmes.")));
    }

    @Test
    void loginInit_WhenConsentsIdTokenAcrValueLowerThanLoginRequestInfoAcrValueWithoutLogo_OpensAcrView() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject_without_logo.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_first_acr_value_low.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
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
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <strong translate=\"no\">Teenusenimi A</strong> sisselogimine"))
                .body(containsString("Teenusesse <strong translate=\"no\">Teenusenimi A</strong> sisselogimine nõuab kõrgema tasemega autentimisvahendiga uuesti autentimist."))
                .body(not(containsString("data:image/svg+xml;base64,testlogo")));
    }

    @Test
    void loginInit_WhenContinueSessionAndConsentsAreMissing_ReAuthenticate() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_missing.json")));
        HYDRA_MOCK_SERVER.stubFor(delete(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(204)));
        HYDRA_MOCK_SERVER.stubFor(delete(urlEqualTo("/admin/oauth2/auth/sessions/login?sid=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
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

        assertThat(invalidatedHydraCookie.getMaxAge(), equalTo(0L));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "mock_sso_oidc_login_request_with_requested_at_below_lower_bound.json",
            "mock_sso_oidc_login_request_with_requested_at_above_upper_bound.json"})
    void loginInit_WhenNoConsentsFoundAtLoginRequestTime_ReAuthenticate(String loginRequest) {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/" + loginRequest)));
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));
        HYDRA_MOCK_SERVER.stubFor(delete(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95&all=true&trigger_backchannel_logout=true"))
                .willReturn(aResponse()
                        .withStatus(204)));
        HYDRA_MOCK_SERVER.stubFor(delete(urlEqualTo("/admin/oauth2/auth/sessions/login?sid=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(204)));

        Cookie invalidatedHydraCookie = given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", equalTo("https://hydra.localhost:9000/oauth2/auth?scope=openid&prompt=consent&response_type=code&client_id=openIdDemo&redirect_uri=https://hydra.localhost:9000/oauth/response&state=049d71ea-30cd-4a74-8dcd-47156055d364&nonce=5210b42a-2362-420b-bb81-54796da8c814&ui_locales=et"))
                .extract().detailedCookie("oauth2_authentication_session_insecure");

        assertThat(invalidatedHydraCookie.getMaxAge(), equalTo(0L));
    }

    @Test
    void loginInit_WhenConsentsRequestRespondsWith500_ThrowsTechnicalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
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

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list --> 500 Internal Server Error from GET");
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

        assertErrorIsLogged("User input exception: loginInit.loginChallenge: Incorrect login_challenge format");
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

        assertErrorIsLogged("Duplicate parameters not allowed in request. Found multiple parameters with name: login_challenge");
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

        assertErrorIsLogged("User input exception: Required request parameter 'login_challenge' for method parameter type String is not present");
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoRespondsWith404_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(404)));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra login request info --> 404 Not Found from GET");
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoRespondsWith410_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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

        assertErrorIsLogged("SsoException: Failed to fetch Hydra login request info --> 410 Gone from GET");
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoRespondsWith500_ThrowsTechincalGeneralError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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

        assertErrorIsLogged("SsoException: Failed to fetch Hydra login request info --> 500 Internal Server Error from GET");
    }

    @Test
    void loginInit_WhenLoginResponseRequestUrlDoesntContainPromptConsent_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Request URL must contain prompt value");
    }

    @Test
    void loginInit_WhenLoginResponseRequestScopeContainsOnlyPhone_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_scope_with_phone.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap());

        assertErrorIsLogged("SsoException: Requested scope must contain openid and may contain phone, but nothing else");
    }

    @Test
    void loginInit_WhenLoginResponseRequestWithInvalidScope_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_scope_with_idcard.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap());

        assertErrorIsLogged("SsoException: Requested scope must contain openid and may contain phone, but nothing else");
    }

    @Test
    void loginInit_WhenLoginResponseRequestScopeWithOpenIdAndInvalidScope_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_scope_with_openid_and_idcard.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap());

        assertErrorIsLogged("SsoException: Requested scope must contain openid and may contain phone, but nothing else");
    }

    @Test
    void loginInit_WhenLoginResponseRequestIdTokenHintClaimIsNonEmpty_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_id_token_hint_claim_non_empty_without_subject.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap());

        assertErrorIsLogged("SsoException: id_token_hint_claims must be null");
    }

    @Test
    void loginInit_WhenLoginResponseRequestSubjectIsEmptyAndSkipIsTrue_ThrowsTechnicalGeneralError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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

        assertErrorIsLogged("SsoException: Subject is null, therefore login response skip value can not be true");
    }

    @Test
    void loginInit_WhenLoginResponseRequestSubjectIsNotEmptyAndSkipIsFalse_ThrowsTechnicalGeneralError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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

        assertErrorIsLogged("SsoException: Subject exists, therefore login response skip value can not be false");
    }

    @Test
    void loginInit_WhenLoginResponseRequestHasMoreThanOneAcrValue_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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

        assertErrorIsLogged("SsoException: acrValues must contain only 1 value");
    }

    @Test
    void loginInit_WhenLoginResponseRequestHasOneIncorrectAcrValue_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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

        assertErrorIsLogged("SsoException: acrValues must be one of low/substantial/high");
    }

    @Test
    void loginInit_WhenLoginResponseRequestHasOneCapitalizedAcrValue_ThrowsUserInputError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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

        assertErrorIsLogged("SsoException: acrValues must be one of low/substantial/high");
    }

    @Test
    void loginInit_WhenNoCSRFCookieIsSet_SetsCSRFCookie() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
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
                .header("Location", Matchers.matchesRegex("https:\\/\\/tara.localhost:10000\\/oidc\\/authorize\\?ui_locales=et&scope=openid\\+phone&acr_values=high&response_type=code&govsso_login_challenge=abcdeff098aadfccabcdeff098aadfcc&redirect_uri=https%3A%2F%2Finproxy.localhost%3A8000%2Flogin%2Ftaracallback&state=.*&nonce=.*&client_id=testclient123"))
                .cookie(COOKIE_NAME_XSRF_TOKEN, detailedCookieMatcher
                        .httpOnly(true)
                        .secured(true)
                        .path("/")
                        .maxAge(securityConfigurationProperties.getCookieMaxAgeSeconds()));
    }

    @Test
    void loginInit_WhenPromptValueIsInvalid_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_invalid_prompt_value.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Invalid prompt value");
    }

    @Test
    void loginInit_WhenMultiplePromptValues_ThrowsUserInputError() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_multiple_prompt_values.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .cookies(emptyMap())
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Request URL contains more than 1 prompt values");
    }

    @Test
    void loginInit_WhenFetchLoginRequestInfoDisplayUserConsentFalse_AcceptsConsent() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_display_user_consent_false.json")));

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
    void loginInit_WhenFetchLoginRequestInfoDisplayUserConsentTrueWithSkipUserConsentsClientIds_AcceptsConsent() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_skip_user_consent_client_ids.json")));

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
    void loginInit_WhenFetchLoginRequestInfoDisplayUserConsentTrueWithSkipUserConsentsClientIdsNotInExistingSession_AsksForConsent() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_skip_user_consent_client_ids_not_in_existing_session.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie(MOCK_OIDC_SESSION_COOKIE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE + ";charset=UTF-8")
                .body(containsString("Teenusesse <span translate=\"no\">Teenusenimi A&lt;1&gt;2&amp;3</span> sisselogimine"));
    }

    @Test
    void loginInit_WhenSessionContinuationWithoutOidcSessionCookie_ThrowsUserInputError() {

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

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Unable to continue session! Oidc session cookie not found.");
    }

    @Test
    void loginInit_WhenSessionContinuationWithoutOidcSessionCookieValue_ThrowsUserInputError() {

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

        given()
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .cookie("oauth2_authentication_session_insecure", "")
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Unable to continue session! Oidc session cookie not found.");
    }

    @ParameterizedTest
    @MethodSource("contextHeaders")
    void loginInit_WhenHeaderIsSet_ContextContainsHeaderValue(String headerName, String expectedContextValue, String expectedContextJsonPath) {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_skip_user_consent_client_ids.json")));

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
                .header(headerName, expectedContextValue)
                .param("login_challenge", TEST_LOGIN_CHALLENGE)
                .when()
                .get(LOGIN_INIT_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .cookies(emptyMap())
                .header("Location", Matchers.matchesRegex("https://clienta.localhost:11443/auth/login/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/admin/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .withRequestBody(matchingJsonPath(expectedContextJsonPath, WireMock.equalTo(expectedContextValue))));
    }

    @Nested
    @NestedTestConfiguration(OVERRIDE)
    @TestPropertySource(properties = {"govsso.session-max-duration-hours=1"})
    class MaxSessionDurationOneHourTests extends BaseTest {

        @BeforeEach
        public void setupExpectedResponseSpec() {
            RestAssured.responseSpecification = new ResponseSpecBuilder()
                    .expectHeaders(EXPECTED_RESPONSE_HEADERS_WITH_CORS).build();
        }

        @Test
        @SneakyThrows
        void loginInit_WhenConsentIdTokenExpired10SecondsAgo_ThrowsTechnicalGeneralError() {

            SignedJWT jwt = createIdTokenWithAgeInSeconds(3610);
            String responseBody = createConsentsResponseBodyWithIdToken(jwt);

            HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json; charset=UTF-8")
                            .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

            HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json; charset=UTF-8")
                            .withBody(responseBody)));

            given()
                    .param("login_challenge", TEST_LOGIN_CHALLENGE)
                    .when()
                    .get(LOGIN_INIT_REQUEST_MAPPING)
                    .then()
                    .assertThat()
                    .statusCode(500)
                    .body("error", equalTo("TECHNICAL_GENERAL"));

            assertErrorIsLogged("SsoException: Hydra session has expired");
        }

        @Test
        @SneakyThrows
        void loginInit_WhenConsentIdTokenLasts10MoreSeconds_Returns200() {

            SignedJWT jwt = createIdTokenWithAgeInSeconds(3590);
            String responseBody = createConsentsResponseBodyWithIdToken(jwt);

            HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json; charset=UTF-8")
                            .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_subject.json")));

            HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=all_expired&login_session_id=e56cbaf9-81e9-4473-a733-261e8dd38e95"))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json; charset=UTF-8")
                            .withBody(responseBody)));

            HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/admin/oauth2/auth/sessions/consent?subject=test1234&include_expired=partially_expired"))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json; charset=UTF-8")
                            .withBodyFile("mock_responses/mock_sso_oidc_consents.json")));

            given()
                    .param("login_challenge", TEST_LOGIN_CHALLENGE)
                    .cookie(MOCK_OIDC_SESSION_COOKIE)
                    .when()
                    .get(LOGIN_INIT_REQUEST_MAPPING)
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
                          "login_session_id": "e56cbaf9-81e9-4473-a733-261e8dd38e95",
                          "requested_at": "2023-01-01T01:00:00Z"
                        },
                        "remember_for": 900
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
