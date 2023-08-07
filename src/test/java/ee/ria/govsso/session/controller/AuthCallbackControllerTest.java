package ee.ria.govsso.session.controller;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import ee.ria.govsso.session.service.tara.TaraService;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieSigner;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.Date;
import java.util.stream.Stream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.putRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static ee.ria.govsso.session.controller.AuthCallbackController.CALLBACK_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static java.util.Collections.emptyMap;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.springframework.http.HttpHeaders.ORIGIN;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class AuthCallbackControllerTest extends BaseTest {
    private static final String TEST_CODE = "_wBCdwHmgifrnus0frBW43BHK74ZR4UDwGsPSX-TwtY.Cqk0T6OtkYZppp_aLHXz_00gMnhiCK6HSZftPfs7BLg";
    private static final String TEST_STATE = "VuF_ylfAWHflipdR2d6xKGLh6VB_7UrNetD3lXfOc0g";
    private final TaraConfigurationProperties taraConfigurationProperties;
    private final TaraService taraService;
    private final SsoCookieSigner ssoCookieSigner;

    static Stream<Arguments> contextHeaders() {
        return Stream.of(
                arguments("X-Forwarded-For", "111.111.111.111", "$.context.ip_address"),
                arguments("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36", "$.context.user_agent")
        );
    }

    @BeforeAll
    static void setUp() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @Test
    void authCallback_WhenTokenRequestAndAcceptRequestAreSuccessful_Redirects() {
        SsoCookie ssoCookie = createSsoCookie();
        OIDCTokenResponse tokenResponse = getTaraOidcTokenResponse(ssoCookie, "high", TEST_LOGIN_CHALLENGE);

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/login/test"));
    }

    @Test
    void authCallback_WhenTokenRequestResponseLoginChallengeIsNull_ThrowsUserInputError() {
        SsoCookie ssoCookie = createSsoCookie();
        OIDCTokenResponse tokenResponse = getTaraOidcTokenResponse(ssoCookie, "high", null);

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Invalid TARA callback govsso login challenge");
    }

    @Test
    void authCallback_WhenTokenRequestResponseLoginChallengeIsInvalid_ThrowsUserInputError() {
        SsoCookie ssoCookie = createSsoCookie();
        OIDCTokenResponse tokenResponse = getTaraOidcTokenResponse(ssoCookie, "high", "invalidLoginChallenge");

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Invalid TARA callback govsso login challenge");
    }

    @Test
    void authCallback_WhenTokenRequestWithSubstantialAcrAndIdTokenWithLowAcr_ThrowsUserInputError() {
        SsoCookie ssoCookie = createSsoCookie();
        OIDCTokenResponse tokenResponse = getTaraOidcTokenResponse(ssoCookie, "low");

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_substantial_acr.json")));

        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: ID Token acr value must be equal to or higher than hydra login request acr");
    }

    @Test
    void authCallback_WhenTokenLoginRequestResponseAcrIsEmpty_Redirects() {
        SsoCookie ssoCookie = createSsoCookie();
        OIDCTokenResponse tokenResponse = getTaraOidcTokenResponse(ssoCookie, "high");

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_empty_acr.json")));

        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/login/test"));
    }

    @Test
    void authCallback_WhenTokenRequestResponseAcrIsLow_ThrowsUserInputError() {
        SsoCookie ssoCookie = createSsoCookie();
        OIDCTokenResponse tokenResponse = getTaraOidcTokenResponse(ssoCookie, "low");

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request_with_empty_acr.json")));

        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: ID Token acr value must be equal to or higher than hydra login request acr");

    }

    @Test
    void authCallback_WhenErrorParemeterIsUserCancel_Redirects() {
        SsoCookie ssoCookie = createSsoCookie();
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));
        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/reject?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_reject.json")));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .param("error", "user_cancel")
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/reject/test"));
    }

    @Test
    void authCallback_WhenErrorParameterIsIncorrect_ThrowsUserInputError() {
        SsoCookie ssoCookie = createSsoCookie();

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/reject?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_reject.json")));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .param("error", "xuser_cancelx")
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: loginCallback.error: the only supported value is: 'user_cancel'");
    }

    @Test
    void authCallback_WhenErrorParameterIsDuplicate_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .param("error", "user_cancel")
                .param("error", "user_cancel")
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("Duplicate parameters not allowed in request. Found multiple parameters with name: error");
    }

    @Test
    void authCallback_WhenCodeParameterIsMissing_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: code parameter must not be null");
    }

    @Test
    void authCallback_WhenCodeParameterIsDuplicate_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("Duplicate parameters not allowed in request. Found multiple parameters with name: code");
    }

    @ParameterizedTest
    @ValueSource(strings = {"",
            "_wBCd",
            "_wBCdwHmgifrnus0frBW43BHK74ZR4UDwGsPSX+TwtY.Cqk0T6OtkYZppp_aLHXz_00gMnhiCK6HSZftPfs7BLg",
            "_wBCdwHmgifrnus0frBW43BHK74ZR4UDwGsPSX-TwtY.256TahemarkiPikkVaartus_256TahemarkiPikkVaartus_gggggggggggg" +
                    "256TahemarkiPikkVaartus_256TahemarkiPikkVaartus_256TahemarkiPikkVaartus_256TahemarkiPikkVaartus_" +
                    "gggggggggggggggggggggggggggggggggggggggggggggggggggggggg"})
    void authCallback_WhenCodeParameterIsInvalid_ThrowsUserInputError(String codeParameter) {

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", codeParameter)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: loginCallback.code: must match \"^[A-Za-z0-9\\-_.]{6,255}$\"");
    }

    @Test
    void authCallback_WhenStateParameterIsMissing_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: Required request parameter 'state' for method parameter type String is not present");
    }

    @Test
    void authCallback_WhenStateParameterIsDuplicate_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("Duplicate parameters not allowed in request. Found multiple parameters with name: state");
    }

    @Test
    void authCallback_WhenStateParameterNotValidatingAgainstSsoCookie_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .param("state", new State().getValue())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Invalid TARA callback state");
    }

    @Test
    void authCallback_WhenSsoCookieMissing_ThrowsUserInputError() {

        given()
                .param("code", TEST_CODE)
                .param("state", TEST_STATE)
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_COOKIE_MISSING"));

        assertErrorIsLogged("SsoException: Missing or expired cookie");
    }

    @Test
    void authCallback_WhenSsoCookieTaraStateValueIsNull_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie().withTaraAuthenticationRequestState(null);

        given()
                .param("code", TEST_CODE)
                .param("state", TEST_STATE)
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Session tara authentication request state must not be null");
    }

    @Test
    void authCallback_WhenSsoCookieTaraStateValueIsBlank_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie();
        ssoCookie.withTaraAuthenticationRequestState(" ");

        given()
                .param("code", TEST_CODE)
                .param("state", TEST_STATE)
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Invalid TARA callback state");
    }

    @Test
    void authCallback_WhenSsoCookieTaraNonceValueIsNull_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie().withTaraAuthenticationRequestNonce(null);

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Session tara authentication request nonce must not be null");
    }

    @Test
    void authCallback_WhenSsoCookieTaraNonceValueIsBlank_ThrowsUserInputError() {

        SsoCookie ssoCookie = createSsoCookie().withTaraAuthenticationRequestNonce(" ");

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("SsoException: Session tara authentication request nonce must not be null");
    }

    @ParameterizedTest
    @ValueSource(strings = {"",
            "727cWytFrnR5Qnd3.WJ2ceQVFNQIjEI05TNguUzjE9E",
            "727cWytFrnR5Qnd3_WJ2ceQVFNQIjEI05TNguUzjE9EE",
            "727cWytFrnR5Qnd3_WJ2ceQVFNQIjEI05TNguUzjE9"})
    void authCallback_WhenStateParameterIsInvalid_ThrowsUserInputError(String stateParameter) {

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .param("state", stateParameter)
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: loginCallback.state: must match \"^[A-Za-z0-9\\-_]{43}$\"");
    }

    @Test
    void authCallback_WhenRequestIdTokenRespondsWith500_ThrowsTechnicalGeneralError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(500)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_tara_oidc_token.json")));

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_TARA_UNAVAILABLE"));

        assertErrorIsLogged("SsoException: ErrorCode:null, Error description:null, Status Code:500");
    }

    @Test
    void authCallback_WhenRequestIdTokenRespondsWith400_ThrowsUserInputOrExpiredError() {

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(400)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_tara_oidc_token.json")));

        SsoCookie ssoCookie = createSsoCookie();

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT_OR_EXPIRED"));

        assertErrorIsLogged("SsoException: ErrorCode:null, Error description:null, Status Code:400");
    }

    @Test
    void authCallback_WhenAcceptLoginRespondsWith500_ThrowsTechnicalGeneralError() {
        SsoCookie ssoCookie = createSsoCookie();
        OIDCTokenResponse tokenResponse = getTaraOidcTokenResponse(ssoCookie, "high");

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(500)));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("Unexpected error: 500 Internal Server Error from PUT");
    }

    @Test
    void authCallback_WhenOriginHeaderIsSet_NoCorsResponseHeadersAreSet() {

        SsoCookie ssoCookie = createSsoCookie();
        OIDCTokenResponse tokenResponse = getTaraOidcTokenResponse(ssoCookie, "high");

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .header(ORIGIN, "https://clienta.localhost:11443")
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .headers(emptyMap())
                .header("Location", Matchers.containsString("auth/login/test"));
    }

    @ParameterizedTest
    @MethodSource("contextHeaders")
    void authCallback_WhenHeaderIsSet_ContextContainsHeaderValue(String headerName, String expectedContextValue, String expectedContextJsonPath) {
        SsoCookie ssoCookie = createSsoCookie();
        OIDCTokenResponse tokenResponse = getTaraOidcTokenResponse(ssoCookie, "high", TEST_LOGIN_CHALLENGE);

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/requests/login?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_request.json")));

        TARA_MOCK_SERVER.stubFor(post(urlEqualTo("/oidc/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(tokenResponse.toJSONObject().toJSONString())));

        HYDRA_MOCK_SERVER.stubFor(put(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_login_accept.json")));

        given()
                .param("code", TEST_CODE)
                .param("state", ssoCookie.getTaraAuthenticationRequestState())
                .cookie(ssoCookieSigner.getSignedCookieValue(ssoCookie))
                .header(headerName, expectedContextValue)
                .when()
                .get(CALLBACK_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", Matchers.containsString("auth/login/test"));

        HYDRA_MOCK_SERVER.verify(putRequestedFor(urlEqualTo("/oauth2/auth/requests/login/accept?login_challenge=" + TEST_LOGIN_CHALLENGE))
                .withRequestBody(matchingJsonPath(expectedContextJsonPath, WireMock.equalTo(expectedContextValue))));
    }

    private SsoCookie createSsoCookie() {
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest("high", TEST_LOGIN_CHALLENGE);
        return SsoCookie.builder()
                .loginChallenge(TEST_LOGIN_CHALLENGE)
                .taraAuthenticationRequestState(authenticationRequest.getState().getValue())
                .taraAuthenticationRequestNonce(authenticationRequest.getNonce().getValue())
                .build();
    }

    @SneakyThrows
    private OIDCTokenResponse getTaraOidcTokenResponse(SsoCookie ssoCookie, String acr) {
        return getTaraOidcTokenResponse(ssoCookie, acr, TEST_LOGIN_CHALLENGE);
    }

    @SneakyThrows
    private OIDCTokenResponse getTaraOidcTokenResponse(SsoCookie ssoCookie, String acr, String loginChallenge) {
        JWSSigner signer = new RSASSASigner(TARA_JWK);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .claim("nonce", ssoCookie.getTaraAuthenticationRequestNonce())
                .claim("state", ssoCookie.getTaraAuthenticationRequestState())
                .claim("acr", acr)
                .claim("amr", new String[]{"mID"})
                .claim("govsso_login_challenge", loginChallenge)
                .audience(taraConfigurationProperties.clientId())
                .subject("test")
                .issuer(TARA_MOCK_URL)
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(10)))
                .build();

        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(RS256).keyID(TARA_JWK.getKeyID()).build(), claimsSet);
        jwt.sign(signer);

        BearerAccessToken accessToken = new BearerAccessToken();
        OIDCTokens oidcTokens = new OIDCTokens(jwt, accessToken, null);
        return new OIDCTokenResponse(oidcTokens);
    }
}
