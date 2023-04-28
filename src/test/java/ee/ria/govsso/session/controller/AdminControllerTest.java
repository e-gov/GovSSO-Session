package ee.ria.govsso.session.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.govsso.session.BaseTest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;

import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Stream;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.session.configuration.SecurityConfiguration.COOKIE_NAME_XSRF_TOKEN;
import static ee.ria.govsso.session.controller.AdminController.ADMIN_SESSIONS_BY_ID_REQUEST_MAPPING;
import static ee.ria.govsso.session.controller.AdminController.ADMIN_SESSIONS_REQUEST_MAPPING;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class AdminControllerTest extends BaseTest {
    protected static final String TEST_SUBJECT = "Isikukood1";
    protected static final String TEST_LOGIN_SESSION_ID = "00000000-0000-0000-0000-111111111111";
    private final ObjectMapper objectMapper;

    private static Stream<Arguments> invalidStatusCodes() {
        return Arrays.stream(HttpStatus.values())
                .filter(s -> s.is4xxClientError() || s.is5xxServerError())
                .map(s -> arguments((s.value())));
    }

    private static Stream<Arguments> subjectNames() {
        return Stream.of(
                Arguments.of(" ", "blank"),
                Arguments.of("x".repeat(256), "length 256")
        );
    }

    @Test
    void getBySubject_WhenConsentSessionsFound_ReturnsSessions(@Value("classpath:__files/mock_responses/admin/admin_sessions_subject.json") Resource expectedResult) throws IOException {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=%s&include_expired=true".formatted(TEST_SUBJECT)))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_sessions.json")));
        String expectedMinifiedJson = objectMapper.readValue(expectedResult.getFile(), JsonNode.class).toString();

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .pathParam("subject", TEST_SUBJECT)
                .when()
                .get(ADMIN_SESSIONS_REQUEST_MAPPING)
                .then()
                .assertThat()
                .contentType(APPLICATION_JSON_VALUE)
                .statusCode(200)
                .body(equalTo(expectedMinifiedJson));
    }

    @ParameterizedTest(name = "{index} subject={1}")
    @MethodSource("subjectNames")
    void getBySubject_WhenInvalidSubjectParameter_ReturnsHttp400(String subject, String subjectLengthDescription) {

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .pathParam("subject", subject)
                .when()
                .get(ADMIN_SESSIONS_REQUEST_MAPPING)
                .then()
                .assertThat()
                .contentType(APPLICATION_JSON_VALUE)
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: getBySubject.subject:");
    }

    @ParameterizedTest
    @MethodSource("invalidStatusCodes")
    void getBySubject_WhenGetConsentsReturnsInvalidHttpStatus_ReturnsHttp500(int statusCode) {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/auth/sessions/consent?subject=%s&include_expired=true".formatted(TEST_SUBJECT)))
                .willReturn(aResponse()
                        .withStatus(statusCode)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/mock_sso_oidc_consents_multiple_sessions.json")));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .pathParam("subject", TEST_SUBJECT)
                .when()
                .get(ADMIN_SESSIONS_REQUEST_MAPPING)
                .then()
                .assertThat()
                .contentType(APPLICATION_JSON_VALUE)
                .statusCode(500)
                .body("error", equalTo("TECHNICAL_GENERAL"));

        assertErrorIsLogged("SsoException: Failed to fetch Hydra consents list");
    }

    @Test
    void deleteBySubject_WhenDeleteConsentSuccess_ReturnsHttp204() {
        HYDRA_MOCK_SERVER.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=%s&all=true&trigger_backchannel_logout=true".formatted(TEST_SUBJECT)))
                .willReturn(aResponse()
                        .withStatus(204)));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .pathParam("subject", TEST_SUBJECT)
                .when()
                .delete(ADMIN_SESSIONS_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200);
    }

    @ParameterizedTest(name = "{index} subject={1}")
    @MethodSource("subjectNames")
    void deleteBySubject_WhenInvalidSubjectParameter_ReturnsHttp400(String subject, String subjectLengthDescription) {

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .pathParam("subject", subject)
                .when()
                .delete(ADMIN_SESSIONS_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400);

        assertErrorIsLogged("User input exception: deleteBySubject.subject:");
    }

    @ParameterizedTest
    @MethodSource("invalidStatusCodes")
    void deleteBySubject_WhenDeleteConsentsReturnsInvalidHttpStatus_ReturnsHttp500(int statusCode) {
        HYDRA_MOCK_SERVER.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=%s&all=true&trigger_backchannel_logout=true".formatted(TEST_SUBJECT)))
                .willReturn(aResponse()
                        .withStatus(statusCode)));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .pathParam("subject", TEST_SUBJECT)
                .when()
                .delete(ADMIN_SESSIONS_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("SsoException: Failed to delete Hydra consent --> %d".formatted(statusCode));
    }

    @Test
    void deleteBySubjectSession_WhenDeleteConsentSuccess_Returns204() {
        HYDRA_MOCK_SERVER.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=%s&login_session_id=%s&all=true&trigger_backchannel_logout=true".formatted(TEST_SUBJECT, TEST_LOGIN_SESSION_ID)))
                .willReturn(aResponse()
                        .withStatus(204)));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .pathParam("subject", TEST_SUBJECT)
                .pathParam("loginSessionId", TEST_LOGIN_SESSION_ID)
                .when()
                .delete(ADMIN_SESSIONS_BY_ID_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(200);
    }

    @ParameterizedTest(name = "{index} subject={1}")
    @MethodSource("subjectNames")
    void deleteBySubjectSession_WhenInvalidSubjectParameter_ReturnsHttp400(String subject, String subjectLengthDescription) {

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .pathParam("subject", subject)
                .pathParam("loginSessionId", TEST_LOGIN_SESSION_ID)
                .when()
                .delete(ADMIN_SESSIONS_BY_ID_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400);

        assertErrorIsLogged("User input exception: deleteBySubjectSession.subject:");
    }

    @ParameterizedTest
    @ValueSource(strings = {"length-35-aaaaaaaaaaaaaaaaaaaaaaaaa", "length-37-aaaaaaaaaaaaaaaaaaaaaaaaa", "length-36-contains-invalid-chars-!!!", "length-36-contains-uppercase-chars-A"})
    void deleteBySubjectSession_WhenInvalidLoginSessionIdParameter_ReturnsHttp400(String loginSessionId) {

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .pathParam("subject", TEST_SUBJECT)
                .pathParam("loginSessionId", loginSessionId)
                .when()
                .delete(ADMIN_SESSIONS_BY_ID_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(400);

        assertErrorIsLogged("User input exception: deleteBySubjectSession.loginSessionId: must match \"^[0-9a-f-]{36}$\"");
    }

    @ParameterizedTest
    @MethodSource("invalidStatusCodes")
    void deleteBySubjectSession_WhenDeleteConsentsReturnsInvalidHttpStatus_ReturnsHttp500(int statusCode) {
        HYDRA_MOCK_SERVER.stubFor(delete(urlEqualTo("/oauth2/auth/sessions/consent?subject=%s&login_session_id=%s&all=true&trigger_backchannel_logout=true".formatted(TEST_SUBJECT, TEST_LOGIN_SESSION_ID)))
                .willReturn(aResponse()
                        .withStatus(statusCode)));

        given()
                .cookie(COOKIE_NAME_XSRF_TOKEN, MOCK_CSRF_TOKEN)
                .pathParam("subject", TEST_SUBJECT)
                .pathParam("loginSessionId", TEST_LOGIN_SESSION_ID)
                .when()
                .delete(ADMIN_SESSIONS_BY_ID_REQUEST_MAPPING)
                .then()
                .assertThat()
                .statusCode(500);

        assertErrorIsLogged("SsoException: Failed to delete Hydra consent --> %d".formatted(statusCode));
    }
}
