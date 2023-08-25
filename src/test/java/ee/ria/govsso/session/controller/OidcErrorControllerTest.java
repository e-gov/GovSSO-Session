package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

class OidcErrorControllerTest extends BaseTest {

    @Test
    void oidcError_WhenInvalidOidcClientErrorCode_ThrowsInvalidOidcClientError() {
        given()
                .param("error", "invalid_client")
                .param("error_description", "Invalid client error description")
                .when()
                .get("/error/oidc")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INVALID_OIDC_CLIENT"));

        assertErrorIsLogged("SsoException: Oidc server error: code = invalid_client, description = Invalid client error description");
    }

    @Test
    void oidcError_WhenInvalidOidcRequestErrorCode_ThrowsInvalidOidcRequestError() {
        given()
                .param("error", "invalid_request")
                .param("error_description", "Invalid request error description")
                .when()
                .get("/error/oidc")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INVALID_OIDC_REQUEST"));

        assertErrorIsLogged("SsoException: Oidc server error: code = invalid_request, description = Invalid request error description");
    }

    @Test
    void oidcError_WhenUnknownErrorCode_ThrowsUserOidcOtherError() {
        given()
                .param("error", "unknown_error_code")
                .param("error_description", "Error description")
                .when()
                .get("/error/oidc")
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("USER_OIDC_OTHER_ERROR"));

        assertErrorIsLogged("SsoException: Oidc server error: code = unknown_error_code, description = Error description");
    }

    @Test
    void oidcError_WhenInvalidErrorCodeSize_ThrowsUserInputError() {
        given()
                .param("error", "x".repeat(51))
                .param("error_description", "Error description")
                .when()
                .get("/error/oidc")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        assertErrorIsLogged("User input exception: oidcError.errorCode: size must be between 0 and 50");
    }
}
