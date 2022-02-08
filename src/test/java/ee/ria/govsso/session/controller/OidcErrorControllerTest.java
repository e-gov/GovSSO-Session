package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.BaseTest;
import ee.ria.govsso.session.error.ErrorHandler;
import ee.ria.govsso.session.error.exceptions.SsoException;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.springframework.boot.test.mock.mockito.SpyBean;

import java.io.IOException;

import static io.restassured.RestAssured.given;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

class OidcErrorControllerTest extends BaseTest {

    @SpyBean
    private ErrorHandler errorHandler;

    @Captor
    private ArgumentCaptor<Exception> exceptionCaptor;

    @Test
    void oidcError_WhenInvalidOidcClientErrorCode_ThrowsInvalidOidcClientError() throws IOException {
        given()
                .param("error", "invalid_client")
                .param("error_description", "Invalid client error description")
                .param("error_hint", "Invalid client error hint")
                .when()
                .get("/error/oidc")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INVALID_OIDC_CLIENT"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("Oidc server error: code = invalid_client, description = Invalid client error description, hint = Invalid client error hint"));
    }

    @Test
    void oidcError_WhenInvalidOidcRequestErrorCode_ThrowsInvalidOidcRequestError() throws IOException {
        given()
                .param("error", "invalid_request")
                .param("error_description", "Invalid request error description")
                .param("error_hint", "Invalid request error hint")
                .when()
                .get("/error/oidc")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INVALID_OIDC_REQUEST"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("Oidc server error: code = invalid_request, description = Invalid request error description, hint = Invalid request error hint"));
    }

    @Test
    void oidcError_WhenUnknownErrorCode_ThrowsUserOidcOtherError() throws IOException {
        given()
                .param("error", "unknown_error_code")
                .param("error_description", "Error description")
                .param("error_hint", "Error hint")
                .when()
                .get("/error/oidc")
                .then()
                .assertThat()
                .statusCode(500)
                .body("error", equalTo("USER_OIDC_OTHER_ERROR"));

        verify(errorHandler).handleSsoException((SsoException) exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("Oidc server error: code = unknown_error_code, description = Error description, hint = Error hint"));
    }

    @Test
    void oidcError_WhenInvalidErrorCodeSize_ThrowsUserInputError() throws IOException {
        given()
                .param("error", "x".repeat(51))
                .param("error_description", "Error description")
                .param("error_hint", "Error hint")
                .when()
                .get("/error/oidc")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", equalTo("USER_INPUT"));

        verify(errorHandler).handleBindException(exceptionCaptor.capture(), any());
        assertThat(exceptionCaptor.getValue().getMessage(),
                equalTo("oidcError.errorCode: size must be between 0 and 50"));
    }
}