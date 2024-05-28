package ee.ria.govsso.session.logging;

import ee.ria.govsso.session.BaseTestLoggingAssertion;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;

import static ch.qos.logback.classic.Level.INFO;
import static ee.ria.govsso.session.logging.ClientRequestLogger.Service.HYDRA;

@Slf4j
class ClientRequestLoggerTest extends BaseTestLoggingAssertion {

    private final ClientRequestLogger clientRequestLogger = new ClientRequestLogger(ClientRequestLogger.class, HYDRA);

    @Test
    void logRequest_WhenNoRequestBody() {
        clientRequestLogger.request(HttpMethod.GET, "https://hydra.localhost:9000").log();

        assertMessage()
                .withLoggerClass(ClientRequestLogger.class)
                .withMessage("HYDRA request")
                .withLevel(INFO)
                .withMarker("http.request.method=GET, url.full=https://hydra.localhost:9000")
                .isLoggedOnce();
    }

    @Test
    void logRequest_WhenRequestBodyPresent() {
        clientRequestLogger.request(HttpMethod.GET, "https://hydra.localhost:9000")
                .body("RequestBody")
                .log();

        assertMessage()
                .withLoggerClass(ClientRequestLogger.class)
                .withMessage("HYDRA request")
                .withLevel(INFO)
                .withMarker("http.request.method=GET, url.full=https://hydra.localhost:9000, http.request.body.content=\"RequestBody\"")
                .isLoggedOnce();
    }

    @Test
    void logRequest_WhenHeaderPresent() {
        clientRequestLogger.request(HttpMethod.GET, "https://hydra.localhost:9000")
                .header(HttpHeaders.ORIGIN, "origin-value")
                .log();

        assertMessage()
                .withLoggerClass(ClientRequestLogger.class)
                .withMessage("HYDRA request")
                .withLevel(INFO)
                .withMarker("http.request.method=GET, url.full=https://hydra.localhost:9000, http.request.header.Origin=origin-value")
                .isLoggedOnce();
    }

    @Test
    void logRequest_WhenHeaderNullValue_ThenHeaderNotLogged() {
        clientRequestLogger.request(HttpMethod.GET, "https://hydra.localhost:9000")
                .header(HttpHeaders.ORIGIN, null)
                .log();

        assertMessage()
                .withLoggerClass(ClientRequestLogger.class)
                .withMessage("HYDRA request")
                .withLevel(INFO)
                .withMarker("http.request.method=GET, url.full=https://hydra.localhost:9000")
                .isLoggedOnce();
    }

    @Test
    void logRequest_WhenHeaderHasMultipleValues() {
        clientRequestLogger.request(HttpMethod.GET, "https://hydra.localhost:9000")
                .header("Foo", "first-value")
                .header("Foo", "second-value")
                .log();

        assertMessage()
                .withLoggerClass(ClientRequestLogger.class)
                .withMessage("HYDRA request")
                .withLevel(INFO)
                .withMarker("http.request.method=GET, url.full=https://hydra.localhost:9000, http.request.header.Foo=first-value, http.request.header.Foo=second-value")
                .isLoggedOnce();
    }

    @Test
    void logResponse_WhenNoResponseBody() {
        clientRequestLogger.response(HttpStatus.OK).log();

        assertMessage()
                .withLoggerClass(ClientRequestLogger.class)
                .withMessage("HYDRA response")
                .withLevel(INFO)
                .withMarker("http.response.status_code=200")
                .isLoggedOnce();
    }

    @Test
    void logResponse_WhenResponseBodyPresent() {
        clientRequestLogger.response(HttpStatus.OK)
                .body("ResponseBody")
                .log();

        assertMessage()
                .withLoggerClass(ClientRequestLogger.class)
                .withMessage("HYDRA response")
                .withLevel(INFO)
                .withMarker("http.response.status_code=200, http.response.body.content=\"ResponseBody\"")
                .isLoggedOnce();
    }

    @Test
    void logResponse_WhenHeaderPresent() {
        clientRequestLogger.response(HttpStatus.OK)
                .header(HttpHeaders.ORIGIN, "origin-value")
                .log();

        assertMessage()
                .withLoggerClass(ClientRequestLogger.class)
                .withMessage("HYDRA response")
                .withLevel(INFO)
                .withMarker("http.response.status_code=200, http.response.header.Origin=origin-value")
                .isLoggedOnce();
    }

    @Test
    void logResponse_WhenHeaderNullValue_ThenHeaderNotLogged() {
        clientRequestLogger.response(HttpStatus.OK)
                .header(HttpHeaders.ORIGIN, null)
                .log();

        assertMessage()
                .withLoggerClass(ClientRequestLogger.class)
                .withMessage("HYDRA response")
                .withLevel(INFO)
                .withMarker("http.response.status_code=200")
                .isLoggedOnce();
    }

    @Test
    void logResponse_WhenHeaderHasMultipleValues() {
        clientRequestLogger.response(HttpStatus.OK)
                .header("Foo", "first-value")
                .header("Foo", "second-value")
                .log();

        assertMessage()
                .withLoggerClass(ClientRequestLogger.class)
                .withMessage("HYDRA response")
                .withLevel(INFO)
                .withMarker("http.response.status_code=200, http.response.header.Foo=first-value, http.response.header.Foo=second-value")
                .isLoggedOnce();
    }

}
