package ee.ria.govsso.session.logging;

import ee.ria.govsso.session.BaseTestLoggingAssertion;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;

import static ch.qos.logback.classic.Level.INFO;
import static ee.ria.govsso.session.logging.ClientRequestLogger.Service.HYDRA;

@Slf4j
class ClientRequestLoggerTest extends BaseTestLoggingAssertion {

    private final ClientRequestLogger clientRequestLogger = new ClientRequestLogger(ClientRequestLogger.class, HYDRA);

    @Test
    void logRequest_WhenNoRequestBody() {
        clientRequestLogger.logRequest("https://hydra.localhost:9000", HttpMethod.GET.name());

        assertMessage()
                .withLoggerClass(ClientRequestLogger.class)
                .withMessage("HYDRA request")
                .withLevel(INFO)
                .withMarker("http.request.method=GET, url.full=https://hydra.localhost:9000")
                .isLoggedOnce();
    }

    @Test
    void logRequest_WhenRequestBodyPresent() {
        clientRequestLogger.logRequest("https://hydra.localhost:9000", HttpMethod.GET.name(), "RequestBody");

        assertMessage()
                .withLoggerClass(ClientRequestLogger.class)
                .withMessage("HYDRA request")
                .withLevel(INFO)
                .withMarker("http.request.method=GET, url.full=https://hydra.localhost:9000, http.request.body.content=\"RequestBody\"")
                .isLoggedOnce();
    }

    @Test
    void logResponse_WhenNoResponseBody() {
        clientRequestLogger.logResponse(HttpStatus.OK.value());

        assertMessage()
                .withLoggerClass(ClientRequestLogger.class)
                .withMessage("HYDRA response")
                .withLevel(INFO)
                .withMarker("http.response.status_code=200")
                .isLoggedOnce();
    }

    @Test
    void logResponse_WhenResponseBodyPresent() {
        clientRequestLogger.logResponse(HttpStatus.OK.value(), "ResponseBody");

        assertMessage()
                .withLoggerClass(ClientRequestLogger.class)
                .withMessage("HYDRA response")
                .withLevel(INFO)
                .withMarker("http.response.status_code=200, http.response.body.content=\"ResponseBody\"")
                .isLoggedOnce();
    }
}
