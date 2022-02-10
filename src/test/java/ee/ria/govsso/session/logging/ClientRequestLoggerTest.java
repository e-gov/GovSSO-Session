package ee.ria.govsso.session.logging;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ee.ria.govsso.session.BaseTestLoggingAssertion;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

@Slf4j
class ClientRequestLoggerTest extends BaseTestLoggingAssertion {

    private final ClientRequestLogger clientRequestLogger = new ClientRequestLogger(ClientRequestLogger.class, "Hydra");

    @Test
    void logRequest_WhenNoRequestBody() {
        clientRequestLogger.logRequest("https://hydra.localhost:9000", HttpMethod.GET.name());
        List<ILoggingEvent> loggedEvents = assertInfoIsLogged(ClientRequestLogger.class, "Hydra service request");
        assertThat(loggedEvents, hasSize(1));
        ILoggingEvent logEvent = loggedEvents.get(0);
        assertThat("http.request.method=GET, url.full=https://hydra.localhost:9000", equalTo(logEvent.getMarker().toString()));
    }

    @Test
    void logRequest_WhenRequestBodyPresent() {
        clientRequestLogger.logRequest("https://hydra.localhost:9000", HttpMethod.GET.name(), "RequestBody");
        List<ILoggingEvent> loggedEvents = assertInfoIsLogged(ClientRequestLogger.class, "Hydra service request");
        assertThat(loggedEvents, hasSize(1));
        ILoggingEvent logEvent = loggedEvents.get(0);
        assertThat(
                "http.request.method=GET, url.full=https://hydra.localhost:9000, http.request.body.content=\"RequestBody\"",
                equalTo(logEvent.getMarker().toString()));
    }

    @Test
    void logResponse_WhenNoResponseBody() {
        clientRequestLogger.logResponse(HttpStatus.OK.value());
        List<ILoggingEvent> loggedEvents = assertInfoIsLogged(ClientRequestLogger.class, "Hydra service response");
        assertThat(loggedEvents, hasSize(1));
        assertThat("http.response.status_code=200", equalTo(loggedEvents.get(0).getMarker().toString()));
    }

    @Test
    void logResponse_WhenResponseBodyPresent() {
        clientRequestLogger.logResponse(HttpStatus.OK.value(), "ResponseBody");
        List<ILoggingEvent> loggedEvents = assertInfoIsLogged(ClientRequestLogger.class, "Hydra service response");
        assertThat(loggedEvents, hasSize(1));
        ILoggingEvent logEvent = loggedEvents.get(0);
        assertThat("http.response.status_code=200, http.response.body.content=\"ResponseBody\"",
                equalTo(logEvent.getMarker().toString()));
    }
}
