package ee.ria.govsso.session.logging;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.logstash.logback.marker.LogstashMarker;

import static net.logstash.logback.marker.Markers.append;

public class ClientRequestLogger { // TODO: Compare with AUT-850

    private final org.slf4j.Logger log;

    private static final String PROP_URL_FULL = "url.full";
    private static final String PROP_REQUEST_METHOD = "http.request.method";
    private static final String PROP_REQUEST_BODY_CONTENT = "http.request.body.content";

    private static final String PROP_RESPONSE_BODY_CONTENT = "http.response.body.content";
    private static final String PROP_RESPONSE_STATUS_CODE = "http.response.status_code";

    private final String LOG_REQUEST_MESSAGE;
    private final String LOG_RESPONSE_MESSAGE;

    private final ObjectMapper OBJECT_MAPPER;

    public ClientRequestLogger(Class<?> classToBeLogged, String serviceName) {
        log = org.slf4j.LoggerFactory.getLogger(classToBeLogged);
        LOG_REQUEST_MESSAGE = String.format("%s service request", serviceName);
        LOG_RESPONSE_MESSAGE = String.format("%s service response", serviceName);
        OBJECT_MAPPER = new ObjectMapper();
        OBJECT_MAPPER.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    public void logRequest(String requestUrl, String httpMethod) {
        this.logRequest(requestUrl, httpMethod, null);
    }

    public void logRequest(String requestUrl, String httpMethod, Object requestBodyObject) {
        LogstashMarker logMarker = append(PROP_REQUEST_METHOD, httpMethod)
                .and(append(PROP_URL_FULL, requestUrl));

        if (requestBodyObject != null) {
            try {
                String requestBodyJson = OBJECT_MAPPER.writeValueAsString(requestBodyObject);
                logMarker.and(append(PROP_REQUEST_BODY_CONTENT, requestBodyJson));
            } catch (JsonProcessingException ex) {
                throw new IllegalStateException("Unable to convert request body object to JSON string", ex);
            }
        }
        log.info(logMarker, LOG_REQUEST_MESSAGE);
    }

    public void logResponse(int httpStatusCode) {
        this.logResponse(httpStatusCode, null);
    }

    public void logResponse(int httpStatusCode, Object responseBodyObject) {
        LogstashMarker logMarker = append(PROP_RESPONSE_STATUS_CODE, httpStatusCode);
        if (responseBodyObject != null) {
            try {
                String responseBodyJson = OBJECT_MAPPER.writeValueAsString(responseBodyObject);
                logMarker.and(append(PROP_RESPONSE_BODY_CONTENT, responseBodyJson));
            } catch (JsonProcessingException ex) {
                throw new IllegalStateException("Unable to convert response body object to JSON string", ex);
            }
        }
        log.info(logMarker, LOG_RESPONSE_MESSAGE);
    }
}
