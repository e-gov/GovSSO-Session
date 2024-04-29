package ee.ria.govsso.session.logging;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import net.logstash.logback.marker.LogstashMarker;

import static net.logstash.logback.marker.Markers.append;

public class ClientRequestLogger {

    private final org.slf4j.Logger log;

    private static final String PROP_URL_FULL = "url.full";
    private static final String PROP_REQUEST_METHOD = "http.request.method";
    private static final String PROP_REQUEST_BODY_CONTENT = "http.request.body.content";

    private static final String PROP_RESPONSE_BODY_CONTENT = "http.response.body.content";
    private static final String PROP_RESPONSE_STATUS_CODE = "http.response.status_code";

    private final String logRequestMessage;
    private final String logResponseMessage;

    private final ObjectMapper objectMapper;

    public enum Service {
        ALERTS,
        TARA,
        HYDRA,
        PAASUKE,
    }

    public ClientRequestLogger(Class<?> classToBeLogged, Service service) {
        log = org.slf4j.LoggerFactory.getLogger(classToBeLogged);
        logRequestMessage = String.format("%s request", service.name());
        logResponseMessage = String.format("%s response", service.name());
        objectMapper = JsonMapper
                .builder()
                .serializationInclusion(JsonInclude.Include.NON_NULL)
                .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
                .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
                .addModule(new JavaTimeModule())
                .build();
    }

    public void logRequest(String requestUrl, String httpMethod) {
        this.logRequest(requestUrl, httpMethod, null);
    }

    public void logRequest(String requestUrl, String httpMethod, Object requestBodyObject) {
        LogstashMarker logMarker = append(PROP_REQUEST_METHOD, httpMethod)
                .and(append(PROP_URL_FULL, requestUrl));

        if (requestBodyObject != null) {
            try {
                String requestBodyJson = objectMapper.writeValueAsString(requestBodyObject);
                logMarker.and(append(PROP_REQUEST_BODY_CONTENT, requestBodyJson));
            } catch (JsonProcessingException ex) {
                throw new IllegalStateException("Unable to convert request body object to JSON string", ex);
            }
        }
        log.info(logMarker, logRequestMessage);
    }

    public void logResponse(int httpStatusCode) {
        this.logResponse(httpStatusCode, null);
    }

    public void logResponse(int httpStatusCode, Object responseBodyObject) {
        LogstashMarker logMarker = append(PROP_RESPONSE_STATUS_CODE, httpStatusCode);
        if (responseBodyObject != null) {
            try {
                String responseBodyJson = objectMapper.writeValueAsString(responseBodyObject);
                logMarker.and(append(PROP_RESPONSE_BODY_CONTENT, responseBodyJson));
            } catch (JsonProcessingException ex) {
                throw new IllegalStateException("Unable to convert response body object to JSON string", ex);
            }
        }
        log.info(logMarker, logResponseMessage);
    }
}
