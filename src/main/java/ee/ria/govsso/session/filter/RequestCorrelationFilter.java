package ee.ria.govsso.session.filter;

import co.elastic.apm.api.ElasticApm;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.MDC;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.info.GitProperties;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class RequestCorrelationFilter extends OncePerRequestFilter {

    public static final String MDC_ATTRIBUTE_KEY_CLIENT_IP = "client.ip";
    public static final String MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID = "labels.govsso_trace_id";
    public static final String REQUEST_ATTRIBUTE_NAME_REQUEST_ID = "requestId";
    private static final String MDC_ATTRIBUTE_KEY_VERSION = "service.version";
    private static final String MDC_ATTRIBUTE_KEY_REQUEST_TRACE_ID = "trace.id";
    private final String version;

    public RequestCorrelationFilter(BuildProperties buildProperties, GitProperties gitProperties) {
        version = getVersion(buildProperties, gitProperties);
        logger.info("Application version: " + version);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String requestTraceId = ElasticApm.currentTransaction().getTraceId();
        if (StringUtils.isEmpty(requestTraceId)) {
            requestTraceId = RandomStringUtils.random(32, "0123456789abcdef");
            MDC.put(MDC_ATTRIBUTE_KEY_REQUEST_TRACE_ID, requestTraceId);
        }

        // NB! Set traceId also as HttpServletRequest attribute to make it accessible for Tomcat's AccessLogValve.
        // Also used as incident number in ErrorAttributes. Tracing ID-s from MDC cannot be used because Elastic APM
        // agent adds tracing ID-s to MDC right before the logging event is created and removes it right after the event
        // is logged. At other times, tracing ID-s are missing from MDC, when Elastic APM agent is enabled.
        request.setAttribute(REQUEST_ATTRIBUTE_NAME_REQUEST_ID, requestTraceId);

        if (version != null) {
            MDC.put(MDC_ATTRIBUTE_KEY_VERSION, version);
        } else {
            MDC.remove(MDC_ATTRIBUTE_KEY_VERSION);
        }

        String ipAddress = request.getRemoteAddr();
        if (StringUtils.isNotEmpty(ipAddress)) {
            MDC.put(MDC_ATTRIBUTE_KEY_CLIENT_IP, ipAddress);
        } else {
            MDC.remove(MDC_ATTRIBUTE_KEY_CLIENT_IP);
        }

        MDC.remove(MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID);

        filterChain.doFilter(request, response);

        // TODO Ideally all MDC values that are set here should be cleared after request completes - investigate where
        //  is the correct place to do that. Doing it here clears trace.id too early so that error page can not access
        //  it.
        //  As the second-best solution, we are (re)setting _all_ values above at the start of request. Usually request
        //  threads and background threads are not cross-used.
    }

    private String getVersion(BuildProperties buildProperties, GitProperties gitProperties) {
        if (buildProperties != null) {
            String versionWithoutBuildNumber = buildProperties.getVersion();

            if (gitProperties != null) {
                String buildNumber = gitProperties.get("build.number");
                if (StringUtils.isNotEmpty(buildNumber)) {
                    return versionWithoutBuildNumber + "-" + buildNumber;
                }
            }
            return versionWithoutBuildNumber;
        }
        return null;
    }

}
