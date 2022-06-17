package ee.ria.govsso.session.util;

import co.elastic.apm.api.ElasticApm;
import ee.ria.govsso.session.filter.RequestCorrelationFilter;
import lombok.NonNull;
import lombok.experimental.UtilityClass;
import org.slf4j.MDC;

@UtilityClass
public class RequestUtil {

    private static final String APM_LABEL_KEY_FLOW_TRACE_ID = "govsso_trace_id";

    // All calling locations have checked beforehand, that loginOrLogoutChallenge conforms to a certain pattern.
    public void setFlowTraceId(@NonNull String loginOrLogoutChallenge) {
        ElasticApm.currentTransaction().setLabel(APM_LABEL_KEY_FLOW_TRACE_ID, loginOrLogoutChallenge);
        MDC.put(RequestCorrelationFilter.MDC_ATTRIBUTE_KEY_FLOW_TRACE_ID, loginOrLogoutChallenge);
    }

}
