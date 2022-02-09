package ee.ria.govsso.session.configuration;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;
import java.io.IOException;

import static org.apache.commons.lang3.StringUtils.isEmpty;

@Slf4j
@Component
@RequiredArgsConstructor
public class RequestCorrelationFilter extends OncePerRequestFilter {
    public static final String MDC_ATTRIBUTE_TRACE_ID = "trace.id";

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws ServletException, IOException {

        String requestId = MDC.get(MDC_ATTRIBUTE_TRACE_ID);

        if (isEmpty(requestId)) {
            MDC.put(MDC_ATTRIBUTE_TRACE_ID, RandomStringUtils.random(32, "0123456789abcdef"));
        }

        filterChain.doFilter(request, response);
    }
}
