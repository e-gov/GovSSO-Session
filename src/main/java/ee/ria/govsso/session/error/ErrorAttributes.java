package ee.ria.govsso.session.error;

import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.util.LocaleUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.WebRequest;

import java.util.Locale;
import java.util.Map;

import static ee.ria.govsso.session.filter.RequestCorrelationFilter.MDC_ATTRIBUTE_TRACE_ID;

@Slf4j
@Component
@RequiredArgsConstructor
public class ErrorAttributes extends DefaultErrorAttributes {
    public static final String ERROR_ATTR_MESSAGE = "message";
    public static final String ERROR_ATTR_ERROR_CODE = "error";
    public static final String ERROR_ATTR_INCIDENT_NR = "incident_nr";

    private final MessageSource messageSource;

    @Override
    public Map<String, Object> getErrorAttributes(WebRequest webRequest, ErrorAttributeOptions options) {
        Map<String, Object> attr = super.getErrorAttributes(webRequest, options);

        Throwable error = getError(webRequest);
        HttpStatus status = HttpStatus.resolve((int) attr.get("status"));

        if (error instanceof SsoException ssoException) {
            ErrorCode errorCode = ssoException.getErrorCode();
            setAttributes(attr, errorCode);
        } else {
            if (status != null && status.is4xxClientError())
                setAttributes(attr, ErrorCode.USER_INPUT);
            else
                setAttributes(attr, ErrorCode.TECHNICAL_GENERAL);
        }

        return attr;
    }

    private void setAttributes(Map<String, Object> attr, ErrorCode errorCode) {
        Locale locale = LocaleUtil.getLocale();
        attr.put(ERROR_ATTR_MESSAGE, messageSource.getMessage("error." + errorCode.name().toLowerCase(Locale.ROOT), null, locale));
        attr.put(ERROR_ATTR_INCIDENT_NR, MDC.get(MDC_ATTRIBUTE_TRACE_ID));
        attr.put(ERROR_ATTR_ERROR_CODE, errorCode.name());
    }

}
