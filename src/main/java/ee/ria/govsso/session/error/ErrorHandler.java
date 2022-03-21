package ee.ria.govsso.session.error;

import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.util.ExceptionUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintViolationException;
import java.io.IOException;

import static net.logstash.logback.marker.Markers.append;

@Slf4j
@ControllerAdvice
@RequiredArgsConstructor
public class ErrorHandler {

    // These are considered as USER_INPUT errors.
    @ExceptionHandler({ConstraintViolationException.class, MissingServletRequestParameterException.class})
    public void handleBindException(Exception ex, HttpServletResponse response) throws IOException {
        if (log.isDebugEnabled()) {
            logErrorWithStacktrace(ex, ErrorCode.USER_INPUT, "User input exception: {}");
        } else {
            logError(ex, ErrorCode.USER_INPUT, "User input exception: {}");
        }
        response.sendError(400);
    }

    @ExceptionHandler({SsoException.class})
    public void handleSsoException(SsoException ex, HttpServletResponse response) throws IOException {
        if (ex.getErrorCode().isLogStackTrace() || log.isDebugEnabled()) {
            logErrorWithStacktrace(ex, ex.getErrorCode(), "SsoException: {}");
        } else {
            logError(ex, ex.getErrorCode(), "SsoException: {}");
        }
        response.sendError(ex.getErrorCode().getHttpStatusCode());
    }

    // These are considered as TECHNICAL_GENERAL errors.
    @ExceptionHandler({Exception.class})
    public void handleAll(Exception ex, HttpServletResponse response) throws IOException {
        logErrorWithStacktrace(ex, ErrorCode.TECHNICAL_GENERAL, "Unexpected error: {}");
        response.sendError(500);
    }

    private void logErrorWithStacktrace(Exception ex, ErrorCode errorCode, String messageFormat) {
        log.error(append("error.code", errorCode.name()), messageFormat, ExceptionUtil.getCauseMessages(ex), ex);
    }

    private void logError(Exception ex, ErrorCode errorCode, String messageFormat) {
        log.error(append("error.code", errorCode.name()), messageFormat, ExceptionUtil.getCauseMessages(ex));
    }

}
