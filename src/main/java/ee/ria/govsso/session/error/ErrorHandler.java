package ee.ria.govsso.session.error;

import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.logging.StatisticsLogger;
import ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType;
import ee.ria.govsso.session.service.hydra.ConsentRequestInfo;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.util.ExceptionUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintViolationException;
import java.io.IOException;

import static ee.ria.govsso.session.logging.StatisticsLogger.AUTHENTICATION_REQUEST_TYPE;
import static ee.ria.govsso.session.logging.StatisticsLogger.CONSENT_REQUEST_INFO;
import static ee.ria.govsso.session.logging.StatisticsLogger.LOGIN_REQUEST_INFO;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@ControllerAdvice
@RequiredArgsConstructor
public class ErrorHandler {
    private final StatisticsLogger statisticsLogger;

    // These are considered as USER_INPUT errors.
    @ExceptionHandler({ConstraintViolationException.class, MissingServletRequestParameterException.class})
    public void handleBindException(Exception ex, HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (log.isDebugEnabled()) {
            logErrorWithStacktrace(ex, ErrorCode.USER_INPUT, "User input exception: {}", request);
        } else {
            logError(ex, ErrorCode.USER_INPUT, "User input exception: {}", request);
        }
        response.sendError(400);
    }

    @ExceptionHandler({SsoException.class})
    public void handleSsoException(SsoException ex, HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (ex.getErrorCode().isLogStackTrace() || log.isDebugEnabled()) {
            logErrorWithStacktrace(ex, ex.getErrorCode(), "SsoException: {}", request);
        } else {
            logError(ex, ex.getErrorCode(), "SsoException: {}", request);
        }
        response.sendError(ex.getErrorCode().getHttpStatusCode());
    }

    // These are considered as TECHNICAL_GENERAL errors.
    @ExceptionHandler({Exception.class})
    public void handleAll(Exception ex, HttpServletRequest request, HttpServletResponse response) throws IOException {
        logErrorWithStacktrace(ex, ErrorCode.TECHNICAL_GENERAL, "Unexpected error: {}", request);
        response.sendError(500);
    }

    private void logErrorWithStacktrace(Exception ex, ErrorCode errorCode, String messageFormat, HttpServletRequest request) {
        log.error(append("error.code", errorCode.name()), messageFormat, ExceptionUtil.getCauseMessages(ex), ex);
        logStatistics(ex, errorCode, request);
    }

    private void logError(Exception ex, ErrorCode errorCode, String messageFormat, HttpServletRequest request) {
        log.error(append("error.code", errorCode.name()), messageFormat, ExceptionUtil.getCauseMessages(ex));
        logStatistics(ex, errorCode, request);
    }

    private void logStatistics(Exception ex, ErrorCode errorCode, HttpServletRequest request) {
        Object requestType = request.getAttribute(AUTHENTICATION_REQUEST_TYPE);
        LoginRequestInfo loginRequestInfo = (LoginRequestInfo) request.getAttribute(LOGIN_REQUEST_INFO);
        ConsentRequestInfo consentRequestInfo = (ConsentRequestInfo) request.getAttribute(CONSENT_REQUEST_INFO);
        if (loginRequestInfo != null) {
            statisticsLogger.logError(ex, errorCode, loginRequestInfo.getClient(), loginRequestInfo.getSessionId(), (AuthenticationRequestType) requestType);
        } else if (consentRequestInfo != null) {
            statisticsLogger.logError(ex, errorCode, consentRequestInfo.getClient(), consentRequestInfo.getLoginSessionId(), (AuthenticationRequestType) requestType);
        }
    }
}
