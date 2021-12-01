package ee.ria.govsso.session.error;

import ee.ria.govsso.session.error.exceptions.SsoException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintViolationException;
import java.io.IOException;

@Slf4j
@ControllerAdvice
@RequiredArgsConstructor
public class ErrorHandler {

    // These are considered as USER_INPUT errors.
    @ExceptionHandler({ConstraintViolationException.class, MissingServletRequestParameterException.class})
    public void handleBindException(Exception ex, HttpServletResponse response) throws IOException {
        if (log.isDebugEnabled())
            log.error("User input exception: {}", ex.getMessage(), ex);
        else
            log.error("User input exception: {}", ex.getMessage());
        response.sendError(400);
    }

    @ExceptionHandler({SsoException.class})
    public void handleSsoException(SsoException ex, HttpServletResponse response) throws IOException {
        if (ex.getErrorCode().isLogStackTrace() || log.isDebugEnabled())
            log.error("Server encountered an SsoException: {}", ex.getMessage(), ex);
        else
            log.error("Server encountered an SsoException: {}", ex.getMessage());
        response.sendError(ex.getErrorCode().getHttpStatusCode());
    }

    // These are considered as TECHNICAL_GENERAL errors.
    @ExceptionHandler({Exception.class})
    public void handleAll(Exception ex, HttpServletResponse response) throws IOException {
        log.error("Server encountered an unexpected error: {}", ex.getMessage(), ex);
        response.sendError(500);
    }

}
