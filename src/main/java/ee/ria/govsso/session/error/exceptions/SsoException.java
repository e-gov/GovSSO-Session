package ee.ria.govsso.session.error.exceptions;

import ee.ria.govsso.session.error.ErrorCode;
import lombok.Getter;

import static ee.ria.govsso.session.error.ErrorCode.TECHNICAL_GENERAL;

@Getter
public class SsoException extends RuntimeException {

    private final ErrorCode errorCode;

    public SsoException(String message) {
        super(message);
        this.errorCode = TECHNICAL_GENERAL;
    }

    public SsoException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = TECHNICAL_GENERAL;
    }

    public SsoException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public SsoException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }
}
