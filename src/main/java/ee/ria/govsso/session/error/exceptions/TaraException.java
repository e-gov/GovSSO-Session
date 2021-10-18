package ee.ria.govsso.session.error.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;
import lombok.Getter;

import static ee.ria.govsso.session.error.ErrorCode.TARA_ERROR;

@Getter
public class TaraException extends SsoException {

    private final String taraErrorCode;

    public TaraException(String message) {
        super(TARA_ERROR, message, null);
        taraErrorCode = null;
    }

    public TaraException(String message, Throwable cause) {
        super(TARA_ERROR, message, cause);
        taraErrorCode = null;
    }

    public TaraException(ErrorObject errorCode) {
        super(TARA_ERROR, errorCode.getDescription());
        taraErrorCode = errorCode.getCode();
    }
}
