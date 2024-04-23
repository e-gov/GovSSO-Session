package ee.ria.govsso.session.error;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    USER_INPUT(400, false),
    USER_INPUT_OR_EXPIRED(400, false),
    USER_COOKIE_MISSING(400, false),
    USER_INVALID_OIDC_CLIENT(400, false),
    USER_INVALID_OIDC_REQUEST(400, false),
    USER_OIDC_OTHER_ERROR(500, false),
    TECHNICAL_TARA_UNAVAILABLE(500, false),
    TECHNICAL_GENERAL(500, true),
    TECHNICAL_PAASUKE_UNAVAILABLE(500, true);

    private final int httpStatusCode;
    private final boolean logStackTrace;
}
