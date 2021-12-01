package ee.ria.govsso.session.error;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    USER_INPUT(400, false),
    USER_INPUT_OR_EXPIRED(400, false),
    TECHNICAL_TARA_UNAVAILABLE(500, false),
    TECHNICAL_GENERAL(500, true);

    private final int httpStatusCode;
    private final boolean logStackTrace;
}
