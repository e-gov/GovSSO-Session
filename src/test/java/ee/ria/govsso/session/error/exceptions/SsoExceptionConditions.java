package ee.ria.govsso.session.error.exceptions;

import ee.ria.govsso.session.error.ErrorCode;
import lombok.experimental.UtilityClass;
import org.assertj.core.api.Condition;

import java.util.Objects;

@UtilityClass
public class SsoExceptionConditions {

    public static Condition<SsoException> errorCode(ErrorCode expected) {
        return new Condition<>(
                e -> Objects.equals(e.getErrorCode(), expected),
                "error code to be <%s>",
                expected
        );
    }

}
