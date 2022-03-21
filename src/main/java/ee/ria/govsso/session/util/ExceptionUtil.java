package ee.ria.govsso.session.util;

import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.exception.ExceptionUtils;

import java.util.function.Predicate;
import java.util.stream.Collectors;

@UtilityClass
public class ExceptionUtil {

    public String getCauseMessages(Exception ex) {
        return ExceptionUtils.getThrowableList(ex).stream()
                .map(Throwable::getMessage)
                .filter(Predicate.not(String::isBlank))
                .collect(Collectors.joining(" --> "));
    }

}
