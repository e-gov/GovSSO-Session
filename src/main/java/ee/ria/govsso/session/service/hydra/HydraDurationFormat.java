package ee.ria.govsso.session.service.hydra;

import lombok.NonNull;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
 * Sub-second values are allowed by Hydra but not supported by this class.
 *
 * Note that the format `^([0-9]+(ns|us|ms|s|m|h))*$` given at https://www.ory.com/docs/hydra/reference/api is not
 * entirely correct, at least with Hydra 2.1.2. In reality, sub-second values are represented as decimals on seconds
 * field, rather than milli-, micro- or nanoseconds.
 * For example a duration of 123 millisecond, 456 microseconds and 789 nanoseconds is represented as `0.123456789s`,
 * not `123ms456us789ns`.
 */
public class HydraDurationFormat {

    private static final Pattern PARSER_PATTERN =
            Pattern.compile("^((?<HOURS>\\d+)h)?((?<MINUTES>\\d+)m)?((?<SECONDS>\\d+)s)?$");
    private static final List<ChronoUnit> TIME_UNITS = List.of(
            ChronoUnit.HOURS,
            ChronoUnit.MINUTES,
            ChronoUnit.SECONDS
    );

    public static Duration parse(@NonNull String durationString) {
        if (durationString.isEmpty()) {
            throw new IllegalArgumentException("Invalid duration string, cannot be empty");
        }
        Matcher matcher = PARSER_PATTERN.matcher(durationString);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid duration string: \"%s\"".formatted(durationString));
        }
        Duration duration = Duration.ZERO;
        for (ChronoUnit timeUnit : TIME_UNITS) {
            String groupValue = matcher.group(timeUnit.name());
            if (groupValue == null) {
                continue;
            }
            int amount = Integer.parseInt(groupValue);
            duration = duration.plus(amount, timeUnit);
        }
        return duration;
    }

}
