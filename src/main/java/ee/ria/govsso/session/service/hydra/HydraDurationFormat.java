package ee.ria.govsso.session.service.hydra;

import lombok.NonNull;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
