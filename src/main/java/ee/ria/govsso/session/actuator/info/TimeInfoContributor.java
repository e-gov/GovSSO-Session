package ee.ria.govsso.session.actuator.info;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.TimeGauge;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class TimeInfoContributor implements InfoContributor {

    private final MeterRegistry meterRegistry;

    @Override
    public void contribute(Info.Builder builder) {
        builder
                .withDetail("startTime", getServiceStartTime())
                .withDetail("currentTime", OffsetDateTime.now(ZoneOffset.UTC));
    }

    private OffsetDateTime getServiceStartTime() {
        TimeGauge startTime = meterRegistry.find("process.start.time").timeGauge();
        if (startTime == null) {
            throw new IllegalStateException("Failed to get application start time");
        }
        long startTimeEpochMilli = Double.valueOf(startTime.value(TimeUnit.MILLISECONDS)).longValue();
        Instant startTimeInstant = Instant.ofEpochMilli(startTimeEpochMilli);
        return OffsetDateTime.ofInstant(startTimeInstant, ZoneOffset.UTC);
    }
}
