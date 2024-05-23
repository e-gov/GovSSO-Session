package ee.ria.govsso.session.actuator.health;

import ee.ria.govsso.session.service.paasuke.PaasukeService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PaasukeHealthIndicator implements HealthIndicator {

    private final PaasukeService paasukeService;

    @Override
    public Health health() {
        if (paasukeService.getLastRequestToPaasukeSuccessful() == null) {
            return Health.unknown().build();
        } else if (paasukeService.getLastRequestToPaasukeSuccessful()) {
            return Health.up().build();
        } else {
            return Health.down().build();
        }
    }
}
