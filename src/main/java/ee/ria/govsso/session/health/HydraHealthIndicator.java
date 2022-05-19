package ee.ria.govsso.session.health;

import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class HydraHealthIndicator implements HealthIndicator {

    private final WebClient webclient;
    private final HydraConfigurationProperties confProperties;

    @Override
    public Health health() {
        HttpStatus hydraCheckStatus = checkHydraStatus();
        return hydraCheckStatus != null && hydraCheckStatus.is2xxSuccessful()
                ? Health.up().build()
                : Health.down().build();
    }

    @SneakyThrows
    private HttpStatus checkHydraStatus() {
        try {
            return webclient
                    .get()
                    .uri(confProperties.adminUrl().toURI().resolve("/health/alive"))
                    .exchangeToMono(response -> Mono.just(response.statusCode()))
                    .block();
        } catch (WebClientResponseException e) {
            log.debug("Failed to check Hydra status: " + e.getMessage());
            return e.getStatusCode();
        } catch (Exception e) {
            log.debug("Failed to check Hydra status: " + e.getMessage());
            return HttpStatus.INTERNAL_SERVER_ERROR;
        }
    }
}
