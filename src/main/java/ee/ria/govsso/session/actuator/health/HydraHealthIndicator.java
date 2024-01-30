package ee.ria.govsso.session.actuator.health;

import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
import ee.ria.govsso.session.util.ExceptionUtil;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
class HydraHealthIndicator implements HealthIndicator {

    private static final String HYDRA_HEALTH_CHECK_PATH = "/health/alive";

    @Qualifier("hydraWebClient")
    private final WebClient webclient;
    private final HydraConfigurationProperties confProperties;

    @Override
    public Health health() {
        HttpStatusCode hydraCheckStatus = checkHydraStatus();
        return hydraCheckStatus != null && hydraCheckStatus.is2xxSuccessful()
                ? Health.up().build()
                : Health.down().build();
    }

    @SneakyThrows
    private HttpStatusCode checkHydraStatus() {
        try {
            return webclient
                    .get()
                    .uri(confProperties.adminUrl().toURI().resolve(HYDRA_HEALTH_CHECK_PATH))
                    .exchangeToMono(response -> Mono.just(response.statusCode()))
                    .block();
        } catch (WebClientResponseException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to check Hydra status: {}", ExceptionUtil.getCauseMessages(e), e);
            }
            return e.getStatusCode();
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to check Hydra status: {}", ExceptionUtil.getCauseMessages(e), e);
            }
            return HttpStatus.INTERNAL_SERVER_ERROR;
        }
    }
}
