package ee.ria.govsso.session.service.alerts;

import ee.ria.govsso.session.configuration.properties.AdminConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.AlertsConfigurationProperties;
import ee.ria.govsso.session.logging.ClientRequestLogger;
import ee.ria.govsso.session.util.ExceptionUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static ee.ria.govsso.session.logging.ClientRequestLogger.Service.ALERTS;
import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;

@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(value = "govsso.alerts.enabled", havingValue = "true")
public class AlertsService {

    @Qualifier("adminWebClient")
    private final WebClient webclient;
    private final ClientRequestLogger requestLogger = new ClientRequestLogger(this.getClass(), ALERTS);
    private final AlertsConfigurationProperties alertsConfigurationProperties;
    private final AdminConfigurationProperties adminConfigurationProperties;
    List<Alert> alerts;

    @Scheduled(fixedRateString = "${govsso.alerts.refresh-alerts-interval-in-milliseconds:10000}")
    public void updateAlertsTask() {
        String uri = adminConfigurationProperties.hostUrl() + "/alerts";

        try {
            requestLogger.logRequest(uri, HttpMethod.GET.name());
            List<Alert> alerts = webclient.get()
                    .uri(uri)
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToFlux(Alert.class)
                    .collectList()
                    .blockOptional().orElseThrow();
            requestLogger.logResponse(HttpStatus.OK.value(), alerts);

            this.alerts = alerts;

        } catch (Exception ex) {
            log.error("Unable to update alerts: {}", ExceptionUtil.getCauseMessages(ex), ex);
        }
    }

    public List<Alert> getStaticAndActiveAlerts() {
        List<Alert> alerts = new ArrayList<>();
        getStaticAlert().ifPresent(alerts::add);
        alerts.addAll(getActiveAlerts());
        return alerts;
    }

    public boolean hasStaticAlert() {
        return getStaticAlert().isPresent();
    }

    private List<Alert> getActiveAlerts() {
        if (alerts == null) {
            return emptyList();
        }
        return alerts.stream()
                .filter(Alert::isActive)
                .collect(toList());
    }

    private Optional<Alert> getStaticAlert() {
        AlertsConfigurationProperties.StaticAlert staticAlert = alertsConfigurationProperties.getStaticAlert();
        if (staticAlert == null) {
            return Optional.empty();
        }
        LoginAlert loginAlert = new LoginAlert();
        loginAlert.setMessageTemplates(staticAlert.getMessageTemplates());

        Alert alert = new Alert();
        alert.setStartTime(OffsetDateTime.now().toString());
        alert.setEndTime(OffsetDateTime.now().plusYears(1).toString());
        alert.setLoginAlert(loginAlert);
        alert.setLoadedFromConf(true);

        return Optional.of(alert);
    }
}
