package ee.ria.govsso.session.service.alerts;

import ee.ria.govsso.session.BaseTest;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

@Slf4j
@TestPropertySource(
        properties = {"govsso.alerts.enabled=true"})
public class AlertsServiceTest extends BaseTest {

    @Autowired(required = false)
    private AlertsService alertsService;

    public static void createAlertsStub(String response, int status) {
        ADMIN_MOCK_SERVER.stubFor(get(urlEqualTo("/alerts"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withStatus(status)
                        .withBodyFile(response)));
    }

    @Test
    void updateAlerts_WhenAlertsRequestReturnsActiveAlerts_getStaticAndActiveAlertsMethodReturnsAlerts() {
        createAlertsStub("mock_responses/alerts/active-alerts-response.json", 200);

        alertsService.updateAlertsTask();

        List<Alert> alerts = alertsService.getStaticAndActiveAlerts();

        assertThat(alerts, hasSize(1));

        Alert alert = alerts.get(0);

        assertThat(alert.getStartTime(), equalTo("2021-01-01T12:00:00Z"));
        assertThat(alert.getEndTime(), equalTo("3031-01-01T12:00:00Z"));
        assertThat(alert.getAlertMessage("et"), equalTo("Alert 1 message et"));
        assertThat(alert.getAlertMessage("en"), equalTo("Alert 1 message en"));
        assertThat(alert.getLoginAlert().isEnabled(), is(true));
    }

    @Test
    void updateAlerts_WhenAlertsRequestReturnsInactiveAlerts_getStaticAndActiveAlertsMethodReturnsEmptyList() {
        createAlertsStub("mock_responses/alerts/inactive-alerts-response.json", 200);
        alertsService.updateAlertsTask();
        assertThat(alertsService.getStaticAndActiveAlerts(), empty());
    }

    @Test
    void updateAlerts_WhenAlertsRequestReturnsDisabledAlerts_getStaticAndActiveAlertsMethodReturnsEmptyList() {
        createAlertsStub("mock_responses/alerts/disabled-alerts-response.json", 200);
        alertsService.updateAlertsTask();
        assertThat(alertsService.getStaticAndActiveAlerts(), empty());
    }
}

