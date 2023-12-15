package ee.ria.govsso.session.configuration.properties;

import ee.ria.govsso.session.service.alerts.MessageTemplate;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import java.util.ArrayList;
import java.util.List;

@Data
@Validated
@ConfigurationProperties(prefix = "govsso.alerts")
public class AlertsConfigurationProperties {

    @Min(value = 1000)
    private int refreshAlertsIntervalInMilliseconds = 10000;
    private StaticAlert staticAlert;

    @Data
    public static class StaticAlert {
        private List<MessageTemplate> messageTemplates = new ArrayList<>();
    }
}
