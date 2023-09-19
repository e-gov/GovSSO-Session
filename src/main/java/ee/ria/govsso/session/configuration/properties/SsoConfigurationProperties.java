package ee.ria.govsso.session.configuration.properties;

import lombok.Data;
import lombok.SneakyThrows;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

import javax.annotation.PostConstruct;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import java.net.URI;
import java.net.URL;

@Data
@Validated
@ConstructorBinding
@ConfigurationProperties(prefix = "govsso")
public class SsoConfigurationProperties {

    @NotNull
    URL baseUrl;
    @Min(1)
    int sessionMaxUpdateIntervalMinutes;
    @Min(1)
    int sessionMaxDurationHours;

    String selfServiceUrl;

    @PostConstruct
    public void validateConfiguration() {
        Assert.isTrue(sessionMaxUpdateIntervalMinutes >= 1 && sessionMaxUpdateIntervalMinutes <= (sessionMaxDurationHours * 60),
                "Max update interval must be at least 1 minute and must be less than max duration.");
    }

    public int getSessionMaxUpdateIntervalInSeconds() {
        return sessionMaxUpdateIntervalMinutes * 60;
    }

    @SneakyThrows
    public URI getCallbackUri() {
        return new URL(baseUrl, "login/taracallback").toURI();
    }

}
