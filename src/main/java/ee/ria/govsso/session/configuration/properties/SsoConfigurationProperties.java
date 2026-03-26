package ee.ria.govsso.session.configuration.properties;

import lombok.AccessLevel;
import lombok.Data;
import lombok.Getter;
import lombok.SneakyThrows;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.net.URI;
import java.net.URL;
import java.time.Duration;

@Data
@Validated
@ConfigurationProperties(prefix = "govsso")
public class SsoConfigurationProperties {

    @NotNull
    URL baseUrl;
    @Min(1)
    @Getter(AccessLevel.NONE)
    int sessionMaxUpdateIntervalMinutes;
    @Min(1)
    @Getter(AccessLevel.NONE)
    int sessionMaxDurationHours;

    String selfServiceUrl;

    @PostConstruct
    public void validateConfiguration() {
        Assert.isTrue(sessionMaxUpdateIntervalMinutes >= 1 && sessionMaxUpdateIntervalMinutes <= (sessionMaxDurationHours * 60),
                "Max update interval must be at least 1 minute and must be less than max duration.");
    }

    public Duration getSessionMaxUpdateInterval() {
        return Duration.ofMinutes(sessionMaxUpdateIntervalMinutes);
    }

    public Duration getSessionMaxDuration() {
        return Duration.ofHours(sessionMaxDurationHours);
    }

    @SneakyThrows
    public URI getCallbackUri() {
        return new URL(baseUrl, "login/taracallback").toURI();
    }

}
