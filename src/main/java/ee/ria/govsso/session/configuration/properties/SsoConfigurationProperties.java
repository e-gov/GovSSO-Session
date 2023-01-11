package ee.ria.govsso.session.configuration.properties;

import lombok.SneakyThrows;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.util.Assert;
import org.springframework.validation.annotation.Validated;

import javax.annotation.PostConstruct;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import java.net.URI;
import java.net.URL;

@Validated
@ConstructorBinding
@ConfigurationProperties(prefix = "govsso")
public record SsoConfigurationProperties(
        @NotNull
        URL baseUrl,
        @Min(1)
        int sessionMaxUpdateIntervalMinutes,
        @Min(1)
        int consentRequestRememberForMinutes,
        @Min(1)
        int sessionMaxDurationHours) {
    @PostConstruct
    public void validateConfiguration() {
        Assert.isTrue(sessionMaxUpdateIntervalMinutes >= 1 && sessionMaxUpdateIntervalMinutes <= (sessionMaxDurationHours * 60),
                "Max update interval must be at least 1 minute and must be less than max session duration.");
        Assert.isTrue(consentRequestRememberForMinutes >= sessionMaxUpdateIntervalMinutes && consentRequestRememberForMinutes <= (sessionMaxDurationHours * 60),
                "Consent request remember for interval must be greater or equal to session max update interval and must be less than max session duration.");
    }

    public int getSessionMaxUpdateIntervalInSeconds() {
        return sessionMaxUpdateIntervalMinutes * 60;
    }

    public int getConsentRequestRememberForInSeconds() {
        return consentRequestRememberForMinutes * 60;
    }

    @SneakyThrows
    public URI getCallbackUri() {
        return new URL(baseUrl, "login/taracallback").toURI();
    }

}
