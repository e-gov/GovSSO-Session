package ee.ria.govsso.session.configuration.properties;

import lombok.SneakyThrows;
import lombok.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import java.net.URI;
import java.net.URL;

@Value
@Validated
@ConstructorBinding
@ConfigurationProperties(prefix = "govsso")
public class SsoConfigurationProperties {

    @NotNull
    URL baseUrl;

    @SneakyThrows
    public URI getCallbackUri() {
        return new URL(baseUrl, "auth/taracallback").toURI();
    }

}
