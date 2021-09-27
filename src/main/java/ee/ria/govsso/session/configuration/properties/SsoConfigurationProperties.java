package ee.ria.govsso.session.configuration.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotNull;
import java.net.URL;

@Data
@Validated
@ConfigurationProperties(prefix = "govsso")
public class SsoConfigurationProperties {

    @NotNull
    private URL baseUrl;

}
