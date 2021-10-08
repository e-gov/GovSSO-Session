package ee.ria.govsso.session.configuration.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.net.URL;

@Data
@Validated
@ConfigurationProperties(prefix = "govsso.tara")
public class TaraConfigurationProperties {

    @NotNull
    private URL authUrl;

    @NotNull
    private URL tokenUrl;

    @NotBlank
    private String clientId;

    @NotBlank
    private String clientSecret;

}