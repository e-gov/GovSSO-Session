package ee.ria.govsso.session.configuration.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;

@Data
@Validated
@ConfigurationProperties(prefix = "govsso.tara")
public class TaraConfigurationProperties {

    @NotBlank
    private String authUrl;

}
