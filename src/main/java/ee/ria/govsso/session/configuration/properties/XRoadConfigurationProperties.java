package ee.ria.govsso.session.configuration.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;

@Validated
@ConfigurationProperties(prefix = "govsso.xroad")
public record XRoadConfigurationProperties(
        @NotBlank
        String clientId
) {}
