package ee.ria.govsso.session.configuration.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.net.URL;

@Validated
@ConfigurationProperties(prefix = "govsso.hydra")
public record HydraConfigurationProperties(
        @NotNull
        URL adminUrl,
        HydraTlsConfigurationProperties tls) {

    @Validated
    @ConfigurationProperties(prefix = "govsso.hydra.tls")
    public record HydraTlsConfigurationProperties(
            @NotNull
            Resource trustStoreLocation,
            @NotBlank
            String trustStorePassword,
            @DefaultValue("PKCS12")
            @NotBlank
            String trustStoreType) {
    }
}
