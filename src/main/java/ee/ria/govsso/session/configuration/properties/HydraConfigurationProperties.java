package ee.ria.govsso.session.configuration.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.net.URL;

@Validated
@ConstructorBinding
@ConfigurationProperties(prefix = "govsso.hydra")
public record HydraConfigurationProperties(
        @NotNull
        URL adminUrl,
        TlsConfigurationProperties tls) {

    @Validated
    @ConstructorBinding
    @ConfigurationProperties(prefix = "govsso.hydra.tls")
    public record TlsConfigurationProperties(
            @NotNull
            Resource trustStoreLocation,
            @NotBlank
            String trustStorePassword,
            @DefaultValue("PKCS12")
            @NotNull
            String trustStoreType) {
    }
}
