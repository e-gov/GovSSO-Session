package ee.ria.govsso.session.configuration.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PositiveOrZero;
import java.net.URL;

@Validated
@ConfigurationProperties(prefix = "govsso.tara")
public record TaraConfigurationProperties(
        @NotNull
        URL issuerUrl,
        @NotBlank
        String clientId,
        @NotBlank
        String clientSecret,
        @DefaultValue("5000")
        @PositiveOrZero
        Integer connectTimeoutMilliseconds,
        @DefaultValue("5000")
        @PositiveOrZero
        Integer readTimeoutMilliseconds,
        @DefaultValue("10")
        @PositiveOrZero
        Integer maxClockSkewSeconds,
        TlsConfigurationProperties tls) {

    @Validated
    @ConfigurationProperties(prefix = "govsso.tara.tls")
    public record TlsConfigurationProperties(
            @NotNull
            Resource trustStoreLocation,
            @NotBlank
            String trustStorePassword,
            @DefaultValue("PKCS12")
            @NotBlank
            String trustStoreType,
            String defaultProtocol) {
    }
}
