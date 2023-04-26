package ee.ria.govsso.session.configuration.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.PositiveOrZero;
import java.net.URL;

@Validated
@ConstructorBinding
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
        Integer maxClockSkewSeconds,
        TlsConfigurationProperties tls) {

    @Validated
    @ConstructorBinding
    @ConfigurationProperties(prefix = "govsso.tara.tls")
    public record TlsConfigurationProperties(
            @NotNull
            Resource trustStoreLocation,
            @NotBlank
            String trustStorePassword,
            @DefaultValue("PKCS12")
            @NotNull
            String trustStoreType,
            String defaultProtocol) {
    }
}
