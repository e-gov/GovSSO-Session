package ee.ria.govsso.session.configuration.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.net.URL;
import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "govsso.paasuke")
public record PaasukeConfigurationProperties(
        @NotNull
        URL hostUrl,
        @DefaultValue("10s")
        Duration requestTimeout,
        Tls tls) {

    @Validated
    public record Tls(
            @NotNull
            Resource trustStoreLocation,
            @NotBlank
            String trustStorePassword,
            @DefaultValue("PKCS12")
            @NotBlank
            String trustStoreType,
            @NotNull
            Resource keyStoreLocation,
            @NotBlank
            String keyStorePassword,
            @DefaultValue("PKCS12")
            @NotBlank
            String keyStoreType
  ) {}

}
