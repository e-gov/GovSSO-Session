package ee.ria.govsso.session.configuration.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.net.URL;
import java.time.Duration;

@Validated
@ConstructorBinding
@ConfigurationProperties(prefix = "govsso.paasuke")
public record PaasukeConfigurationProperties(
        @NotNull
        URL hostUrl,
        @DefaultValue("10s")
        Duration requestTimeout,
        Tls tls) {

    @Validated
    @ConstructorBinding
    public record Tls(
            @NotNull
            Resource trustStoreLocation,
            @NotBlank
            String trustStorePassword,
            @DefaultValue("PKCS12")
            @NotBlank
            String trustStoreType) {
    }

}
