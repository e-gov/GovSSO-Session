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
@ConfigurationProperties(prefix = "govsso.admin")
public record AdminConfigurationProperties(
        @NotNull
        URL hostUrl,
        AdminTlsConfigurationProperties tls) {

    @Validated
    @ConstructorBinding
    @ConfigurationProperties(prefix = "govsso.admin.tls")
    public record AdminTlsConfigurationProperties(
            @NotNull
            Resource trustStoreLocation,
            @NotBlank
            String trustStorePassword,
            @DefaultValue("PKCS12")
            @NotBlank
            String trustStoreType) {
    }
}
