package ee.ria.govsso.session.configuration.properties;

import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Slf4j
@Value
@Validated
@ConstructorBinding
@ConfigurationProperties(prefix = "govsso.security")
public class SecurityConfigurationProperties {
    public static final String DEFAULT_CONTENT_SECURITY_POLICY = "connect-src 'self'; " +
            "default-src 'none'; " +
            "font-src 'self'; " +
            "img-src 'self'; " +
            "script-src 'self'; " +
            "style-src 'self'; " +
            "base-uri 'none'; " +
            "frame-ancestors 'none'; " +
            "block-all-mixed-content";

    @Size(min = 32)
    String cookieSigningSecret;

    @NotBlank
    String contentSecurityPolicy;

    @Min(value = -1)
    long cookieMaxAgeSeconds;

    public SecurityConfigurationProperties(
            @DefaultValue(DEFAULT_CONTENT_SECURITY_POLICY) String contentSecurityPolicy, String cookieSigningSecret,
            @DefaultValue("3600") long cookieMaxAgeSeconds) {
        this.contentSecurityPolicy = contentSecurityPolicy;
        this.cookieSigningSecret = cookieSigningSecret;
        this.cookieMaxAgeSeconds = cookieMaxAgeSeconds;
    }
}
