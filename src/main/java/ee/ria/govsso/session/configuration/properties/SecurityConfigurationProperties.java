package ee.ria.govsso.session.configuration.properties;

import ee.ria.govsso.session.logging.LogbackFieldValueMasker;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.Set;

@Slf4j
@Value
@Validated
@ConfigurationProperties(prefix = "govsso.security")
public class SecurityConfigurationProperties {
    public static final String DEFAULT_CONTENT_SECURITY_POLICY = "connect-src 'self'; " +
            "default-src 'none'; " +
            "font-src 'self'; " +
            "img-src 'self' data:; " +
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
    int cookieMaxAgeSeconds;

    Set<String> maskedFieldNames;

    public SecurityConfigurationProperties(
            @DefaultValue(DEFAULT_CONTENT_SECURITY_POLICY) String contentSecurityPolicy, String cookieSigningSecret,
            @DefaultValue("3600") int cookieMaxAgeSeconds, Set<String> maskedFieldNames) {
        this.contentSecurityPolicy = contentSecurityPolicy;
        this.cookieSigningSecret = cookieSigningSecret;
        this.cookieMaxAgeSeconds = cookieMaxAgeSeconds;

        this.maskedFieldNames = maskedFieldNames;
        if (maskedFieldNames != null && !maskedFieldNames.isEmpty()) {
            LogbackFieldValueMasker.MASKED_FIELD_NAMES = maskedFieldNames;
        }
    }
}
