package ee.ria.govsso.session.configuration.properties;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;

@Slf4j
@Data
@Validated
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

    @NotBlank
    private String contentSecurityPolicy = DEFAULT_CONTENT_SECURITY_POLICY;
}
