package ee.ria.govsso.session.configuration;

import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.SSLContext;

@Configuration
public class TaraConfiguration {

    @Bean
    public SSLContext taraTrustContext(TaraConfigurationProperties configurationProperties) {
        TaraConfigurationProperties.TlsConfigurationProperties tlsProperties = configurationProperties.tls();

        try {
            SSLContextBuilder sslContextBuilder = SSLContextBuilder.create()
                    .setKeyStoreType(tlsProperties.trustStoreType())
                    .loadTrustMaterial(
                            tlsProperties.trustStoreLocation().getFile(),
                            tlsProperties.trustStorePassword().toCharArray());
            if (StringUtils.isNotBlank(tlsProperties.defaultProtocol())) {
                sslContextBuilder.setProtocol(tlsProperties.defaultProtocol());
            }
            return sslContextBuilder.build();
        } catch (Exception ex) {
            throw new IllegalStateException("TARA SSLContext initialization failed", ex);
        }
    }
}
