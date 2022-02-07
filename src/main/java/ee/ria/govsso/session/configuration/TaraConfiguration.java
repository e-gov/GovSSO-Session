package ee.ria.govsso.session.configuration;

import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Configuration
public class TaraConfiguration {

    @Bean("taraTrustContext")
    public SSLContext trustContext(TaraConfigurationProperties configurationProperties) throws NoSuchAlgorithmException, KeyManagementException, IOException, CertificateException, KeyStoreException {
        TaraConfigurationProperties.TlsConfigurationProperties tlsProperties = configurationProperties.tls();

        SSLContextBuilder sslContextBuilder = SSLContextBuilder.create()
                .setKeyStoreType(tlsProperties.trustStoreType())
                .loadTrustMaterial(
                        tlsProperties.trustStoreLocation().getFile(),
                        tlsProperties.trustStorePassword().toCharArray());
        if (StringUtils.isNotBlank(tlsProperties.defaultProtocol())) {
            sslContextBuilder.setProtocol(tlsProperties.defaultProtocol());
        }
        return sslContextBuilder.build();
    }
}
