package ee.ria.govsso.session.configuration;

import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import lombok.SneakyThrows;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.SSLContext;
import java.io.InputStream;
import java.security.KeyStore;

@Configuration
class TaraConfiguration {

    @Bean
    @SneakyThrows
    SSLContext taraTrustContext(
            TaraConfigurationProperties taraProperties,
            KeyStore taraTrustStore
    ) {
        return SSLContextBuilder.create()
                .setKeyStoreType(taraTrustStore.getType())
                .loadTrustMaterial(taraTrustStore, null)
                .setProtocol(taraProperties.tls().defaultProtocol())
                .build();
    }

    @Bean
    @SneakyThrows
    KeyStore taraTrustStore(TaraConfigurationProperties taraProperties) {
        TaraConfigurationProperties.Tls tlsProperties = taraProperties.tls();
        InputStream trustStoreFile = tlsProperties.trustStoreLocation().getInputStream();
        KeyStore trustStore = KeyStore.getInstance(tlsProperties.trustStoreType());
        trustStore.load(trustStoreFile, tlsProperties.trustStorePassword().toCharArray());
        return trustStore;
    }
}
