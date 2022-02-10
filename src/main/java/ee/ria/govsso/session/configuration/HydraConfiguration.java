package ee.ria.govsso.session.configuration;

import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.security.KeyStore;

@Configuration
public class HydraConfiguration {

    @Bean
    public WebClient hydraWebClient(HydraConfigurationProperties configurationProperties) {
        SslContext sslContext = initSslContext(configurationProperties.tls());

        HttpClient httpClient = HttpClient.create()
                .secure(sslProviderBuilder -> sslProviderBuilder.sslContext(sslContext));
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }

    private SslContext initSslContext(HydraConfigurationProperties.TlsConfigurationProperties tlsProperties) {
        try (InputStream trustStoreFile = tlsProperties.trustStoreLocation().getInputStream()) {
            KeyStore trustStore = KeyStore.getInstance(tlsProperties.trustStoreType());
            trustStore.load(trustStoreFile, tlsProperties.trustStorePassword().toCharArray());

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            return SslContextBuilder.forClient().trustManager(trustManagerFactory).build();
        } catch (Exception ex) {
            throw new IllegalStateException("Hydra WebClient SslContext initialization failed", ex);
        }
    }
}
