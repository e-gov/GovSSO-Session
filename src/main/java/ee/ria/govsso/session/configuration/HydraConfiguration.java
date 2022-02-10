package ee.ria.govsso.session.configuration;

import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
import ee.ria.govsso.session.logging.ClientRequestLogger;
import ee.ria.govsso.session.service.hydra.HydraService;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.security.KeyStore;

@Configuration
@RequiredArgsConstructor
public class HydraConfiguration {

    @Bean
    public ClientRequestLogger hydraRequestLogger() {
        return new ClientRequestLogger(HydraService.class, "Hydra");
    }

    @Bean
    public WebClient hydraWebClient(HydraConfigurationProperties configurationProperties, ClientRequestLogger requestLogger) {
        SslContext sslContext = initSslContext(configurationProperties.tls());

        HttpClient httpClient = HttpClient.create()
                .secure(sslProviderBuilder -> sslProviderBuilder.sslContext(sslContext));
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .filter(responseFilter(requestLogger))
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

    private ExchangeFilterFunction responseFilter(ClientRequestLogger requestLogger) {
        return ExchangeFilterFunction.ofResponseProcessor(clientResponse -> {
            if (clientResponse.statusCode().isError()) {
                return clientResponse.bodyToMono(String.class)
                        .defaultIfEmpty("")
                        .flatMap(responseBody -> {
                            try {
                                requestLogger.logResponse(clientResponse.rawStatusCode(), responseBody);
                                return Mono.just(clientResponse);
                            } catch (Exception ex) {
                                return Mono.error(new IllegalStateException("Failed to log response", ex));
                            }
                        });
            } else {
                return Mono.just(clientResponse);
            }
        });
    }
}
