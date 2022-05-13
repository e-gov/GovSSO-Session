package ee.ria.govsso.session.configuration;

import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
import ee.ria.govsso.session.logging.ClientRequestLogger;
import ee.ria.govsso.session.service.hydra.HydraService;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
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
class HydraConfiguration {

    @Bean
    ClientRequestLogger hydraRequestLogger() {
        return new ClientRequestLogger(HydraService.class, "Hydra");
    }

    @Bean
    WebClient hydraWebClient(ClientRequestLogger requestLogger, KeyStore hydraTrustStore) {
        SslContext sslContext = initSslContext(hydraTrustStore);
        HttpClient httpClient = HttpClient.create()
                .secure(sslProviderBuilder -> sslProviderBuilder.sslContext(sslContext));
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .filter(responseFilter(requestLogger))
                .build();
    }

    @Bean
    @SneakyThrows
    KeyStore hydraTrustStore(HydraConfigurationProperties.TlsConfigurationProperties tlsProperties) {
        InputStream trustStoreFile = tlsProperties.trustStoreLocation().getInputStream();
        KeyStore trustStore = KeyStore.getInstance(tlsProperties.trustStoreType());
        trustStore.load(trustStoreFile, tlsProperties.trustStorePassword().toCharArray());
        return trustStore;
    }

    @SneakyThrows
    private SslContext initSslContext(KeyStore hydraTrustStore) {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(hydraTrustStore);
        return SslContextBuilder.forClient().trustManager(trustManagerFactory).build();
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
