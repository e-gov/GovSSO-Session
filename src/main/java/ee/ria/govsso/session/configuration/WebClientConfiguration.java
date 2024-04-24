package ee.ria.govsso.session.configuration;

import ee.ria.govsso.session.configuration.properties.AdminConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.PaasukeConfigurationProperties;
import ee.ria.govsso.session.logging.ClientRequestLogger;
import ee.ria.govsso.session.service.hydra.HydraService;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.security.KeyStore;

import static ee.ria.govsso.session.logging.ClientRequestLogger.Service.HYDRA;

@Configuration
@RequiredArgsConstructor
class WebClientConfiguration {

    @Bean
    ClientRequestLogger hydraRequestLogger() {
        return new ClientRequestLogger(HydraService.class, HYDRA);
    }

    @Bean
    public WebClient adminWebClient(
            KeyStore adminTrustStore) {
        SslContext sslContext = initSslContext(adminTrustStore);
        HttpClient httpClient = HttpClient.create()
                .secure(sslProviderBuilder -> sslProviderBuilder.sslContext(sslContext));
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }

    @Bean
    WebClient hydraWebClient(
            @Qualifier("hydraRequestLogger") ClientRequestLogger requestLogger,
            KeyStore hydraTrustStore) {
        SslContext sslContext = initSslContext(hydraTrustStore);
        HttpClient httpClient = HttpClient.create()
                .secure(sslProviderBuilder -> sslProviderBuilder.sslContext(sslContext));
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                // TODO (AUT-1392): Remove filter
                .filter(responseFilter(requestLogger))
                .build();
    }

    @Bean
    WebClient paasukeWebClient(
            KeyStore paasukeTrustStore,
            KeyStore paasukeKeyStore,
            PaasukeConfigurationProperties paasukeConfigurationProperties) {
        SslContext sslContext = initSslContext(
                paasukeTrustStore,
                paasukeKeyStore,
                paasukeConfigurationProperties.tls().keyStorePassword());
        HttpClient httpClient = HttpClient.create()
                .secure(sslProviderBuilder -> sslProviderBuilder.sslContext(sslContext));
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }

    @Bean
    @SneakyThrows
    KeyStore hydraTrustStore(HydraConfigurationProperties hydraProperties) {
        HydraConfigurationProperties.Tls tlsProperties = hydraProperties.tls();
        InputStream trustStoreFile = tlsProperties.trustStoreLocation().getInputStream();
        KeyStore trustStore = KeyStore.getInstance(tlsProperties.trustStoreType());
        trustStore.load(trustStoreFile, tlsProperties.trustStorePassword().toCharArray());
        return trustStore;
    }

    @Bean
    @SneakyThrows
    KeyStore adminTrustStore(AdminConfigurationProperties adminProperties) {
        AdminConfigurationProperties.Tls tlsProperties = adminProperties.tls();
        InputStream trustStoreFile = tlsProperties.trustStoreLocation().getInputStream();
        KeyStore trustStore = KeyStore.getInstance(tlsProperties.trustStoreType());
        trustStore.load(trustStoreFile, tlsProperties.trustStorePassword().toCharArray());
        return trustStore;
    }

    @Bean
    @SneakyThrows
    KeyStore paasukeTrustStore(PaasukeConfigurationProperties paasukeProperties) {
        PaasukeConfigurationProperties.Tls tlsProperties = paasukeProperties.tls();
        InputStream trustStoreFile = tlsProperties.trustStoreLocation().getInputStream();
        KeyStore trustStore = KeyStore.getInstance(tlsProperties.trustStoreType());
        trustStore.load(trustStoreFile, tlsProperties.trustStorePassword().toCharArray());
        return trustStore;
    }

    @Bean
    @SneakyThrows
    KeyStore paasukeKeyStore(PaasukeConfigurationProperties paasukeProperties) {
        PaasukeConfigurationProperties.Tls tlsProperties = paasukeProperties.tls();
        InputStream keyStoreFile = tlsProperties.keyStoreLocation().getInputStream();
        KeyStore keyStore = KeyStore.getInstance(tlsProperties.keyStoreType());
        keyStore.load(keyStoreFile, tlsProperties.keyStorePassword().toCharArray());
        return keyStore;
    }

    @SneakyThrows
    private SslContext initSslContext(KeyStore trustStore) {
        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        return SslContextBuilder.forClient().trustManager(trustManagerFactory).build();
    }

    @SneakyThrows
    private SslContext initSslContext(KeyStore trustStore, KeyStore keyStore, String keyStorePassword) {
        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
        return SslContextBuilder.forClient()
                .trustManager(trustManagerFactory)
                .keyManager(keyManagerFactory)
                .build();
    }

    @Deprecated
    /* In order to keep all the logging in the same place, log 4xx and 5xx responses manually or implement a filter
     * that logs all requests or responses instead. See AUT-1392. */
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
