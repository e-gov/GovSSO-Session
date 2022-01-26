package ee.ria.govsso.session.configuration;

import ee.ria.govsso.session.session.SsoCookieArgumentResolver;
import ee.ria.govsso.session.session.SsoCookieSigner;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.retry.annotation.EnableRetry;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

@Slf4j
@EnableRetry
@EnableScheduling
@ConfigurationPropertiesScan
@Configuration
@RequiredArgsConstructor
public class SsoConfiguration implements WebMvcConfigurer {
    private final ConfigurableBeanFactory configurableBeanFactory;
    private final SsoCookieSigner ssoCookieSigner;

    @Bean
    public SSLContext trustContext() throws NoSuchAlgorithmException, KeyManagementException {
        // TODO Configure proper trust store.
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, InsecureTrustManagerFactory.INSTANCE.getTrustManagers(), null);
        return sslContext;
    }

    @Bean
    public WebClient createWebClient() throws SSLException {
        // TODO Configure proper trust store.
        SslContext sslContext = SslContextBuilder
                .forClient()
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();
        HttpClient httpClient = HttpClient.create().secure(t -> t.sslContext(sslContext));
        ClientHttpConnector httpConnector = new ReactorClientHttpConnector(httpClient);
        return WebClient.builder().clientConnector(httpConnector).build();
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add(new SsoCookieArgumentResolver(configurableBeanFactory, ssoCookieSigner));
    }
}
