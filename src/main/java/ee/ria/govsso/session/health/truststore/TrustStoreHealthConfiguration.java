package ee.ria.govsso.session.health.truststore;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.health.CompositeHealthContributor;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyStore;
import java.util.Map;

@Configuration
@RequiredArgsConstructor
class TrustStoreHealthConfiguration {

    @Bean
    CompositeHealthContributor truststoreHealthContributor(KeyStore hydraTrustStore, KeyStore taraTrustStore) {
        return CompositeHealthContributor.fromMap(Map.<String, HealthIndicator>of(
                "TARA", trustStoreHealthIndicator(taraTrustStore),
                "Hydra", trustStoreHealthIndicator(hydraTrustStore)
        ));
    }

    private TrustStoreHealthIndicator trustStoreHealthIndicator(KeyStore trustStore) {
        return new TrustStoreHealthIndicator(
                new CertificateInfoCache(CertificateInfoLoader.loadCertificateInfos(trustStore))
        );
    }
}
