package ee.ria.govsso.session.actuator.health.truststore;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.actuate.health.Status;

import java.util.List;
import java.util.Map;

record TrustStoreHealthIndicator(
        CertificateInfoCache certificateInfoCache) implements HealthIndicator {

    @Override
    public Health health() {
        List<CertificateInfo> certificateInfos = certificateInfoCache.certificateInfos();

        return new Health.Builder()
                .withDetails(Map.of("certificates", certificateInfos))
                .status(determineHealthStatus(certificateInfos))
                .build();
    }

    private Status determineHealthStatus(List<CertificateInfo> certificateInfos) {
        if (!isAnyCertificateActive(certificateInfos)) {
            return Status.DOWN;
        }

        return areAllCertificatesActive(certificateInfos) ? Status.UP : Status.UNKNOWN;
    }

    private boolean isAnyCertificateActive(List<CertificateInfo> certificateInfos) {
        return certificateInfos.stream()
                .anyMatch(certInfo -> certInfo.getState() == CertificateState.ACTIVE);
    }

    private boolean areAllCertificatesActive(List<CertificateInfo> certificateInfos) {
        return certificateInfos.stream()
                .allMatch(certInfo -> certInfo.getState() == CertificateState.ACTIVE);
    }
}
