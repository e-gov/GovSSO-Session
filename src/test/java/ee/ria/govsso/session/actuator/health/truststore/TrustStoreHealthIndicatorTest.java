package ee.ria.govsso.session.actuator.health.truststore;

import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Status;

import java.util.ArrayList;
import java.util.List;

import static ee.ria.govsso.session.actuator.health.truststore.CertificateInfoTestUtil.activeCertInfoBuilder;
import static ee.ria.govsso.session.actuator.health.truststore.CertificateInfoTestUtil.expiredCertInfoBuilder;
import static ee.ria.govsso.session.actuator.health.truststore.CertificateInfoTestUtil.inactiveCertInfoBuilder;
import static org.junit.jupiter.api.Assertions.assertEquals;

class TrustStoreHealthIndicatorTest {

    @Test
    void health_allActiveCertificates_statusUP() {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        certificateInfos.add(activeCertInfoBuilder().build());
        certificateInfos.add(activeCertInfoBuilder().build());

        CertificateInfoCache certificateInfoCache = new CertificateInfoCache(certificateInfos);
        TrustStoreHealthIndicator healthIndicator = new TrustStoreHealthIndicator(certificateInfoCache);

        assertEquals(Status.UP, healthIndicator.health().getStatus());
    }

    @Test
    void health_noActiveCertificates_statusDOWN() {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        certificateInfos.add(expiredCertInfoBuilder().build());
        certificateInfos.add(inactiveCertInfoBuilder().build());

        CertificateInfoCache certificateInfoCache = new CertificateInfoCache(certificateInfos);
        TrustStoreHealthIndicator healthIndicator = new TrustStoreHealthIndicator(certificateInfoCache);

        assertEquals(Status.DOWN, healthIndicator.health().getStatus());
    }

    @Test
    void health_activeAndExpiredCertificates_statusUNKOWN() {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        certificateInfos.add(activeCertInfoBuilder().build());
        certificateInfos.add(expiredCertInfoBuilder().build());

        CertificateInfoCache certificateInfoCache = new CertificateInfoCache(certificateInfos);
        TrustStoreHealthIndicator healthIndicator = new TrustStoreHealthIndicator(certificateInfoCache);

        assertEquals(Status.UNKNOWN, healthIndicator.health().getStatus());
    }

    @Test
    void health_activeAndInactiveCertificates_statusUNKOWN() {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        certificateInfos.add(activeCertInfoBuilder().build());
        certificateInfos.add(inactiveCertInfoBuilder().build());

        CertificateInfoCache certificateInfoCache = new CertificateInfoCache(certificateInfos);
        TrustStoreHealthIndicator healthIndicator = new TrustStoreHealthIndicator(certificateInfoCache);

        assertEquals(Status.UNKNOWN, healthIndicator.health().getStatus());
    }
}
