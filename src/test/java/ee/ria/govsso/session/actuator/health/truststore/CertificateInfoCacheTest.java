package ee.ria.govsso.session.actuator.health.truststore;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.Period;
import java.util.ArrayList;
import java.util.List;

import static ee.ria.govsso.session.actuator.health.truststore.CertificateInfoTestUtil.activeCertInfoBuilder;
import static ee.ria.govsso.session.actuator.health.truststore.CertificateInfoTestUtil.expiredCertInfoBuilder;
import static ee.ria.govsso.session.actuator.health.truststore.CertificateInfoTestUtil.inactiveCertInfoBuilder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class CertificateInfoCacheTest {

    @Test
    void certificateInfos_allCertificatesActive() {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        certificateInfos.add(activeCertInfoBuilder().build());
        certificateInfos.add(activeCertInfoBuilder().build());

        CertificateInfoCache certificateInfoCache = new CertificateInfoCache(certificateInfos);

        List<CertificateInfo> certificateInfosFromCache = certificateInfoCache.certificateInfos();
        assertEquals(2, certificateInfosFromCache.size());
        assertCertActiveWithNoWarning(certificateInfosFromCache.get(0));
        assertCertActiveWithNoWarning(certificateInfosFromCache.get(1));
    }

    @Test
    void certificateInfos_certificateValidFromFuture_certificateStateInactive() {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        certificateInfos.add(inactiveCertInfoBuilder().build());
        certificateInfos.add(activeCertInfoBuilder().build());

        CertificateInfoCache certificateInfoCache = new CertificateInfoCache(certificateInfos);

        List<CertificateInfo> certificateInfosFromCache = certificateInfoCache.certificateInfos();
        assertEquals(2, certificateInfosFromCache.size());
        assertCertInactiveWithNoWarning(certificateInfosFromCache.get(0));
        assertCertActiveWithNoWarning(certificateInfosFromCache.get(1));
    }

    @Test
    void certificateInfos_certificateValidToPast_certificateStateExpired() {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        certificateInfos.add(expiredCertInfoBuilder().build());
        certificateInfos.add(activeCertInfoBuilder().build());

        CertificateInfoCache certificateInfoCache = new CertificateInfoCache(certificateInfos);

        List<CertificateInfo> certificateInfosFromCache = certificateInfoCache.certificateInfos();
        assertEquals(2, certificateInfosFromCache.size());
        assertCertExpiredWithNoWarning(certificateInfosFromCache.get(0));
        assertCertActiveWithNoWarning(certificateInfosFromCache.get(1));
    }

    @Test
    void certificateInfos_certificateExpiresToday_certificateStateActiveWithWarning() {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        certificateInfos.add(activeCertInfoBuilder().validTo(Instant.now().plus(Duration.ofMinutes(1))).build());
        certificateInfos.add(activeCertInfoBuilder().build());

        CertificateInfoCache certificateInfoCache = new CertificateInfoCache(certificateInfos);

        List<CertificateInfo> certificateInfosFromCache = certificateInfoCache.certificateInfos();
        assertEquals(2, certificateInfosFromCache.size());
        assertCertActiveWithWarning(certificateInfosFromCache.get(0), "Certificate expires in 0 days");
        assertCertActiveWithNoWarning(certificateInfosFromCache.get(1));
    }

    @Test
    void certificateInfos_certificateExpiresIn29Days_certificateStateActiveWithWarning() {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        certificateInfos.add(activeCertInfoBuilder().validTo(
                        Instant.now()
                                .plus(Period.ofDays(29))
                                .plus(Duration.ofMinutes(1)))
                .build());
        certificateInfos.add(activeCertInfoBuilder().build());

        CertificateInfoCache certificateInfoCache = new CertificateInfoCache(certificateInfos);

        List<CertificateInfo> certificateInfosFromCache = certificateInfoCache.certificateInfos();
        assertEquals(2, certificateInfosFromCache.size());
        assertCertActiveWithWarning(certificateInfosFromCache.get(0), "Certificate expires in 29 days");
        assertCertActiveWithNoWarning(certificateInfosFromCache.get(1));
    }

    @Test
    void certificateInfos_certificateExpiresIn30Days_certificateStateActiveWithWarning() {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        certificateInfos.add(activeCertInfoBuilder().validTo(
                        Instant.now()
                                .plus(Period.ofDays(30))
                                .plus(Duration.ofMinutes(1)))
                .build());
        certificateInfos.add(activeCertInfoBuilder().build());

        CertificateInfoCache certificateInfoCache = new CertificateInfoCache(certificateInfos);

        List<CertificateInfo> certificateInfosFromCache = certificateInfoCache.certificateInfos();
        assertEquals(2, certificateInfosFromCache.size());
        assertCertActiveWithNoWarning(certificateInfosFromCache.get(0));
        assertCertActiveWithNoWarning(certificateInfosFromCache.get(1));
    }

    private void assertCertActiveWithNoWarning(CertificateInfo certificateInfo) {
        assertEquals(CertificateState.ACTIVE, certificateInfo.getState());
        assertNull(certificateInfo.getWarning());
    }

    private void assertCertActiveWithWarning(CertificateInfo certificateInfo, String warningMessage) {
        assertEquals(CertificateState.ACTIVE, certificateInfo.getState());
        assertEquals(warningMessage, certificateInfo.getWarning());
    }

    private void assertCertInactiveWithNoWarning(CertificateInfo certificateInfo) {
        assertEquals(CertificateState.INACTIVE, certificateInfo.getState());
        assertNull(certificateInfo.getWarning());
    }

    private void assertCertExpiredWithNoWarning(CertificateInfo certificateInfo) {
        assertEquals(CertificateState.EXPIRED, certificateInfo.getState());
        assertNull(certificateInfo.getWarning());
    }
}
