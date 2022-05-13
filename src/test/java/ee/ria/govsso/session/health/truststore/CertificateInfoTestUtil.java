package ee.ria.govsso.session.health.truststore;

import java.time.Duration;
import java.time.Instant;
import java.time.Period;

class CertificateInfoTestUtil {

    static CertificateInfo.CertificateInfoBuilder activeCertInfoBuilder() {
        return CertificateInfo.builder()
                .alias("test-alias")
                .validFrom(Instant.now().minus(Duration.ofMinutes(1)))
                .validTo(Instant.now().plus(Period.ofDays(35)))
                .subjectDN("test-subject-dn")
                .serialNumber("test-serial-number");
    }

    static CertificateInfo.CertificateInfoBuilder expiredCertInfoBuilder() {
        return CertificateInfo.builder()
                .alias("test-alias")
                .validFrom(Instant.now().minus(Period.ofDays(35)))
                .validTo(Instant.now().minus(Duration.ofMinutes(1)))
                .subjectDN("test-subject-dn")
                .serialNumber("test-serial-number");
    }

    static CertificateInfo.CertificateInfoBuilder inactiveCertInfoBuilder() {
        return CertificateInfo.builder()
                .alias("test-alias")
                .validFrom(Instant.now().plus(Duration.ofMinutes(1)))
                .validTo(Instant.now().plus(Period.ofDays(35)))
                .subjectDN("test-subject-dn")
                .serialNumber("test-serial-number");
    }
}
