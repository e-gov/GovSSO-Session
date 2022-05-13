package ee.ria.govsso.session.health.truststore;

import java.time.Instant;
import java.time.Period;
import java.time.temporal.ChronoUnit;
import java.util.List;

record CertificateInfoCache(List<CertificateInfo> certificateInfos) {

    private static final int DAYS_BEFORE_WARN_ABOUT_CERT_EXPIRATION = 30;
    private static final String CERTIFICATE_EXPIRATION_WARNING = "Certificate expires in %s days";

    public List<CertificateInfo> certificateInfos() {
        Instant now = Instant.now();
        updateCertificateInfosStates(now);
        updateCertificateInfosExpirationWarnings(now);
        return certificateInfos;
    }

    private void updateCertificateInfosStates(Instant now) {
        certificateInfos.forEach(certInfo -> certInfo.setState(determineCertificateState(certInfo, now)));
    }

    private static CertificateState determineCertificateState(CertificateInfo certificateInfo, Instant now) {
        if (certificateInfo.getValidFrom().isAfter(now)) {
            return CertificateState.INACTIVE;
        }
        if (now.isAfter(certificateInfo.getValidTo())) {
            return CertificateState.EXPIRED;
        }
        return CertificateState.ACTIVE;
    }

    private void updateCertificateInfosExpirationWarnings(Instant now) {
        Instant expirationWarningTargetDate = now.plus(Period.ofDays(DAYS_BEFORE_WARN_ABOUT_CERT_EXPIRATION));
        certificateInfos.stream()
                .filter(certInfo -> certInfo.getState() == CertificateState.ACTIVE)
                .forEach(certInfo -> {
                    if (expirationWarningTargetDate.isAfter(certInfo.getValidTo())) {
                        long daysToExpiration = ChronoUnit.DAYS.between(now, certInfo.getValidTo());
                        certInfo.setWarning(String.format(CERTIFICATE_EXPIRATION_WARNING, daysToExpiration));
                    }
                });
    }
}
