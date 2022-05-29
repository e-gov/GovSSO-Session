package ee.ria.govsso.session.actuator.health.truststore;

import lombok.SneakyThrows;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;

class CertificateInfoLoader {

    private static final String CERTIFICATE_TYPE_X_509 = "X.509";

    @SneakyThrows
    static List<CertificateInfo> loadCertificateInfos(KeyStore trustStore) {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        Enumeration<String> aliases = trustStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (trustStore.isCertificateEntry(alias)) {
                Certificate certificate = trustStore.getCertificate(alias);
                if (CERTIFICATE_TYPE_X_509.equals(certificate.getType())) {
                    certificateInfos.add(buildCertificateInfo(alias, (X509Certificate) certificate));
                }
            }
        }

        certificateInfos.sort(Comparator.comparing(CertificateInfo::getAlias));
        return certificateInfos;
    }

    private static CertificateInfo buildCertificateInfo(String alias, X509Certificate certificate) {
        return CertificateInfo.builder()
                .alias(alias)
                .validFrom(certificate.getNotBefore().toInstant())
                .validTo(certificate.getNotAfter().toInstant())
                .subjectDN(certificate.getSubjectX500Principal().getName())
                .serialNumber(certificate.getSerialNumber().toString())
                .build();
    }
}
