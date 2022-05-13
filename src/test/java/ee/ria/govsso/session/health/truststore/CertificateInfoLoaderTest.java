package ee.ria.govsso.session.health.truststore;

import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.security.KeyStore;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@SpringBootTest
@Import({BuildProperties.class})
@RequiredArgsConstructor(onConstructor_ = @Autowired)
class CertificateInfoLoaderTest {

    private final KeyStore hydraTrustStore;
    private final KeyStore taraTrustStore;

    @Test
    void loadCertificateInfos_hydra() {
        List<CertificateInfo> certificateInfos = CertificateInfoLoader.loadCertificateInfos(hydraTrustStore);
        assertEquals(1, certificateInfos.size());
        CertificateInfo certificateInfo = certificateInfos.get(0);
        assertEquals("govsso-ca.localhost", certificateInfo.getAlias());
        assertEquals("CN=govsso-ca.localhost,O=govsso-local,L=Tallinn,C=EE", certificateInfo.getSubjectDN());
        assertNull(certificateInfo.getState());
        assertNull(certificateInfo.getWarning());
    }

    @Test
    void loadCertificateInfos_tara() {
        List<CertificateInfo> certificateInfos = CertificateInfoLoader.loadCertificateInfos(taraTrustStore);
        assertEquals(1, certificateInfos.size());
        CertificateInfo certificateInfo = certificateInfos.get(0);
        assertEquals("tara-ca.localhost", certificateInfo.getAlias());
        assertEquals("CN=tara-ca.localhost,O=tara-local,L=Tallinn,C=EE", certificateInfo.getSubjectDN());
        assertNull(certificateInfo.getState());
        assertNull(certificateInfo.getWarning());
    }
}
