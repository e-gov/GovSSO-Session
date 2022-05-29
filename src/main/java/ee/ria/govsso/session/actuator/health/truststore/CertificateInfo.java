package ee.ria.govsso.session.actuator.health.truststore;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Builder
class CertificateInfo {
    private String alias;
    private Instant validFrom;
    private Instant validTo;
    private String subjectDN;
    private String serialNumber;

    @Setter
    private CertificateState state;

    @Setter
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String warning;
}
