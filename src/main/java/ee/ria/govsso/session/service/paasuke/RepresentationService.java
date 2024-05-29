package ee.ria.govsso.session.service.paasuke;

import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.ErrorHandler;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.Client;
import ee.ria.govsso.session.service.hydra.ConsentRequestInfo;
import ee.ria.govsso.session.service.hydra.Representee;
import ee.ria.govsso.session.service.hydra.RepresenteeList;
import ee.ria.govsso.session.service.hydra.RepresenteeRequestStatus;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.stream.Collectors;

import static ee.ria.govsso.session.service.hydra.RepresenteeList.RepresenteeListRequestStatus.REPRESENTEE_LIST_CURRENT;
import static ee.ria.govsso.session.service.hydra.RepresenteeList.RepresenteeListRequestStatus.SERVICE_NOT_AVAILABLE;
import static java.util.Objects.requireNonNull;
import static net.logstash.logback.marker.Markers.append;

@Slf4j
@Service
@RequiredArgsConstructor
public class RepresentationService {
    private final PaasukeService paasukeService;

    public RepresenteeList getRepresentees(ConsentRequestInfo consentRequestInfo, String subject) {
        try {
            String paasukeParameters = extractPaasukeParameters(consentRequestInfo);
            PaasukeGovssoClient govssoClient = extractGovssoClient(consentRequestInfo);
            Person[] persons = paasukeService.fetchRepresentees(subject, paasukeParameters, govssoClient);
            return representeeListRequestSuccess(persons);
        } catch (SsoException e) {
            log.error(append(ErrorHandler.ERROR_CODE_MARKER, e.getErrorCode().name()), e.getMessage(), e);
            return representeeListRequestFailed();
        }
    }

    public Representee getRepresentee(ConsentRequestInfo consentRequestInfo, String subject, String representeeSubject) {
        RepresenteeRequestStatus status = RepresenteeRequestStatus.SERVICE_NOT_AVAILABLE;
        try {
            String paasukeParameters = extractPaasukeParameters(consentRequestInfo);
            PaasukeGovssoClient govssoClient = extractGovssoClient(consentRequestInfo);
            MandateTriplet mandateTriplet =
                    paasukeService.fetchMandates(representeeSubject, subject, paasukeParameters, govssoClient);
            if (mandateTriplet.mandates().isEmpty()) {
                status = RepresenteeRequestStatus.REQUESTED_REPRESENTEE_NOT_ALLOWED;
                throw new SsoException(ErrorCode.USER_INPUT, "User is not allowed to represent provided representee");
            }
            return toHydraRepresentation(mandateTriplet);
        } catch (SsoException e) {
            log.error(append(ErrorHandler.ERROR_CODE_MARKER, e.getErrorCode().name()), e.getMessage(), e);
            return representeeRequestFailed(status);
        }
    }

    private static String extractPaasukeParameters(ConsentRequestInfo consentRequestInfo) {
        return consentRequestInfo.getClient().getMetadata().getPaasukeParameters();
    }

    private static PaasukeGovssoClient extractGovssoClient(ConsentRequestInfo consentRequestInfo) {
        Client client = consentRequestInfo.getClient();
        String institutionRegistryCode = requireNonNull(
                client.getMetadata().getOidcClient().getInstitution().getRegistryCode());
        String clientId = client.getClientId();
        return new PaasukeGovssoClient(
                "EE" + institutionRegistryCode,
                clientId
        );
    }

    private static Representee representeeRequestFailed(RepresenteeRequestStatus status) {
        return Representee.builder().status(status).build();
    }

    private static RepresenteeList representeeListRequestSuccess(Person[] persons) {
        return RepresenteeList.builder()
            .status(REPRESENTEE_LIST_CURRENT)
            .list(Arrays.stream(persons).map(RepresentationService::toHydraRepresentation).toList())
            .build();
    }

    private static Representee toHydraRepresentation(Person representee) {
        return Representee.builder()
            .type(representee.type())
            .givenName(representee.firstName())
            .familyName(representee.surname())
            .name(representee.legalName())
            .sub(representee.identifier())
            .build();
    }

    private static RepresenteeList representeeListRequestFailed() {
        return RepresenteeList.builder().status(SERVICE_NOT_AVAILABLE).build();
    }

    private static Representee toHydraRepresentation(MandateTriplet mandateTriplet) {
        Person representee = mandateTriplet.representee();
        return Representee.builder()
            .status(RepresenteeRequestStatus.REQUESTED_REPRESENTEE_CURRENT)
            .type(representee.type())
            .givenName(representee.firstName())
            .familyName(representee.surname())
            .name(representee.legalName())
            .sub(representee.identifier())
            .mandates(mandateTriplet.mandates()
                .stream()
                .map(mandate -> Representee.Mandate.builder()
                    .role(mandate.role())
                    .build())
                .collect(Collectors.toList())
            )
            .build();
    }
}
