package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.error.ErrorHandler;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.ConsentAcceptResponse;
import ee.ria.govsso.session.service.hydra.ConsentRequestInfo;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.Representee;
import ee.ria.govsso.session.service.paasuke.PaasukeService;
import ee.ria.govsso.session.service.paasuke.Person;
import ee.ria.govsso.session.util.RequestUtil;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import javax.validation.constraints.Pattern;
import java.util.Arrays;
import java.util.List;

import static net.logstash.logback.marker.Markers.append;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class ConsentInitController {
    public static final String CONSENT_INIT_REQUEST_MAPPING = "/consent/init";

    private final HydraService hydraService;
    private final PaasukeService paasukeService;

    @GetMapping(value = CONSENT_INIT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView consentInit(
            @RequestParam(name = "consent_challenge")
            @Pattern(regexp = "^[a-f0-9]{32}$") String consentChallenge) {

        ConsentRequestInfo consentRequestInfo = hydraService.fetchConsentRequestInfo(consentChallenge);
        RequestUtil.setFlowTraceId(consentRequestInfo.getLoginChallenge());

        List<Representee> representees = null;
        if (List.of(consentRequestInfo.getRequestedScope()).contains("representee_list")) {
            representees = getRepresentees(consentRequestInfo);
        }
        ConsentAcceptResponse response = hydraService.acceptConsent(consentChallenge, consentRequestInfo, representees);
        return new RedirectView(response.getRedirectTo().toString());
    }

    @SneakyThrows
    private List<Representee> getRepresentees(ConsentRequestInfo consentRequestInfo) {
        String queryParams = consentRequestInfo.getClient().getMetadata().getPaasukeParameters();
        try {
            Person[] persons = paasukeService.fetchRepresentees(consentRequestInfo.getSubject(), queryParams);
            return Arrays.stream(persons).map(this::toHydraRepresentation).toList();
        } catch (SsoException e) {
            log.error(append(ErrorHandler.ERROR_CODE_MARKER, e.getErrorCode().name()), e.getMessage(), e);
        }
        return null;
    }

    //TODO RefreshTokenHookController has the exact same method, refactor so it can be reused in both places.
    private Representee toHydraRepresentation(Person representee) {
        return Representee.builder()
                .type(representee.type())
                .givenName(representee.firstName())
                .familyName(representee.surname())
                .name(representee.legalName())
                .sub(representee.identifier())
                .build();
    }
}
