package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.service.hydra.ConsentAcceptResponse;
import ee.ria.govsso.session.service.hydra.ConsentRequestInfo;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.util.RequestUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import jakarta.validation.constraints.Pattern;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class ConsentInitController {
    public static final String CONSENT_INIT_REQUEST_MAPPING = "/consent/init";

    private final HydraService hydraService;

    @GetMapping(value = CONSENT_INIT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView consentInit(
            @RequestParam(name = "consent_challenge")
            @Pattern(regexp = "^[a-f0-9]{32}$") String consentChallenge) {

        ConsentRequestInfo consentRequestInfo = hydraService.fetchConsentRequestInfo(consentChallenge);
        RequestUtil.setFlowTraceId(consentRequestInfo.getLoginChallenge());

        ConsentAcceptResponse response = hydraService.acceptConsent(consentChallenge, consentRequestInfo);
        return new RedirectView(response.getRedirectTo().toString());
    }
}
