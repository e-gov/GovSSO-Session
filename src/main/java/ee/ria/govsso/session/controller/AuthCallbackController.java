package ee.ria.govsso.session.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.tara.TaraService;
import ee.ria.govsso.session.session.SsoSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Base64;
import java.util.Map;

import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class AuthCallbackController {

    public static final String CALLBACK_REQUEST_MAPPING = "/auth/taracallback";

    private final SsoConfigurationProperties ssoConfigurationProperties;

    private final TaraService taraService;
    private final HydraService hydraService;

    @GetMapping(value = CALLBACK_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView authCallback(
            @RequestParam(name = "code") String code,
            @SessionAttribute(value = SSO_SESSION) SsoSession ssoSession) throws JsonProcessingException {

        String idToken = taraService.getIdToken(code, ssoConfigurationProperties.getBaseUrl() + "auth/taracallback");
        String redirectUrl = hydraService.acceptLogin(ssoSession.getLoginRequestInfo().getChallenge(), getSubFromIdToken(idToken));

        return new RedirectView(redirectUrl);
    }

    private String getSubFromIdToken(String idToken) throws JsonProcessingException {

        String payload = getIdTokenPayload(idToken);
        Map<String, String> map = new ObjectMapper().readValue(payload, Map.class);

        return map.get("sub");
    }

    private String getIdTokenPayload(String idToken) {

        int payloadIndex = 1;
        Base64.Decoder decoder = Base64.getDecoder();
        String[] chunks = idToken.split("\\.");
        String payload = new String(decoder.decode(chunks[payloadIndex]));

        return payload;
    }
}
