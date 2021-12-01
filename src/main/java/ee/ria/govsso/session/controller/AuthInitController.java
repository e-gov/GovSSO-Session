package ee.ria.govsso.session.controller;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.tara.TaraService;
import ee.ria.govsso.session.session.SsoSession;
import ee.ria.govsso.session.session.SsoSession.LoginRequestInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpSession;
import javax.validation.constraints.Pattern;

import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class AuthInitController {

    public static final String AUTH_INIT_REQUEST_MAPPING = "/auth/init";
    public static final String AUTH_VIEW_REQUEST_MAPPING = "/auth/view";
    private final HydraService hydraService;
    private final TaraService taraService;

    @GetMapping(value = AUTH_INIT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView authInit(
            @RequestParam(name = "login_challenge")
            @Pattern(regexp = "^[a-f0-9]{32}$", message = "Incorrect login_challenge format") String loginChallenge,
            HttpSession session) {

        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(loginChallenge);
        AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
        SsoSession ssoSession = new SsoSession(loginRequestInfo, authenticationRequest.getState().getValue(), authenticationRequest.getNonce().getValue());
        session.setAttribute(SSO_SESSION, ssoSession);
        return new RedirectView(authenticationRequest.toURI().toString());
    }

    @GetMapping(value = AUTH_VIEW_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public String authView() {

        return "authView";
    }
}
