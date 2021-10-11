package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.session.SsoSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpSession;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class AuthInitController {

    public static final String AUTH_INIT_REQUEST_MAPPING = "/auth/init";
    public static final String AUTH_VIEW_REQUEST_MAPPING = "/auth/view";

    private final TaraConfigurationProperties taraConfigurationProperties;
    private final SsoConfigurationProperties ssoConfigurationProperties;
    private final HydraService hydraService;

    @GetMapping(value = AUTH_INIT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView authInit(
            @RequestParam(name = "login_challenge") @Size(max = 50)
            @Pattern(regexp = "[A-Za-z0-9]{1,}", message = "only characters and numbers allowed") String loginChallenge,
            HttpSession session) {

        createSsoSession(session, hydraService.fetchLoginRequestInfo(loginChallenge));

        return new RedirectView(createTaraOidcUrl());
    }

    @GetMapping(value = AUTH_VIEW_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public String authView() {

        return "authView";
    }

    private void createSsoSession(HttpSession session, SsoSession.LoginRequestInfo loginRequestInfo) {
        SsoSession ssoSession = new SsoSession();
        ssoSession.setLoginRequestInfo(loginRequestInfo);
        session.setAttribute(SSO_SESSION, ssoSession);
    }

    private String createTaraOidcUrl() {
        String uri = taraConfigurationProperties.getAuthUrl().toString();

        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(uri)
                .queryParam("response_type", "code")
                .queryParam("scope", "openid")
                .queryParam("state", "1234abcd")
                .queryParam("client_id", taraConfigurationProperties.getClientId())
                .queryParam("redirect_uri", ssoConfigurationProperties.getBaseUrl() + "auth/taracallback");
        return builder.toUriString();
    }
}
