package ee.ria.govsso.session;

import ee.ria.govsso.session.configuration.properties.HydraConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.configuration.properties.TaraConfigurationProperties;
import ee.ria.govsso.session.session.SsoSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpSession;
import javax.validation.Validator;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;

@Slf4j
@Validated
@Controller
public class AuthInitController {

    public static final String AUTH_INIT_REQUEST_MAPPING = "/auth/init";

    @Autowired
    private HydraConfigurationProperties hydraConfigurationProperties;

    @Autowired
    private TaraConfigurationProperties taraConfigurationProperties;

    @Autowired
    private SsoConfigurationProperties ssoConfigurationProperties;

    @Autowired
    private Validator validator;

    @Autowired
    private WebClient webclient;

    @GetMapping(value = AUTH_INIT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView authInit(
            @RequestParam(name = "login_challenge") @Size(max = 50)
            @Pattern(regexp = "[A-Za-z0-9]{1,}", message = "only characters and numbers allowed") String loginChallenge,
            HttpSession session) {

        createSsoSession(session, fetchLoginRequestInfo(loginChallenge));

        return new RedirectView(createTaraOidcUrl());
    }

    private void createSsoSession(HttpSession session, SsoSession.LoginRequestInfo loginRequestInfo) {
        SsoSession ssoSession = new SsoSession();
        ssoSession.setLoginRequestInfo(loginRequestInfo);
        session.setAttribute(SSO_SESSION, ssoSession);
    }

    private String createTaraOidcUrl() {
        String url = taraConfigurationProperties.getAuthUrl();
        UriComponentsBuilder builder = UriComponentsBuilder.fromPath(url)
                .queryParam("state", "123abc")
                .queryParam("client_id", ssoConfigurationProperties.getClientId())
                .queryParam("redirect_uri", ssoConfigurationProperties.getBaseUrl());
        return builder.toUriString();
    }

    private SsoSession.LoginRequestInfo fetchLoginRequestInfo(String loginChallenge) {
        String url = hydraConfigurationProperties.getLoginUrl() + "?login_challenge=" + loginChallenge;

        SsoSession.LoginRequestInfo loginRequestInfo = webclient.get().uri(url).retrieve().bodyToMono(SsoSession.LoginRequestInfo.class).block();

        if (loginRequestInfo == null || !loginRequestInfo.getChallenge().equals(loginChallenge))
            throw new IllegalStateException("Invalid hydra response");
        return loginRequestInfo;
    }
}
