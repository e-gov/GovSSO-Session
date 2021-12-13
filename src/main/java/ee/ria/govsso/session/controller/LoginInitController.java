package ee.ria.govsso.session.controller;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.tara.TaraService;
import ee.ria.govsso.session.session.SsoSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;
import javax.validation.constraints.Pattern;
import java.text.ParseException;
import java.util.Map;

import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class LoginInitController {

    public static final String LOGIN_INIT_REQUEST_MAPPING = "/login/init";
    private final HydraService hydraService;
    private final TaraService taraService;

    @GetMapping(value = LOGIN_INIT_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView loginInit(
            @RequestParam(name = "login_challenge")
            @Pattern(regexp = "^[a-f0-9]{32}$", message = "Incorrect login_challenge format") String loginChallenge,
            HttpSession session) throws ParseException {

        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(loginChallenge);
        SsoSession ssoSession = new SsoSession();
        ssoSession.setLoginChallenge(loginRequestInfo.getChallenge());
        String subject = loginRequestInfo.getSubject();

        if (subject != null && !subject.isEmpty()) {
            JWT idToken = hydraService.getConsents(subject, loginRequestInfo.getSessionId());
            JWTClaimsSet claimsSet = idToken.getJWTClaimsSet();
            Map<String, String> profileAttributes = (Map<String, String>) claimsSet.getClaims().get("profile_attributes");

            ModelAndView model = new ModelAndView("authView");
            model.addObject("givenName", profileAttributes.get("given_name"));
            model.addObject("familyName", profileAttributes.get("family_name"));
            model.addObject("subject", hideCharactersExceptFirstFive(subject));
            model.addObject("clientName", loginRequestInfo.getClient().getClientName());

            session.setAttribute(SSO_SESSION, ssoSession);

            return model;
        } else {
            AuthenticationRequest authenticationRequest = taraService.createAuthenticationRequest();
            ssoSession.setTaraAuthenticationRequestState(authenticationRequest.getState().getValue());
            ssoSession.setTaraAuthenticationRequestNonce(authenticationRequest.getNonce().getValue());
            session.setAttribute(SSO_SESSION, ssoSession);
            return new ModelAndView("redirect:" + authenticationRequest.toURI().toString());
        }
    }

    private String hideCharactersExceptFirstFive(String subject) {
        if (subject.length() > 5) {
            String visibleCharacters = subject.substring(0, 5);
            String hiddenCharacters = subject.substring(5);
            hiddenCharacters = hiddenCharacters.replaceAll(".", "*");
            subject = visibleCharacters + hiddenCharacters;
        }
        return subject;
    }
}
