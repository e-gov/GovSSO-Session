package ee.ria.govsso.session.controller;

import com.nimbusds.jwt.SignedJWT;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
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
import org.springframework.web.bind.annotation.SessionAttribute;
import org.springframework.web.servlet.view.RedirectView;

import javax.validation.constraints.Pattern;

import static ee.ria.govsso.session.session.SsoSession.SSO_SESSION;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class AuthCallbackController {

    public static final String CALLBACK_REQUEST_MAPPING = "/login/taracallback";
    private final TaraService taraService;
    private final HydraService hydraService;

    @GetMapping(value = CALLBACK_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView loginCallback(
            @RequestParam(name = "code") @Pattern(regexp = "^[A-Za-z0-9\\-_.]{6,87}$") String code,
            @RequestParam(name = "state") @Pattern(regexp = "^[A-Za-z0-9\\-_]{43}$") String state,
            @SessionAttribute(value = SSO_SESSION) SsoSession ssoSession) {

        validateLoginRequestInfo(state, ssoSession);

        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(ssoSession.getLoginChallenge());

        SignedJWT idToken = taraService.requestIdToken(code);
        taraService.verifyIdToken(ssoSession.getTaraAuthenticationRequestNonce(), idToken);
        String redirectUrl = hydraService.acceptLogin(ssoSession.getLoginChallenge(), idToken);
        return new RedirectView(redirectUrl);
    }

    private void validateLoginRequestInfo(String state, SsoSession ssoSession) {
        if (ssoSession.getTaraAuthenticationRequestState() == null) {
            throw new SsoException(ErrorCode.USER_INPUT_OR_EXPIRED, "Session tara authentication request state must not be null");
        }
        if (ssoSession.getLoginChallenge() == null) {
            throw new SsoException(ErrorCode.USER_INPUT_OR_EXPIRED, "Session login request info challenge must not be null");
        }
        if (!ssoSession.getTaraAuthenticationRequestState().equals(state)) {
            throw new SsoException(ErrorCode.USER_INPUT, "Invalid TARA callback state");
        }
    }
}
