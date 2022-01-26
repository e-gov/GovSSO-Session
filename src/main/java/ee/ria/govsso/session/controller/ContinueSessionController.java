package ee.ria.govsso.session.controller;

import com.nimbusds.jwt.JWT;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.session.SsoCookie;
import ee.ria.govsso.session.session.SsoCookieValue;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.view.RedirectView;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class ContinueSessionController {
    public static final String AUTH_VIEW_REQUEST_MAPPING = "/login/continuesession";

    private final HydraService hydraService;

    @PostMapping(value = AUTH_VIEW_REQUEST_MAPPING, produces = MediaType.TEXT_HTML_VALUE)
    public RedirectView continueSession(@SsoCookieValue SsoCookie ssoCookie) {

        String loginChallenge = ssoCookie.getLoginChallenge();
        LoginRequestInfo loginRequestInfo = hydraService.fetchLoginRequestInfo(loginChallenge);
        validateLoginRequestInfo(loginRequestInfo);

        JWT idToken = hydraService.getConsents(loginRequestInfo.getSubject(), loginRequestInfo.getSessionId());
        String redirectUrl = hydraService.acceptLogin(loginChallenge, idToken);

        return new RedirectView(redirectUrl);
    }

    private void validateLoginRequestInfo(LoginRequestInfo loginRequestInfo) {
        if (loginRequestInfo.getSubject().isEmpty())
            throw new SsoException(ErrorCode.USER_INPUT, "Login request subject must not be empty");
        if (loginRequestInfo.getOidcContext() != null && loginRequestInfo.getOidcContext().getIdTokenHintClaims() != null)
            throw new SsoException(ErrorCode.USER_INPUT, "Login request ID token hint claim must be null");
    }
}
