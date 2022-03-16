package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.LoginRejectResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.view.RedirectView;

import javax.validation.constraints.Pattern;

@Slf4j
@Validated
@Controller
@RequiredArgsConstructor
public class LoginRejectController {

    public static final String LOGIN_REJECT_REQUEST_MAPPING = "/login/reject";
    private final HydraService hydraService;

    @PostMapping(LOGIN_REJECT_REQUEST_MAPPING)
    public RedirectView loginReject(@ModelAttribute("loginChallenge")
                                    @Pattern(regexp = "^[a-f0-9]{32}$", message = "Incorrect login_challenge format") String loginChallenge) {

        LoginRejectResponse response = hydraService.rejectLogin(loginChallenge);
        if (response.getRedirectTo() == null) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Invalid hydra server response. Redirect URL missing from response.");
        }
        return new RedirectView(response.getRedirectTo().toString());
    }
}
