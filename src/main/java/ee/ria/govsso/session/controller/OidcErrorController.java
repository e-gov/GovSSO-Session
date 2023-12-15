package ee.ria.govsso.session.controller;

import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import org.springframework.stereotype.Controller;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import jakarta.validation.constraints.Size;
import java.util.Map;

@Validated
@Controller
public class OidcErrorController {
    public static final String ERROR_OIDC_REQUEST_MAPPING = "/error/oidc";
    public static final Map<String, ErrorCode> OIDC_ERRORS_MAP = Map.of(
            "invalid_client", ErrorCode.USER_INVALID_OIDC_CLIENT,
            "invalid_request", ErrorCode.USER_INVALID_OIDC_REQUEST);

    @GetMapping(value = ERROR_OIDC_REQUEST_MAPPING)
    public ModelAndView oidcError(
            @RequestParam(name = "error") @Size(max = 50) String errorCode,
            @RequestParam(name = "error_description", required = false, defaultValue = "not set") String errorDescription) {

        throw new SsoException(OIDC_ERRORS_MAP.getOrDefault(errorCode, ErrorCode.USER_OIDC_OTHER_ERROR),
                "Oidc server error: code = %s, description = %s".formatted(errorCode, errorDescription));
    }
}
