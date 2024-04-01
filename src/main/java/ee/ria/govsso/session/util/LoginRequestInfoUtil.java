package ee.ria.govsso.session.util;

import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.LevelOfAssurance;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.hydra.OidcContext;
import lombok.experimental.UtilityClass;
import org.thymeleaf.util.ArrayUtils;

import java.util.Arrays;

@UtilityClass
public class LoginRequestInfoUtil {

    public void validateScopes(LoginRequestInfo loginRequestInfo) {
        String[] requestedScopes = loginRequestInfo.getRequestedScope();
        if (!Arrays.asList(requestedScopes).contains("openid") ||
                !Arrays.stream(requestedScopes).allMatch(s -> s.matches("^(openid|phone|representee\\.\\*)$")) ||
                requestedScopes.length > 3) {
            throw new SsoException(ErrorCode.USER_INPUT, "Requested scope must contain openid and may contain phone and representee.*, but nothing else");
        }

    }

    public void validateAcrValues(LoginRequestInfo loginRequestInfo) {
        OidcContext oidcContext = loginRequestInfo.getOidcContext();

        if (oidcContext == null || ArrayUtils.isEmpty(oidcContext.getAcrValues())) {
            return;
        }
        if (oidcContext.getAcrValues().length > 1) {
            throw new SsoException(ErrorCode.USER_INPUT, "acrValues must contain only 1 value");
        } else if (LevelOfAssurance.findByAcrName(oidcContext.getAcrValues()[0]) == null) {
            throw new SsoException(ErrorCode.USER_INPUT, "acrValues must be one of low/substantial/high");
        }
    }
}
