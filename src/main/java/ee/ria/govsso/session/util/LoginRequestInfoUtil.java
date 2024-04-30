package ee.ria.govsso.session.util;

import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.LevelOfAssurance;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.hydra.OidcContext;
import lombok.experimental.UtilityClass;
import org.thymeleaf.util.ArrayUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@UtilityClass
public class LoginRequestInfoUtil {

    public void validateScopes(LoginRequestInfo loginRequestInfo) {
        List<String> requestedScopes = Arrays.asList(loginRequestInfo.getRequestedScope());
        Set<String> set = new HashSet<>(requestedScopes);
        if (!requestedScopes.contains("openid") ||
                !requestedScopes.stream().allMatch(s -> s.matches("^(openid|phone|representee_list|representee\\.\\*)$")) ||
                set.size() != requestedScopes.size() && requestedScopes.size() > 4) {
            throw new SsoException(ErrorCode.USER_INPUT, "Requested scope must contain openid and may contain phone, representee.* and representee_list, but nothing else");
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
