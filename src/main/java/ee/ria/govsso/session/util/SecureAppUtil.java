package ee.ria.govsso.session.util;

import ee.ria.govsso.session.service.hydra.Consent;
import ee.ria.govsso.session.service.hydra.ConsentRequestInfo;
import ee.ria.govsso.session.service.hydra.SessionType;
import lombok.experimental.UtilityClass;

import java.util.List;

@UtilityClass
public class SecureAppUtil {

    public static boolean isSecuredAppSession(List<Consent> consents) {
        return isSecuredAppSession(consents.get(0).getConsentRequest());
    }

    public static boolean isSecuredAppSession(ConsentRequestInfo consentRequest) {
        return SessionType.SECURED_APP_SESSION == consentRequest.getContext().getSessionTypeOrFallback();
    }
}
