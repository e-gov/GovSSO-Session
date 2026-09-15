package ee.ria.govsso.session.util;

import ee.ria.govsso.session.service.hydra.Consent;
import ee.ria.govsso.session.service.hydra.ConsentRequestInfo;
import ee.ria.govsso.session.service.hydra.Context;
import ee.ria.govsso.session.service.hydra.SessionType;
import lombok.experimental.UtilityClass;

import java.util.List;

@UtilityClass
public class SecureAppUtil {

    public static boolean isSecuredAppSession(List<Consent> consents) {
        return isSecuredAppSession(consents.get(0).getConsentRequest());
    }

    public static boolean isSecuredAppSession(ConsentRequestInfo consentRequest) {
        return isSecuredAppSession(consentRequest.getContext());
    }

    public static boolean isSecuredAppSession(Context context) {
        return SessionType.SECURED_APP_SESSION == context.getSessionTypeOrFallback();
    }

    public static boolean isSecuredAppWebSession(List<Consent> consents) {
        return isSecuredAppWebSession(consents.get(0).getConsentRequest());
    }

    public static boolean isSecuredAppWebSession(ConsentRequestInfo consentRequest) {
        return isSecuredAppWebSession(consentRequest.getContext());
    }

    public static boolean isSecuredAppWebSession(Context context) {
        return SessionType.SECURED_APP_WEB_SESSION == context.getSessionTypeOrFallback();
    }
}
