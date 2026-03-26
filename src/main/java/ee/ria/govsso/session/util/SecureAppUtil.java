package ee.ria.govsso.session.util;

import ee.ria.govsso.session.service.hydra.Consent;
import ee.ria.govsso.session.service.hydra.ConsentRequestInfo;
import lombok.experimental.UtilityClass;

import java.time.Duration;
import java.util.List;

@UtilityClass
public class SecureAppUtil {

    public static final Duration REMEMBER_FOR = Duration.ofDays(90);

    public static boolean isLongLivingSession(List<Consent> consents) {
        return isLongLivingSession(consents.get(0).getConsentRequest());
    }

    public static boolean isLongLivingSession(ConsentRequestInfo consentRequest) {
        return consentRequest.getContext().isLongLivingSession();
    }
}
