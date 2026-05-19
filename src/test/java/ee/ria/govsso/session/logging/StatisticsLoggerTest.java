package ee.ria.govsso.session.logging;

import ch.qos.logback.classic.Level;
import ee.ria.govsso.session.BaseTestLoggingAssertion;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.service.hydra.Client;
import ee.ria.govsso.session.service.hydra.Institution;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.hydra.Metadata;
import ee.ria.govsso.session.service.hydra.OidcClient;
import org.junit.jupiter.api.Test;

import static ch.qos.logback.classic.Level.INFO;
import static ee.ria.govsso.session.logging.StatisticsLogger.AuthenticationRequestType.START_SESSION;

class StatisticsLoggerTest extends BaseTestLoggingAssertion {

    private static final String CLIENT_ID = "client-a";
    private static final String CLIENT_NAME_ET = "Teenusenimi A";
    private static final String CLIENT_SHORT_NAME_ET = "Teenus A";
    private static final String REGISTRY_CODE = "70000001";
    private static final String SECTOR = "public";
    private static final String SESSION_ID = "test-session-id";

    private final StatisticsLogger statisticsLogger = new StatisticsLogger();

    @Test
    void logReject_WhenClientHasEstonianTranslations_ThenClientNameAndShortNameAreLogged() {
        statisticsLogger.logReject(createLoginRequestInfo(), START_SESSION);

        assertMessage()
                .withLoggerClass(StatisticsLogger.class)
                .withMessage(StatisticsLogger.LOG_MESSAGE)
                .withLevel(INFO)
                .withMarker("StatisticsLogger.SessionStatistics(clientId=client-a, clientName=Teenusenimi A, clientShortName=Teenus A, registryCode=70000001, sector=public, sessionId=test-session-id, sessionStartTime=null, sessionDuration=null, country=null, idCode=null, authenticationRequestType=START_SESSION, authenticationType=null, authenticationState=AUTHENTICATION_CANCELED, requestedAcr=null, grantedAcr=null, errorCode=null)")
                .isLoggedOnce();
    }

    @Test
    void logError_WhenClientHasEstonianTranslations_ThenClientNameAndShortNameAreLogged() {
        statisticsLogger.logError(
                new RuntimeException("test error"),
                ErrorCode.TECHNICAL_GENERAL,
                createClient(),
                SESSION_ID,
                START_SESSION
        );

        assertMessage()
                .withLoggerClass(StatisticsLogger.class)
                .withMessage(StatisticsLogger.LOG_MESSAGE)
                .withLevel(Level.ERROR)
                .withMarker("StatisticsLogger.SessionStatistics(clientId=client-a, clientName=Teenusenimi A, clientShortName=Teenus A, registryCode=70000001, sector=public, sessionId=test-session-id, sessionStartTime=null, sessionDuration=null, country=null, idCode=null, authenticationRequestType=START_SESSION, authenticationType=null, authenticationState=AUTHENTICATION_FAILED, requestedAcr=null, grantedAcr=null, errorCode=TECHNICAL_GENERAL)")
                .isLoggedOnce();
    }

    private LoginRequestInfo createLoginRequestInfo() {
        LoginRequestInfo loginRequestInfo = new LoginRequestInfo();
        loginRequestInfo.setClient(createClient());
        loginRequestInfo.setSessionId(SESSION_ID);
        return loginRequestInfo;
    }

    private Client createClient() {
        Institution institution = new Institution();
        institution.setRegistryCode(REGISTRY_CODE);
        institution.setSector(SECTOR);

        OidcClient oidcClient = new OidcClient();
        oidcClient.setInstitution(institution);
        oidcClient.getNameTranslations().put("et", CLIENT_NAME_ET);
        oidcClient.getShortNameTranslations().put("et", CLIENT_SHORT_NAME_ET);

        Metadata metadata = new Metadata();
        metadata.setOidcClient(oidcClient);

        Client client = new Client();
        client.setClientId(CLIENT_ID);
        client.setMetadata(metadata);
        return client;
    }
}
