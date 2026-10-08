package ee.ria.govsso.session.service.authhandover;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.Client;
import ee.ria.govsso.session.service.hydra.Metadata;
import ee.ria.govsso.session.token.UserAttributes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthHandoverAcceptancePolicyTest {

    private static final Instant NOW = Instant.parse("2026-01-01T12:00:00Z");
    private static final int SESSION_MAX_DURATION_HOURS = 12;
    private static final String CLIENT_ID = "client-a";

    private final ListAppender<ILoggingEvent> logAppender = new ListAppender<>();
    private final Logger logger = (Logger) LoggerFactory.getLogger(AuthHandoverAcceptancePolicy.class);
    private AuthHandoverAcceptancePolicy policy;

    @BeforeEach
    void setUp() {
        SsoConfigurationProperties ssoConfigurationProperties = new SsoConfigurationProperties();
        ssoConfigurationProperties.setSessionMaxDurationHours(SESSION_MAX_DURATION_HOURS);
        policy = new AuthHandoverAcceptancePolicy(ssoConfigurationProperties, Clock.fixed(NOW, ZoneOffset.UTC));
        logAppender.start();
        logger.addAppender(logAppender);
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(logAppender);
    }

    @Test
    void clientAcceptsAuthHandover_whenAllChecksPass_returnsTrueAndDoesNotLog() {
        Client client = createClient(true, "1h");
        UserAttributes userAttributes = createUserAttributes(NOW.minus(Duration.ofHours(1)), NOW.minus(Duration.ofMinutes(30)));

        assertThat(policy.clientAcceptsAuthHandover(client, userAttributes), is(true));
        assertNothingLogged();
    }

    @Test
    void clientAcceptsAuthHandover_whenSecuredAppSessionMaxDurationNotSet_returnsTrue() {
        Client client = createClient(true, null);
        UserAttributes userAttributes = createUserAttributes(NOW.minus(Duration.ofHours(1)), null);

        assertThat(policy.clientAcceptsAuthHandover(client, userAttributes), is(true));
        assertNothingLogged();
    }

    @Test
    void clientAcceptsAuthHandover_whenClientDoesNotAllowSecuredAppWebSession_returnsFalse() {
        Client client = createClient(false, null);
        UserAttributes userAttributes = createUserAttributes(NOW, NOW);

        assertThat(policy.clientAcceptsAuthHandover(client, userAttributes), is(false));
        assertResultLogged(AuthHandoverAcceptancePolicy.Result.SECURED_APP_WEB_SESSION_NOT_ALLOWED);
    }

    @Test
    void clientAcceptsAuthHandover_whenAuthHandoverIsOlderThanSessionMaxDuration_returnsFalse() {
        Client client = createClient(true, null);
        UserAttributes userAttributes = createUserAttributes(
                NOW.minus(Duration.ofHours(SESSION_MAX_DURATION_HOURS)).minusSeconds(1), NOW);

        assertThat(policy.clientAcceptsAuthHandover(client, userAttributes), is(false));
        assertResultLogged(AuthHandoverAcceptancePolicy.Result.AUTH_HANDOVER_EXPIRED);
    }

    @Test
    void clientAcceptsAuthHandover_whenAuthHandoverIsExactlySessionMaxDurationOld_returnsTrue() {
        Client client = createClient(true, null);
        UserAttributes userAttributes = createUserAttributes(
                NOW.minus(Duration.ofHours(SESSION_MAX_DURATION_HOURS)), NOW);

        assertThat(policy.clientAcceptsAuthHandover(client, userAttributes), is(true));
        assertNothingLogged();
    }

    @Test
    void clientAcceptsAuthHandover_whenSecuredAppSessionIsOlderThanClientMaxDuration_returnsFalse() {
        Client client = createClient(true, "1h");
        UserAttributes userAttributes = createUserAttributes(NOW, NOW.minus(Duration.ofHours(1)).minusSeconds(1));

        assertThat(policy.clientAcceptsAuthHandover(client, userAttributes), is(false));
        assertResultLogged(AuthHandoverAcceptancePolicy.Result.SECURED_APP_SESSION_EXPIRED);
    }

    @Test
    void clientAcceptsAuthHandover_whenAuthHandoverTimeMissing_throwsException() {
        Client client = createClient(true, null);
        UserAttributes userAttributes = createUserAttributes(null, NOW);

        SsoException exception = assertThrows(SsoException.class,
                () -> policy.clientAcceptsAuthHandover(client, userAttributes));
        assertThat(exception.getErrorCode(), equalTo(ErrorCode.TECHNICAL_GENERAL));
        assertThat(exception.getMessage(), containsString("iat"));
    }

    @Test
    void clientAcceptsAuthHandover_whenTaraAuthTimeMissingAndClientHasMaxDuration_throwsException() {
        Client client = createClient(true, "1h");
        UserAttributes userAttributes = createUserAttributes(NOW, null);

        SsoException exception = assertThrows(SsoException.class,
                () -> policy.clientAcceptsAuthHandover(client, userAttributes));
        assertThat(exception.getErrorCode(), equalTo(ErrorCode.TECHNICAL_GENERAL));
        assertThat(exception.getMessage(), containsString("auth_time"));
    }

    private void assertNothingLogged() {
        assertThat(logAppender.list, is(empty()));
    }

    private void assertResultLogged(AuthHandoverAcceptancePolicy.Result result) {
        assertThat(logAppender.list.stream().map(ILoggingEvent::getLevel).toList(), contains(Level.INFO));
        ILoggingEvent event = logAppender.list.get(0);
        assertThat(event.getFormattedMessage(), equalTo("Client auth handover acceptance evaluated: " + result));
        String marker = event.getMarkerList().get(0).toString();
        assertThat(marker, containsString("auth_handover.client_id=" + CLIENT_ID));
        assertThat(marker, containsString("auth_handover.result=" + result));
    }

    private static Client createClient(boolean allowSecuredAppWebSession, String securedAppSessionMaxDuration) {
        Metadata metadata = new Metadata();
        metadata.setAllowSecuredAppWebSession(allowSecuredAppWebSession);
        metadata.setSecuredAppSessionMaxDuration(securedAppSessionMaxDuration);
        Client client = new Client();
        client.setClientId(CLIENT_ID);
        client.setMetadata(metadata);
        return client;
    }

    private static UserAttributes createUserAttributes(Instant authHandoverTime, Instant taraAuthTime) {
        return UserAttributes.builder()
                .authHandoverTime(authHandoverTime)
                .taraAuthTime(taraAuthTime)
                .build();
    }
}
