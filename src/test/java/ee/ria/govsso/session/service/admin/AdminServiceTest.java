package ee.ria.govsso.session.service.admin;

import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.service.hydra.Client;
import ee.ria.govsso.session.service.hydra.Consent;
import ee.ria.govsso.session.service.hydra.Context;
import ee.ria.govsso.session.service.hydra.ConsentRequestInfo;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.Metadata;
import ee.ria.govsso.session.service.hydra.OidcClient;
import ee.ria.govsso.session.service.useragent.ParsedUserAgent;
import ee.ria.govsso.session.service.useragent.UserAgentParserService;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AdminServiceTest {

    private static final OffsetDateTime NOW = OffsetDateTime.parse("2026-04-27T12:00:00Z");

    private HydraService hydraService;
    private UserAgentParserService userAgentParserService;

    private AdminService adminService;

    @BeforeEach
    void setUp() throws MalformedURLException {
        hydraService = mock(HydraService.class);
        userAgentParserService = mock(UserAgentParserService.class);

        SsoConfigurationProperties properties = new SsoConfigurationProperties();
        properties.setBaseUrl(new URL("https://example.test"));
        properties.setSessionMaxDurationHours(1);
        properties.setSessionMaxUpdateIntervalMinutes(1);

        Clock clock = Clock.fixed(NOW.toInstant(), ZoneId.of("Europe/Tallinn"));
        adminService = new AdminService(clock, hydraService, properties, userAgentParserService);
    }

    @Test
    void getSessions_whenSingleSessionSingleService_returnsOneSession() {
        String subject = "subject-1";
        String sessionId = "session-1";
        String userAgent = "ua";
        String os = "Windows";
        String browser = "Chrome";

        Consent consent = new TestConsentBuilder()
                .sessionId(sessionId)
                .clientId("client-1")
                .requestedAt(NOW.minusMinutes(10))
                .authenticatedAt(NOW.minusMinutes(100))
                .ip("127.0.0.1")
                .userAgent(userAgent)
                .build();

        when(hydraService.getConsentsIncludingPartiallyExpired(subject))
                .thenReturn(List.of(consent));

        when(userAgentParserService.parse(userAgent))
                .thenReturn(new ParsedUserAgent(os, browser));

        List<Session> sessions = adminService.getSessions(subject);

        assertThat(sessions, hasSize(1));

        Session session = sessions.get(0);
        assertThat(session.sessionId(), equalTo(sessionId));
        assertThat(session.userAgent(), equalTo(userAgent));
        assertThat(session.os(), equalTo(os));
        assertThat(session.browser(), equalTo(browser));
        assertThat(session.ipAddresses(), contains("127.0.0.1"));
        assertThat(session.services(), hasSize(1));
    }

    @Test
    void getSessions_whenMultipleConsentsSameSessionDifferentClients_keepsLatestPerClient() {
        String subject = "subject-1";
        String sessionId = "session-1";
        String userAgent = "ua";
        String os = "Windows";
        String browser = "Chrome";

        OffsetDateTime oldRequestedAt = NOW.minusMinutes(20);
        OffsetDateTime newRequestedAt = NOW.minusMinutes(5);
        OffsetDateTime authenticatedAt = NOW.minusMinutes(100);

        Consent oldConsent = new TestConsentBuilder()
                .sessionId(sessionId)
                .clientId("client-1")
                .requestedAt(oldRequestedAt)
                .authenticatedAt(authenticatedAt)
                .ip("127.0.0.1")
                .userAgent(userAgent)
                .build();
        Consent newConsent = new TestConsentBuilder()
                .sessionId(sessionId)
                .clientId("client-1")
                .requestedAt(newRequestedAt)
                .authenticatedAt(authenticatedAt)
                .ip("127.0.0.1")
                .userAgent(userAgent)
                .build();

        when(hydraService.getConsentsIncludingPartiallyExpired(subject))
                .thenReturn(List.of(oldConsent, newConsent));

        when(userAgentParserService.parse(userAgent))
                .thenReturn(new ParsedUserAgent(os, browser));

        List<Session> sessions = adminService.getSessions(subject);

        assertThat(sessions, hasSize(1));
        assertThat(sessions.get(0).services(), hasSize(1));
        assertThat(sessions.get(0).authenticatedAt(), equalTo(authenticatedAt));
    }

    @Test
    void getSessions_whenMultipleSessions_returnsMultipleSessions() {
        String subject = "subject-1";
        String os = "Windows";
        String browser = "Chrome";

        Consent s1 = new TestConsentBuilder()
                .sessionId("session-1")
                .clientId("client-1")
                .requestedAt(NOW.minusMinutes(30))
                .authenticatedAt(NOW.minusMinutes(100))
                .ip("127.0.0.1")
                .userAgent("ua1")
                .build();
        Consent s2 = new TestConsentBuilder()
                .sessionId("session-2")
                .clientId("client-2")
                .requestedAt(NOW.minusMinutes(10))
                .authenticatedAt(NOW.minusMinutes(100))
                .ip("127.0.0.2")
                .userAgent("ua2")
                .build();

        when(hydraService.getConsentsIncludingPartiallyExpired(subject))
                .thenReturn(List.of(s1, s2));

        when(userAgentParserService.parse(any()))
                .thenReturn(new ParsedUserAgent(os, browser));

        List<Session> sessions = adminService.getSessions(subject);

        assertThat(sessions, hasSize(2));
    }

    @Accessors(fluent = true)
    @Setter
    private static class TestConsentBuilder {

        private String sessionId;
        private String clientId;
        private OffsetDateTime authenticatedAt;
        private OffsetDateTime requestedAt;
        private String ip;
        private String userAgent;

        public Consent build() {
            Context context = new Context();
            context.setIpAddress(ip);
            context.setUserAgent(userAgent);

            OidcClient oidcClient = new OidcClient();
            oidcClient.setNameTranslations(Map.of("en", "Test service"));

            Metadata metadata = new Metadata();
            metadata.setOidcClient(oidcClient);

            Client client = new Client();
            client.setClientId(clientId);
            client.setMetadata(metadata);

            ConsentRequestInfo info = new ConsentRequestInfo();
            info.setLoginSessionId(sessionId);
            info.setClient(client);
            info.setContext(context);
            info.setRequestedAt(requestedAt);
            info.setAuthenticatedAt(authenticatedAt);

            Consent consent = new Consent();
            consent.setConsentRequest(info);
            consent.setRememberFor(600);

            return consent;
        }

    }

}
