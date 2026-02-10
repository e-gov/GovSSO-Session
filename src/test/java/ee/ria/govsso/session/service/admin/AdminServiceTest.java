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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.OffsetDateTime;
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

        adminService = new AdminService(hydraService, properties, userAgentParserService);
    }

    @Test
    void getSessions_whenSingleSessionSingleService_returnsOneSession() {
        String subject = "subject-1";
        String sessionId = "session-1";
        String userAgent = "ua";
        String os = "Windows";
        String browser = "Chrome";

        OffsetDateTime now = OffsetDateTime.now();

        Consent consent = consent(
                sessionId,
                "client-1",
                now.minusMinutes(10),
                "127.0.0.1",
                userAgent
        );

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

        OffsetDateTime t1 = OffsetDateTime.now().minusMinutes(20);
        OffsetDateTime t2 = OffsetDateTime.now().minusMinutes(5);

        Consent oldConsent = consent(sessionId, "client-1", t1, "127.0.0.1", userAgent);
        Consent newConsent = consent(sessionId, "client-1", t2, "127.0.0.1", userAgent);

        when(hydraService.getConsentsIncludingPartiallyExpired(subject))
                .thenReturn(List.of(oldConsent, newConsent));

        when(userAgentParserService.parse(userAgent))
                .thenReturn(new ParsedUserAgent(os, browser));

        List<Session> sessions = adminService.getSessions(subject);

        assertThat(sessions, hasSize(1));
        assertThat(sessions.get(0).services(), hasSize(1));
        assertThat(sessions.get(0).authenticatedAt(), equalTo(t1));
    }

    @Test
    void getSessions_whenMultipleSessions_returnsMultipleSessions() {
        String subject = "subject-1";
        String os = "Windows";
        String browser = "Chrome";

        Consent s1 = consent("session-1", "client-1",
                OffsetDateTime.now().minusMinutes(30), "127.0.0.1", "ua1");
        Consent s2 = consent("session-2", "client-2",
                OffsetDateTime.now().minusMinutes(10), "127.0.0.2", "ua2");

        when(hydraService.getConsentsIncludingPartiallyExpired(subject))
                .thenReturn(List.of(s1, s2));

        when(userAgentParserService.parse(any()))
                .thenReturn(new ParsedUserAgent(os, browser));

        List<Session> sessions = adminService.getSessions(subject);

        assertThat(sessions, hasSize(2));
    }

    private Consent consent(
            String sessionId,
            String clientId,
            OffsetDateTime requestedAt,
            String ip,
            String userAgent
    ) {
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

        Consent consent = new Consent();
        consent.setConsentRequest(info);
        consent.setRememberFor(600);

        return consent;
    }
}
