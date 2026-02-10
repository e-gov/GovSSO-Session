package ee.ria.govsso.session.service.admin;

import ee.ria.govsso.session.configuration.properties.SsoConfigurationProperties;
import ee.ria.govsso.session.service.hydra.Client;
import ee.ria.govsso.session.service.hydra.Consent;
import ee.ria.govsso.session.service.hydra.ConsentRequestInfo;
import ee.ria.govsso.session.service.hydra.HydraService;
import ee.ria.govsso.session.service.hydra.Metadata;
import ee.ria.govsso.session.service.useragent.ParsedUserAgent;
import ee.ria.govsso.session.service.useragent.UserAgentParserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static java.time.OffsetDateTime.now;
import static java.util.Comparator.comparing;
import static java.util.function.BinaryOperator.maxBy;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.groupingBy;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

@Service
@RequiredArgsConstructor
public class AdminService {
    private final HydraService hydraService;
    private final SsoConfigurationProperties ssoConfigurationProperties;
    private final UserAgentParserService userAgentParserService;

    public List<Session> getSessions(String subject) {
        List<Consent> consents = hydraService.getConsentsIncludingPartiallyExpired(subject);
        Map<String, List<Consent>> allConsentsBySessionId = groupBySessionId(consents);
        Map<String, Collection<Consent>> latestConsentsForEachClientIdBySessionId = keepOnlyLatestConsentForEachClientIdAndSessionId(allConsentsBySessionId);

        return latestConsentsForEachClientIdBySessionId.entrySet().stream()
                .map(c -> mapToSession(c.getKey(), c.getValue(), allConsentsBySessionId.get(c.getKey())))
                .toList();
    }

    private Map<String, List<Consent>> groupBySessionId(List<Consent> consents) {
        return consents.stream()
                .collect(groupingBy(c -> c.getConsentRequest().getLoginSessionId(),
                        toList()));
    }

    private Map<String, Collection<Consent>> keepOnlyLatestConsentForEachClientIdAndSessionId(Map<String, List<Consent>> consents) {
        // NOTE: Hydra GET /admin/oauth2/auth/sessions/consent response can contain multiple consent sessions per client, but only
        //  one of them is considered latest and potentially active (requested_at + remember_for >= now())
        //  Such old inactive sessions should be filtered:
        return consents.values().stream()
                .flatMap(List::stream)
                .collect(groupingBy(c -> c.getConsentRequest().getLoginSessionId(),
                        collectingAndThen(
                                toMap(c -> c.getConsentRequest().getClient().getClientId(), identity(),
                                        maxBy(comparing(Consent::getRequestedAt))),
                                Map::values
                        )
                ));
    }

    private Session mapToSession(String sessionId, Collection<Consent> activeConsents, List<Consent> allConsents) {
        List<ServiceSession> serviceSessions = activeConsents.stream()
                .map(this::mapToServiceSession)
                .toList();
        OffsetDateTime authenticatedAt = allConsents.stream()
                .min(comparing(Consent::getRequestedAt))
                .map(Consent::getRequestedAt)
                .orElseThrow();
        List<SessionIpInfo> ipInfos = allConsents.stream()
                .map(this::mapToSessionIpInfo)
                .distinct()
                .toList();
        String userAgent = allConsents.get(0).getConsentRequest().getContext().getUserAgent();
        ParsedUserAgent parsed = userAgentParserService.parse(userAgent);

        return Session.builder()
                .sessionId(sessionId)
                .authenticatedAt(authenticatedAt)
                .ipInfos(ipInfos)
                .userAgent(userAgent)
                .os(parsed.os())
                .browser(parsed.browser())
                .services(serviceSessions)
                .build();
    }

    private ServiceSession mapToServiceSession(Consent c) {
        ConsentRequestInfo consentRequest = c.getConsentRequest();
        Client client = consentRequest.getClient();
        Integer rememberFor = c.getRememberFor();
        OffsetDateTime requestedAt = c.getRequestedAt();
        Metadata metadata = client.getMetadata();
        Map<String, String> clientNames = metadata.getOidcClient().getNameTranslations();
        OffsetDateTime expiresAt = requestedAt.plusSeconds(rememberFor);
        OffsetDateTime lastUpdatedAt = expiresAt.isAfter(now()) ? expiresAt.minusSeconds(ssoConfigurationProperties.getSessionMaxUpdateIntervalInSeconds()) : expiresAt;

        return ServiceSession.builder()
                .authenticatedAt(requestedAt)
                .expiresAt(expiresAt)
                .lastUpdatedAt(lastUpdatedAt)
                .clientNames(clientNames)
                .build();
    }

    private SessionIpInfo mapToSessionIpInfo(Consent consent) {
        var context = consent.getConsentRequest().getContext();
        return new SessionIpInfo(
                context.getIpAddress(),
                context.getIpCountry()
        );
    }
}
