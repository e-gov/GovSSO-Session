package ee.ria.govsso.session.token;

import ee.ria.govsso.session.service.hydra.Context;
import ee.ria.govsso.session.service.hydra.SessionType;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

class AccessTokenClaimsFactoryTest {

    private static final Instant TARA_AUTH_TIME = Instant.parse("2026-10-07T08:00:00Z");
    private static final Instant HYDRA_AUTHENTICATED_AT = Instant.parse("2026-10-07T10:00:00Z");

    private final AccessTokenClaimsFactory accessTokenClaimsFactory = new AccessTokenClaimsFactory();

    @Test
    void from_WhenSecuredAppWebSession_AuthTimeIsTaraAuthTimeOfAuthHandoverInitiatorSession() {
        AccessTokenClaims claims = createClaims(SessionType.SECURED_APP_WEB_SESSION);

        assertThat(claims.getAuthTime(), equalTo(TARA_AUTH_TIME));
    }

    @Test
    void from_WhenSecuredAppSession_AuthTimeIsHydraAuthenticatedAt() {
        AccessTokenClaims claims = createClaims(SessionType.SECURED_APP_SESSION);

        assertThat(claims.getAuthTime(), equalTo(HYDRA_AUTHENTICATED_AT));
    }

    @Test
    void from_WhenWebSession_AuthTimeIsNotSet() {
        AccessTokenClaims claims = createClaims(SessionType.WEB_SESSION);

        assertThat(claims.getAuthTime(), nullValue());
    }

    private AccessTokenClaims createClaims(SessionType sessionType) {
        UserAttributes userAttributes = UserAttributes.builder()
                .subject("EE60001019906")
                .taraAuthTime(TARA_AUTH_TIME)
                .acr("high")
                .amr(List.of("mID"))
                .givenName("TEST")
                .familyName("TEST")
                .birthdate("2000-01-01")
                .build();
        Context context = new Context();
        context.setSessionType(sessionType);
        context.setUserAttributes(userAttributes);
        return accessTokenClaimsFactory.from(userAttributes, List.of("openid"), context, HYDRA_AUTHENTICATED_AT);
    }
}
