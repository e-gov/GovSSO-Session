package ee.ria.govsso.session.token;

import com.nimbusds.jwt.JWTClaimsSet;
import ee.ria.govsso.session.service.hydra.LoginSessionInfo;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

class UserAttributesFactoryTest {

    private final UserAttributesFactory userAttributesFactory = new UserAttributesFactory();

    @Test
    void fromAuthHandoverToken_UsesLoginSessionInfoForUserAttributes() throws ParseException {
        Instant authHandoverTime = Instant.parse("2026-10-07T10:00:00Z");
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("EE38001085718")
                .issueTime(Date.from(authHandoverTime))
                .claim("auth_time", Date.from(Instant.parse("2026-10-07T09:00:00Z")).getTime() / 1000)
                .claim("acr", "low")
                .claim("amr", List.of("idcard"))
                .claim("given_name", "TOKEN GIVEN")
                .claim("family_name", "TOKEN FAMILY")
                .claim("birthdate", "1999-12-31")
                .claim("phone_number", "+37200000000")
                .claim("phone_number_verified", false)
                .build();
        Instant sessionAuthTime = Instant.parse("2026-10-07T08:00:00Z");
        LoginSessionInfo loginSessionInfo = new LoginSessionInfo();
        loginSessionInfo.setSubject("EE60001019906");
        loginSessionInfo.setAuthTime(sessionAuthTime);
        loginSessionInfo.setAcr("high");
        loginSessionInfo.setAmr(List.of("mID"));
        loginSessionInfo.setGivenName("MARY ÄNN");
        loginSessionInfo.setFamilyName("O'CONNEŽ-ŠUSLIK");
        loginSessionInfo.setBirthdate("2000-01-01");
        loginSessionInfo.setPhoneNumber("+37200000766");
        loginSessionInfo.setPhoneNumberVerified(true);

        UserAttributes userAttributes = userAttributesFactory.fromAuthHandoverToken(claims, loginSessionInfo);

        assertThat(userAttributes.subject(), is("EE60001019906"));
        assertThat(userAttributes.authHandoverTime(), is(authHandoverTime));
        assertThat(userAttributes.taraAuthTime(), is(sessionAuthTime));
        assertThat(userAttributes.acr(), is("high"));
        assertThat(userAttributes.amr(), equalTo(List.of("mID")));
        assertThat(userAttributes.givenName(), is("MARY ÄNN"));
        assertThat(userAttributes.familyName(), is("O'CONNEŽ-ŠUSLIK"));
        assertThat(userAttributes.birthdate(), is("2000-01-01"));
        assertThat(userAttributes.phoneNumber(), is("+37200000766"));
        assertThat(userAttributes.phoneNumberVerified(), is(true));
    }
}
