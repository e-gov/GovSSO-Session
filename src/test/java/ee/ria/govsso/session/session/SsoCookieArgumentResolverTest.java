package ee.ria.govsso.session.session;

import ee.ria.govsso.session.configuration.properties.SecurityConfigurationProperties;
import ee.ria.govsso.session.error.exceptions.SsoException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.web.context.request.NativeWebRequest;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Collections;

import static ee.ria.govsso.session.error.ErrorCode.USER_INPUT;
import static ee.ria.govsso.session.session.SsoCookie.COOKIE_NAME_GOVSSO;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SsoCookieArgumentResolverTest {
    private static final String SSO_COOKIE_SIGNING_SECRET = "fec1e8ee45b84f7f66824f7797f759f191c696020f5187744a1a3532935bd5ec";
    private static final String VALID_SSO_COOKIE_VALUE = "eyJhbGciOiJIUzI1NiJ9.eyJ0YXJhX3N0YXRlIjoidGFyYV9zdGF0ZSIsImxvZ2luX2NoYWxsZW5nZSI6ImxvZ2luX2NoYWxsZW5nZSIsInRhcmFfbm9uY2UiOiJ0YXJhX25vbmNlIn0.XJL4TNG5lzjBXvazlqtUe-xFtPXhV193cYEf0TVsaLw";
    private static final String INVALID_SSO_COOKIE_VALUE = "eyJhbGciOiJIUzI1NiJ9.eyJ0YXJhX3N0YXRlIjoidGFyYV9zdGF0ZSIsImxvZ2luX2NoYWxsZW5nZSI6ImxvZ2luX2NoYWxsZW5nZSIsInRhcmFfbm9uY2UiOiJ0YXJhX25vbmNlIn0.XXX";
    private static final MethodParameter mockMethodParameter = mock(MethodParameter.class);
    private static final NativeWebRequest mockNativeWebRequest = mock(NativeWebRequest.class);
    private static final HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);
    private static final SecurityConfigurationProperties securityProperties = new SecurityConfigurationProperties("", SSO_COOKIE_SIGNING_SECRET, 3600, Collections.emptySet());
    private static final SsoCookieArgumentResolver resolver = new SsoCookieArgumentResolver(null, new SsoCookieSigner(securityProperties));

    @BeforeAll
    @SuppressWarnings({"unchecked", "rawtypes"})
    static void setup() {

        when(mockNativeWebRequest.getNativeRequest(HttpServletRequest.class)).thenReturn(mockHttpServletRequest);
        when(mockMethodParameter.getNestedParameterType()).thenReturn((Class) SsoCookie.class);
    }

    @Test
    void resolveName_WhenSsoCookieValueParseAndVerificationSucceeds_ReturnsSsoCookie() throws Exception {
        when(mockHttpServletRequest.getCookies()).thenReturn(new Cookie[]{new Cookie(COOKIE_NAME_GOVSSO, VALID_SSO_COOKIE_VALUE)});

        Object result = resolver.resolveName(COOKIE_NAME_GOVSSO, mockMethodParameter, mockNativeWebRequest);

        assertThat(result, notNullValue());
        assertThat(result, instanceOf(SsoCookie.class));
        SsoCookie ssoCookie = (SsoCookie) result;
        assertThat(ssoCookie.getLoginChallenge(), equalTo("login_challenge"));
        assertThat(ssoCookie.getTaraAuthenticationRequestState(), equalTo("tara_state"));
        assertThat(ssoCookie.getTaraAuthenticationRequestNonce(), equalTo("tara_nonce"));
    }

    @Test
    void resolveName_WhenSsoCookieValueParseAndVerificationFalse_ThrowsUserInputError() {
        when(mockHttpServletRequest.getCookies()).thenReturn(new Cookie[]{new Cookie(COOKIE_NAME_GOVSSO, INVALID_SSO_COOKIE_VALUE)});

        SsoException ex = assertThrows(SsoException.class,
                () -> resolver.resolveName(COOKIE_NAME_GOVSSO, mockMethodParameter, mockNativeWebRequest));

        assertThat(ex.getErrorCode(), equalTo(USER_INPUT));
        assertThat(ex.getMessage(), equalTo("Invalid SsoCookie signature"));
    }
}
