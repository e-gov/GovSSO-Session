package ee.ria.govsso.session.service.hydra;

import ee.ria.govsso.session.error.exceptions.SsoException;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.URL;

import static ee.ria.govsso.session.error.ErrorCode.USER_INPUT;
import static ee.ria.govsso.session.error.exceptions.SsoExceptionConditions.errorCode;
import static ee.ria.govsso.session.service.hydra.LoginRequestInfo.REQUEST_PARAM_AUTH_HANOVER_TOKEN;
import static ee.ria.govsso.session.service.hydra.LoginRequestInfo.REQUEST_PARAM_PROMPT;
import static ee.ria.govsso.session.service.hydra.Prompt.CONSENT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;


class LoginRequestInfoTest {

    @Nested
    public class GetAndValidatePrompt {

        public static final String BASE_URL = "https://govsso";

        @Test
        void whenPromptMissing_throwsException() {
            LoginRequestInfo loginRequestInfo = createLoginRequestInfo(BASE_URL);
            assertThatExceptionOfType(SsoException.class)
                    .isThrownBy(loginRequestInfo::getAndValidatePrompt)
                    .has(errorCode(USER_INPUT))
                    .withMessage("Request URL must contain prompt value");
        }

        @Test
        void whenMultiplePromptParams_throwsException() {
            LoginRequestInfo loginRequestInfo =
                    createLoginRequestInfo(BASE_URL + "?" + REQUEST_PARAM_PROMPT + "&" + REQUEST_PARAM_PROMPT);
            assertThatExceptionOfType(SsoException.class)
                    .isThrownBy(loginRequestInfo::getAndValidatePrompt)
                    .has(errorCode(USER_INPUT))
                    .withMessage("Request URL contains more than 1 parameter with name \"prompt\"");
        }

        @Test
        void whenPromptValueUndefined_throwsException() {
            LoginRequestInfo loginRequestInfo = createLoginRequestInfo(BASE_URL + "?" + REQUEST_PARAM_PROMPT);
            assertThatExceptionOfType(SsoException.class)
                    .isThrownBy(loginRequestInfo::getAndValidatePrompt)
                    .has(errorCode(USER_INPUT))
                    .withMessage("Request URL must contain prompt value");
        }

        @Test
        void whenPromptValueEmpty_throwsException() {
            LoginRequestInfo loginRequestInfo = createLoginRequestInfo(BASE_URL + "?" + REQUEST_PARAM_PROMPT + "=");
            assertThatExceptionOfType(SsoException.class)
                    .isThrownBy(loginRequestInfo::getAndValidatePrompt)
                    .has(errorCode(USER_INPUT))
                    .withMessage("Invalid prompt value");
        }

        @Test
        void whenPromptValueUnknown_throwsException() {
            LoginRequestInfo loginRequestInfo =
                    createLoginRequestInfo(BASE_URL + "?" + REQUEST_PARAM_PROMPT + "=not-a-valid-prompt-value");
            assertThatExceptionOfType(SsoException.class)
                    .isThrownBy(loginRequestInfo::getAndValidatePrompt)
                    .has(errorCode(USER_INPUT))
                    .withMessage("Invalid prompt value");
        }

        @Test
        void whenPromptValueValid_returnsEnumValue() {
            LoginRequestInfo loginRequestInfo =
                    createLoginRequestInfo(BASE_URL + "?" + REQUEST_PARAM_PROMPT + "=consent");
            assertThat(loginRequestInfo.getAndValidatePrompt())
                    .isEqualTo(CONSENT);
        }

        @Test
        void whenPromptValueValidWithEncodedSymbols_returnsEnumValue() {
            LoginRequestInfo loginRequestInfo =
                    createLoginRequestInfo(BASE_URL + "?" + REQUEST_PARAM_PROMPT + "=%63onsent");
            assertThat(loginRequestInfo.getAndValidatePrompt())
                    .isEqualTo(CONSENT);
        }


        @SneakyThrows
        LoginRequestInfo createLoginRequestInfo(String requestUrl) {
            LoginRequestInfo loginRequestInfo = new LoginRequestInfo();
            loginRequestInfo.setRequestUrl(new URL(requestUrl));
            return loginRequestInfo;
        }

    }
    
    @Nested
    public class GetAuthHandoverToken {

        public static final String BASE_URL = "https://govsso";

        @Test
        void whenAuthHandoverTokenMissing_returnsNull() {
            LoginRequestInfo loginRequestInfo = createLoginRequestInfo(BASE_URL);
            assertThat(loginRequestInfo.getAuthHandoverToken()).isNull();
        }

        @Test
        void whenMultipleAuthHandoverTokenParams_throwsException() {
            LoginRequestInfo loginRequestInfo = createLoginRequestInfo(
                    BASE_URL + "?" + REQUEST_PARAM_AUTH_HANOVER_TOKEN + "&" + REQUEST_PARAM_AUTH_HANOVER_TOKEN);
            assertThatExceptionOfType(SsoException.class)
                    .isThrownBy(loginRequestInfo::getAuthHandoverToken)
                    .has(errorCode(USER_INPUT))
                    .withMessage("Request URL contains more than 1 parameter with name \"" + REQUEST_PARAM_AUTH_HANOVER_TOKEN + "\"");
        }

        @Test
        void whenAuthHandoverTokenValueUndefined_returnsNull() {
            LoginRequestInfo loginRequestInfo =
                    createLoginRequestInfo(BASE_URL + "?" + REQUEST_PARAM_AUTH_HANOVER_TOKEN);
            assertThat(loginRequestInfo.getAuthHandoverToken()).isNull();
        }

        @Test
        void whenAuthHandoverTokenValueEmpty_returnsEmptyString() {
            LoginRequestInfo loginRequestInfo =
                    createLoginRequestInfo(BASE_URL + "?" + REQUEST_PARAM_AUTH_HANOVER_TOKEN + "=");
            assertThat(loginRequestInfo.getAuthHandoverToken()).isEqualTo("");
        }

        @Test
        void whenAuthHandoverTokenValueSet_returnsThatValue() {
            String expected = "expected-token-value";
            LoginRequestInfo loginRequestInfo =
                    createLoginRequestInfo(BASE_URL + "?" + REQUEST_PARAM_AUTH_HANOVER_TOKEN + "=" + expected);
            assertThat(loginRequestInfo.getAuthHandoverToken()).isEqualTo(expected);
        }

        @Test
        void whenAuthHandoverTokenValueEncoded_returnsUnencodedValue() {
            LoginRequestInfo loginRequestInfo =
                    createLoginRequestInfo(BASE_URL + "?" + REQUEST_PARAM_AUTH_HANOVER_TOKEN + "=ab%63d");
            assertThat(loginRequestInfo.getAuthHandoverToken()).isEqualTo("abcd");
        }

        @SneakyThrows
        LoginRequestInfo createLoginRequestInfo(String requestUrl) {
            LoginRequestInfo loginRequestInfo = new LoginRequestInfo();
            loginRequestInfo.setRequestUrl(new URL(requestUrl));
            return loginRequestInfo;
        }

    }

}
