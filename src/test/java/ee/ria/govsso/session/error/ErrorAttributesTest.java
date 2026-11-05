package ee.ria.govsso.session.error;

import ee.ria.govsso.session.error.exceptions.SsoException;
import jakarta.servlet.RequestDispatcher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.context.MessageSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.Map;

import static ee.ria.govsso.session.error.ErrorAttributes.ERROR_ATTR_ERROR_CODE;
import static ee.ria.govsso.session.error.ErrorAttributes.ERROR_ATTR_ERROR_DESCRIPTION;
import static ee.ria.govsso.session.error.ErrorAttributes.INCLUDE_ERROR_DESCRIPTION;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;

class ErrorAttributesTest {

    private static final String ERROR_MESSAGE = "Test error message";

    private ErrorAttributes errorAttributes;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        MessageSource messageSource = Mockito.mock(MessageSource.class);
        when(messageSource.getMessage(anyString(), isNull(), any())).thenReturn("Translated message");
        errorAttributes = new ErrorAttributes(messageSource);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    @ParameterizedTest
    @EnumSource(value = ErrorCode.class, names = {
            "USER_INPUT",
            "USER_INPUT_OR_EXPIRED",
            "USER_COOKIE_MISSING",
            "USER_INVALID_OIDC_CLIENT",
            "USER_INVALID_OIDC_REQUEST",
            "USER_INVALID_RESOURCE",
            "USER_OIDC_OTHER_ERROR"})
    void getErrorAttributes_whenErrorDescriptionIncludedSsoExceptionHasUserErrorCode_ContainsErrorDescription(ErrorCode errorCode) {
        Map<String, Object> attr = getErrorAttributes(new SsoException(errorCode, ERROR_MESSAGE), errorCode.getHttpStatusCode(), true);

        assertThat(attr)
                .containsEntry(ERROR_ATTR_ERROR_CODE, errorCode.name())
                .containsEntry(ERROR_ATTR_ERROR_DESCRIPTION, ERROR_MESSAGE);
    }

    @ParameterizedTest
    @EnumSource(value = ErrorCode.class, names = {
            "USER_INPUT",
            "USER_INPUT_OR_EXPIRED",
            "USER_COOKIE_MISSING",
            "USER_INVALID_OIDC_CLIENT",
            "USER_INVALID_OIDC_REQUEST",
            "USER_INVALID_RESOURCE",
            "USER_OIDC_OTHER_ERROR"})
    void getErrorAttributes_whenErrorDescriptionNotIncludedSsoExceptionHasUserErrorCode_DoesNotContainErrorDescription(ErrorCode errorCode) {
        Map<String, Object> attr = getErrorAttributes(new SsoException(errorCode, ERROR_MESSAGE), errorCode.getHttpStatusCode(), false);

        assertThat(attr)
                .containsEntry(ERROR_ATTR_ERROR_CODE, errorCode.name())
                .doesNotContainKey(ERROR_ATTR_ERROR_DESCRIPTION);
    }

    @ParameterizedTest
    @EnumSource(value = ErrorCode.class, names = {
            "TECHNICAL_TARA_UNAVAILABLE",
            "TECHNICAL_GENERAL",
            "TECHNICAL_PAASUKE_UNAVAILABLE"})
    void getErrorAttributes_whenErrorDescriptionIncludedSsoExceptionHasTechnicalErrorCode_DoesNotContainErrorDescription(ErrorCode errorCode) {
        Map<String, Object> attr = getErrorAttributes(new SsoException(errorCode, ERROR_MESSAGE), errorCode.getHttpStatusCode(), true);

        assertThat(attr)
                .containsEntry(ERROR_ATTR_ERROR_CODE, errorCode.name())
                .doesNotContainKey(ERROR_ATTR_ERROR_DESCRIPTION);
    }

    @Test
    void getErrorAttributes_whenErrorDescriptionIncludedNonSsoExceptionWithClientErrorStatus_DoesNotContainErrorDescription() {
        Map<String, Object> attr = getErrorAttributes(new IllegalArgumentException(ERROR_MESSAGE), 400, true);

        assertThat(attr)
                .containsEntry(ERROR_ATTR_ERROR_CODE, ErrorCode.USER_INPUT.name())
                .doesNotContainKey(ERROR_ATTR_ERROR_DESCRIPTION);
    }

    private Map<String, Object> getErrorAttributes(Exception exception, int status, boolean includeErrorDescription) {
        request.setAttribute(RequestDispatcher.ERROR_STATUS_CODE, status);
        if (includeErrorDescription) {
            request.setAttribute(INCLUDE_ERROR_DESCRIPTION, true);
        }
        errorAttributes.resolveException(request, response, null, exception);
        return errorAttributes.getErrorAttributes(new ServletWebRequest(request), ErrorAttributeOptions.defaults());
    }
}
