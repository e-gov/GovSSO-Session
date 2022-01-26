package ee.ria.govsso.session.session;

import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.core.MethodParameter;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ServletCookieValueMethodArgumentResolver;

@Slf4j
public class SsoCookieArgumentResolver extends ServletCookieValueMethodArgumentResolver {

    private final SsoCookieSigner ssoCookieSigner;

    public SsoCookieArgumentResolver(ConfigurableBeanFactory beanFactory, SsoCookieSigner ssoCookieSigner) {
        super(beanFactory);
        this.ssoCookieSigner = ssoCookieSigner;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(SsoCookieValue.class);
    }

    @Override
    @NonNull
    protected NamedValueInfo createNamedValueInfo(MethodParameter parameter) {
        SsoCookieValue annotation = parameter.getParameterAnnotation(SsoCookieValue.class);
        Assert.notNull(annotation, "No SsoCookieValue annotation");
        return new SsoCookieValueNamedValueInfo(annotation);
    }

    @Override
    @Nullable
    protected Object resolveName(@NonNull String cookieName, @NonNull MethodParameter parameter, @NonNull NativeWebRequest webRequest) throws Exception {
        Object cookie = super.resolveName(cookieName, parameter, webRequest);
        if (cookie instanceof String cookieValue) {
            return ssoCookieSigner.parseAndVerifyCookie(cookieValue);
        } else {
            return null;
        }
    }

    @Override
    protected void handleMissingValue(@Nullable String name, @Nullable MethodParameter parameter) {
        throw new SsoException(ErrorCode.USER_COOKIE_MISSING, "Missing or expired cookie");
    }

    private static final class SsoCookieValueNamedValueInfo extends NamedValueInfo {

        @SuppressWarnings("unused")
        private SsoCookieValueNamedValueInfo(SsoCookieValue annotation) {
            super(SsoCookie.COOKIE_NAME_GOVSSO, true, null);
        }
    }
}
