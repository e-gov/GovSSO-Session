package ee.ria.govsso.session.util;

import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.support.RequestContextUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Locale;
import java.util.function.Predicate;

import static java.util.regex.Pattern.compile;

@Slf4j
@UtilityClass
public class LocaleUtil {

    public static final Predicate<String> SUPPORTED_LANGUAGES = compile("(?i)(et|en|ru)").asMatchPredicate();
    public static final String DEFAULT_LOCALE = "et";

    public Locale getLocale() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        LocaleResolver localeResolver = RequestContextUtils.getLocaleResolver(request);
        if (localeResolver == null) {
            return null;
        }
        return localeResolver.resolveLocale(request);
    }

    public void setLocale(LoginRequestInfo loginRequestInfo) {
        String requestedLocale = getDefaultOrRequestedLocale(loginRequestInfo);
        setLocale(requestedLocale);
    }

    public void setLocale(String requestedLocale) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        HttpServletResponse response = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();
        Locale locale = StringUtils.parseLocaleString(requestedLocale);
        LocaleResolver localeResolver = RequestContextUtils.getLocaleResolver(request);
        Assert.notNull(localeResolver, "No LocaleResolver found in request: not in a DispatcherServlet request?");
        localeResolver.setLocale(request, response, locale);
    }

    private String getDefaultOrRequestedLocale(LoginRequestInfo loginRequestInfo) {
        if (loginRequestInfo.getOidcContext() == null) {
            return DEFAULT_LOCALE;
        }

        return loginRequestInfo.getOidcContext().getUiLocales()
                .stream()
                .filter(SUPPORTED_LANGUAGES)
                .findFirst()
                .orElse(DEFAULT_LOCALE);
    }
}
