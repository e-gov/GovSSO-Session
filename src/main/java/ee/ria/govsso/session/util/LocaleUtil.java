package ee.ria.govsso.session.util;

import ee.ria.govsso.session.service.hydra.Client;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.hydra.LogoutRequestInfo;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.net.URIBuilder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.support.RequestContextUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

import static java.util.regex.Pattern.compile;

@Slf4j
@UtilityClass
public class LocaleUtil {

    public static final Locale LOCALE_ESTONIAN = new Locale("et");
    public static final Locale LOCALE_RUSSIAN = new Locale("ru");

    public static final Locale DEFAULT_LOCALE = LOCALE_ESTONIAN;
    public static final Set<Locale> SUPPORTED_LOCALES = Set.of(
            LOCALE_ESTONIAN,
            Locale.ENGLISH,
            LOCALE_RUSSIAN);

    public static final String DEFAULT_LANGUAGE = "et";
    private static final Predicate<String> SUPPORTED_LANGUAGES = compile("(?i)(et|en|ru)").asMatchPredicate();

    public Locale getLocale() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        LocaleResolver localeResolver = RequestContextUtils.getLocaleResolver(request);
        if (localeResolver == null) {
            return DEFAULT_LOCALE;
        }
        return localeResolver.resolveLocale(request);
    }

    /*
     * 1) If request parameter `lang` has successfully set a valid locale (LocaleChangeInterceptor calls
     *    localeResolver.setLocale), then don't perform additional steps.
     * 2) Try setting locale based on Hydra request parameter `ui_locales`.
     * 3) Fall back to locale parsed from cookie (CookieLocaleResolver), if it is valid.
     * 4) Fall back to default locale (configured with CookieLocaleResolver).
     */

    public void setLocaleIfUnset(HttpServletRequest request, HttpServletResponse response, LoginRequestInfo loginRequestInfo) {
        if (!SupportedLocaleContextResolver.isLocaleExplicitlySet(request)) {
            String locale = getFirstSupportedLocale(loginRequestInfo);
            setLocale(request, response, locale);
        }
    }

    public void setLocaleIfUnset(HttpServletRequest request, HttpServletResponse response, LogoutRequestInfo logoutRequestInfo) {
        if (!SupportedLocaleContextResolver.isLocaleExplicitlySet(request)) {
            String locale = getFirstSupportedLocale(logoutRequestInfo);
            setLocale(request, response, locale);
        }
    }

    private void setLocale(HttpServletRequest request, HttpServletResponse response, String requestedLocale) {
        if (requestedLocale == null) {
            return;
        }
        Locale locale = StringUtils.parseLocaleString(requestedLocale);
        LocaleResolver localeResolver = RequestContextUtils.getLocaleResolver(request);

        Assert.notNull(localeResolver, "No LocaleResolver found in request: not in a DispatcherServlet request?");
        localeResolver.setLocale(request, response, locale);
    }

    private String getFirstSupportedLocale(LoginRequestInfo loginRequestInfo) {
        if (loginRequestInfo.getOidcContext() == null || loginRequestInfo.getOidcContext().getUiLocales() == null) {
            return null;
        }

        List<String> locales = loginRequestInfo.getOidcContext().getUiLocales();
        return getFirstSupportedLocale(locales);
    }

    private String getFirstSupportedLocale(LogoutRequestInfo logoutRequestInfo) {
        String[] locales = logoutRequestInfo.getUiLocales();
        if (ArrayUtils.isEmpty(locales)) {
            return null;
        }
        return getFirstSupportedLocale(Arrays.asList(locales));
    }

    private String getFirstSupportedLocale(List<String> locales) {
        return locales.stream()
                .filter(Objects::nonNull)
                .filter(SUPPORTED_LANGUAGES)
                .findFirst()
                .map(locale -> locale.toLowerCase(Locale.ROOT))
                .orElse(null);
    }

    public String getTranslatedClientName(Client client) {
        Locale locale = getLocale();

        Map<String, String> nameTranslations = client.getMetadata().getOidcClient().getNameTranslations();
        String translatedName = nameTranslations.get(DEFAULT_LANGUAGE);
        if (nameTranslations.containsKey(locale.getLanguage()))
            translatedName = nameTranslations.get(locale.getLanguage());
        return translatedName;
    }
}
