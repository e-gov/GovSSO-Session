package ee.ria.govsso.session.util;

import ee.ria.govsso.session.service.hydra.Client;
import ee.ria.govsso.session.service.hydra.LoginRequestInfo;
import ee.ria.govsso.session.service.hydra.LogoutRequestInfo;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.support.RequestContextUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDate;
import java.time.chrono.IsoChronology;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.FormatStyle;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Predicate;

import static java.util.regex.Pattern.compile;

@Slf4j
@UtilityClass
public class LocaleUtil {

    private static final Predicate<String> SUPPORTED_LANGUAGES = compile("(?i)(et|en|fr)").asMatchPredicate();
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
        String requestedLocale = getFirstSupportedOrDefaultLocale(loginRequestInfo);
        setLocale(requestedLocale);
    }

    public void setLocale(LogoutRequestInfo logoutRequestInfo) {
        String requestedLocale = getFirstSupportedOrDefaultLocale(logoutRequestInfo);
        setLocale(requestedLocale);
    }

    private void setLocale(String requestedLocale) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        HttpServletResponse response = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();
        Locale locale = StringUtils.parseLocaleString(requestedLocale);
        LocaleResolver localeResolver = RequestContextUtils.getLocaleResolver(request);
        Assert.notNull(localeResolver, "No LocaleResolver found in request: not in a DispatcherServlet request?");
        localeResolver.setLocale(request, response, locale);
    }

    private String getFirstSupportedOrDefaultLocale(LoginRequestInfo loginRequestInfo) {
        if (loginRequestInfo.getOidcContext() == null) {
            return DEFAULT_LOCALE;
        }

        return getFirstSupportedOrDefaultLocale(loginRequestInfo.getOidcContext().getUiLocales());
    }

    private String getFirstSupportedOrDefaultLocale(LogoutRequestInfo logoutRequestInfo) {
        NameValuePair localeParameter = getHydraRequestUrlLocaleParameter(logoutRequestInfo.getRequestUrl());
        if (localeParameter == null) {
            return DEFAULT_LOCALE;
        }

        return getFirstSupportedOrDefaultLocale(List.of(localeParameter.getValue().split(" ")));
    }

    private String getFirstSupportedOrDefaultLocale(List<String> locales) {
        return locales.stream()
                .filter(SUPPORTED_LANGUAGES)
                .findFirst()
                .orElse(DEFAULT_LOCALE);
    }

    public String getTranslatedClientName(Client client) {
        Locale locale = getLocale();

        Map<String, String> nameTranslations = client.getMetadata().getOidcClient().getNameTranslations();
        String translatedName = nameTranslations.get(DEFAULT_LOCALE);
        if (nameTranslations.containsKey(locale.getLanguage()))
            translatedName = nameTranslations.get(locale.getLanguage());
        return translatedName;
    }

    public String formatDateWithLocale(String dateString) {
        LocalDate localDate = LocalDate.parse(dateString);

        String formatPattern = DateTimeFormatterBuilder.getLocalizedDateTimePattern(
                FormatStyle.SHORT,
                null,
                IsoChronology.INSTANCE,
                getLocale());
        // Let other date components use short style, but year must use long style.
        formatPattern = formatPattern.replaceAll("\\byy\\b", "yyyy");
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(formatPattern, getLocale());

        return localDate.format(formatter);
    }

    @SneakyThrows
    private NameValuePair getHydraRequestUrlLocaleParameter(String requestUrl) {
        NameValuePair localeParameter = new URIBuilder(requestUrl).getQueryParams()
                .stream()
                .filter(x -> x.getName().equals("ui_locales"))
                .findFirst()
                .orElse(null);

        return localeParameter;
    }
}
