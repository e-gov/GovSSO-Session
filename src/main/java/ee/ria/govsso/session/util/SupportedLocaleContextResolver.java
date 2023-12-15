package ee.ria.govsso.session.util;

import lombok.NonNull;
import org.springframework.context.i18n.LocaleContext;
import org.springframework.context.i18n.SimpleLocaleContext;
import org.springframework.web.servlet.LocaleContextResolver;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Locale;
import java.util.Set;

/**
 * Limits locale to one of supported locales.
 */
public class SupportedLocaleContextResolver implements LocaleContextResolver {

    private static final String LOCALE_EXPLICITLY_SET_ATTRIBUTE_NAME = SupportedLocaleContextResolver.class.getName() + ".LOCALE_EXPLICITLY_SET";

    private final LocaleContextResolver delegate;
    private final Set<Locale> supportedLocales;
    private final Locale defaultLocale;
    private final SimpleLocaleContext defaultLocaleContext;

    public SupportedLocaleContextResolver(@NonNull LocaleContextResolver delegate, @NonNull Set<Locale> supportedLocales, @NonNull Locale defaultLocale) {
        this.delegate = delegate;
        this.supportedLocales = supportedLocales;
        this.defaultLocale = defaultLocale;
        defaultLocaleContext = new SimpleLocaleContext(defaultLocale);
    }

    @Override
    public LocaleContext resolveLocaleContext(HttpServletRequest request) {
        LocaleContext localeContext = delegate.resolveLocaleContext(request);
        Locale locale = localeContext.getLocale();
        if (!supportedLocales.contains(locale)) {
            return defaultLocaleContext;
        }
        return localeContext;
    }

    @Override
    public Locale resolveLocale(HttpServletRequest request) {
        Locale locale = delegate.resolveLocale(request);
        if (!supportedLocales.contains(locale)) {
            return defaultLocale;
        }
        return locale;
    }

    @Override
    public void setLocaleContext(HttpServletRequest request, HttpServletResponse response, LocaleContext localeContext) {
        if (localeContext != null && supportedLocales.contains(localeContext.getLocale())) {
            delegate.setLocaleContext(request, response, localeContext);
            request.setAttribute(LOCALE_EXPLICITLY_SET_ATTRIBUTE_NAME, Boolean.TRUE);
        }
    }

    @Override
    public void setLocale(HttpServletRequest request, HttpServletResponse response, Locale locale) {
        if (supportedLocales.contains(locale)) {
            delegate.setLocale(request, response, locale);
            request.setAttribute(LOCALE_EXPLICITLY_SET_ATTRIBUTE_NAME, Boolean.TRUE);
        }
    }

    public static boolean isLocaleExplicitlySet(HttpServletRequest request) {
        return Boolean.TRUE.equals(request.getAttribute(LOCALE_EXPLICITLY_SET_ATTRIBUTE_NAME));
    }

}
