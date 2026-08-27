package ee.ria.govsso.session.session;

import ee.ria.govsso.session.util.LocaleUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Locale;
import java.util.Map;

import static java.util.stream.Collectors.toUnmodifiableMap;

@ControllerAdvice
public class ThymeleafSupport {

    public boolean isNotLocale(String code) {
        return !LocaleContextHolder.getLocale().getLanguage().equalsIgnoreCase(code);
    }

    @ModelAttribute("localeUrls")
    public Map<String, String> getLocaleUrls(HttpServletRequest request) {
        return LocaleUtil.SUPPORTED_LOCALES.stream()
                .collect(toUnmodifiableMap(Locale::getLanguage, locale -> getLocaleUrl(request, locale)));
    }

    private String getLocaleUrl(HttpServletRequest request, Locale locale) {
        return UriComponentsBuilder.fromPath(request.getRequestURI())
                .query(request.getQueryString())
                .replaceQueryParam("lang", locale.getLanguage())
                .build()
                .toUriString();
    }
}
