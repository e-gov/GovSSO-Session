package ee.ria.govsso.session.util;

import lombok.experimental.UtilityClass;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.support.RequestContextUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Locale;

@UtilityClass
public class RequestUtil {

    public Locale getLocale() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        LocaleResolver localeResolver = RequestContextUtils.getLocaleResolver(request);
        if (localeResolver == null) {
            return null;
        }
        return localeResolver.resolveLocale(request);
    }

    public void setLocale(String requestedLocale) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        HttpServletResponse response = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();
        Locale locale = org.springframework.util.StringUtils.parseLocaleString(requestedLocale);
        LocaleResolver localeResolver = RequestContextUtils.getLocaleResolver(request);
        Assert.notNull(localeResolver, "No LocaleResolver found in request: not in a DispatcherServlet request?");
        localeResolver.setLocale(request, response, locale);
    }
}
