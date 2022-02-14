package ee.ria.govsso.session.session;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponents;

import java.util.Locale;

@Slf4j
@Component
public class ThymeleafSupport {

    public boolean isNotLocale(String code, Locale locale) {
        return !locale.getLanguage().equalsIgnoreCase(code);
    }

    public String getLocaleUrl(String locale) {
        UriComponents uriComponents = ServletUriComponentsBuilder.fromCurrentRequest().replaceQueryParam("lang", locale).build();
        return uriComponents.getPath() + "?" + uriComponents.getQuery();
    }
}
