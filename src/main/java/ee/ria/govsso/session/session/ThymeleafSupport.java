package ee.ria.govsso.session.session;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class ThymeleafSupport {

    public boolean isNotLocale(String code) {
        return !LocaleContextHolder.getLocale().getLanguage().equalsIgnoreCase(code);
    }
}
