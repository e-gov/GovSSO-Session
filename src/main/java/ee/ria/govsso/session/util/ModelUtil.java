package ee.ria.govsso.session.util;

import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import lombok.experimental.UtilityClass;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.web.servlet.ModelAndView;

import java.net.URISyntaxException;

@UtilityClass
public class ModelUtil {


    public void addSelfServiceUrlToModel(ModelAndView model, String selfServiceUrl) {
        try {
            if(StringUtils.isNotBlank(selfServiceUrl)) {
                model.addObject("selfServiceUrl",
                        new URIBuilder(selfServiceUrl)
                                .addParameter("lang", LocaleUtil.getLocale().getLanguage())
                                .build()
                                .toString());
            }
        } catch (URISyntaxException e) {
            throw new SsoException(ErrorCode.TECHNICAL_GENERAL, "Failed to build self service URL");
        }
    }

}
