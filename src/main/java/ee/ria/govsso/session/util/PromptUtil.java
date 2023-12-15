package ee.ria.govsso.session.util;

import ee.ria.govsso.session.error.exceptions.SsoException;
import ee.ria.govsso.session.service.hydra.Prompt;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.net.URIBuilder;
import org.springframework.util.CollectionUtils;

import java.net.URL;
import java.util.List;

import static ee.ria.govsso.session.error.ErrorCode.USER_INPUT;

@UtilityClass
public class PromptUtil {

    // TODO: maybe split to value getter util and validator
    @SneakyThrows
    public static Prompt getAndValidatePromptFromRequestUrl(URL requestUrl) {
        List<NameValuePair> promptValues = new URIBuilder(requestUrl.toString())
                .getQueryParams()
                .stream()
                .filter(param -> param.getName().equals("prompt"))
                .toList();

        if (CollectionUtils.isEmpty(promptValues)) {
            throw new SsoException(USER_INPUT, "Request URL must contain prompt value");
        }

        if (promptValues.size() > 1) {
            throw new SsoException(USER_INPUT, "Request URL contains more than 1 prompt values");
        }

        Prompt prompt = Prompt.findByName(promptValues.get(0).getValue());
        if (prompt == null) {
            throw new SsoException(USER_INPUT, "Invalid prompt value");
        }
        return prompt;
    }
}
