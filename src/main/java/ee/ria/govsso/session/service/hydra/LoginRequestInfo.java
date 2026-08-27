package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonIgnore;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import jakarta.annotation.Nullable;
import lombok.Data;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.net.URIBuilder;
import org.jspecify.annotations.NonNull;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import static ee.ria.govsso.session.error.ErrorCode.TECHNICAL_GENERAL;
import static ee.ria.govsso.session.error.ErrorCode.USER_INPUT;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class LoginRequestInfo {
    public static final String REQUEST_PARAM_PROMPT = "prompt";
    public static final String REQUEST_PARAM_AUTH_HANOVER_TOKEN = "govsso_auth_handover_token";
    //Models selected fields of https://www.ory.sh/hydra/docs/reference/api/#operation/getLoginRequest, Ory Hydra response is deserialized into this class.

    private String challenge;
    private Client client;
    private String subject;
    private String sessionId;
    private URL requestUrl;
    private String[] requestedScope;
    private OidcContext oidcContext;
    private boolean skip;
    private OffsetDateTime requestedAt;

    // We could call getAcr() directly to validate the ACR values but calling validateAcr() is semantically better.
    public void validateAcr() {
        getAcr();
    }

    @JsonIgnore
    @Nullable
    public LevelOfAssurance getAcr() {
        LevelOfAssurance loginRequestAcr = getLoginRequestAcr();
        LevelOfAssurance clientSettingsAcr = getClientSettingsAcr();
        if (loginRequestAcr != null && clientSettingsAcr != null) {
            if (loginRequestAcr != clientSettingsAcr) {
                throw new SsoException(ErrorCode.USER_INPUT, "Requested acr_values must match configured minimum_acr_value");
            }
        }
        if (loginRequestAcr != null) {
            return loginRequestAcr;
        }
        if (clientSettingsAcr != null) {
            return clientSettingsAcr;
        }
        return null;
    }

    private LevelOfAssurance getLoginRequestAcr() {
        List<String> acrValues = Optional.of(this)
                .map(LoginRequestInfo::getOidcContext)
                .map(OidcContext::getAcrValues)
                .orElse(null);
        if (acrValues == null || acrValues.isEmpty()) {
            return null;
        }
        if (acrValues.size() > 1) {
            throw new SsoException(ErrorCode.USER_INPUT, "acrValues must contain only 1 value");
        }
        String acrName = acrValues.get(0);
        LevelOfAssurance acr = LevelOfAssurance.findByAcrName(acrName);
        if (acr == null) {
            throw new SsoException(ErrorCode.USER_INPUT, "acrValues must be one of low/substantial/high");
        }
        return acr;
    }

    private LevelOfAssurance getClientSettingsAcr() {
        String acrName = Optional.of(this)
                .map(LoginRequestInfo::getClient)
                .map(Client::getMetadata)
                .map(Metadata::getMinimumAcrValue)
                .orElse(null);
        if (acrName == null) {
            return null;
        }
        return LevelOfAssurance.findByAcrName(acrName);
    }

    @JsonIgnore
    public @NonNull Prompt getAndValidatePrompt() {
        String paramValue = getRequestUrlParam(REQUEST_PARAM_PROMPT);
        if(paramValue == null) {
            throw new SsoException(USER_INPUT, "Request URL must contain prompt value");
        }
        Prompt prompt = Prompt.findByName(paramValue);
        if (prompt == null) {
            throw new SsoException(USER_INPUT, "Invalid prompt value");
        }
        return prompt;
    }

    @JsonIgnore
    public String getAuthHandoverToken() {
        return getRequestUrlParam(REQUEST_PARAM_AUTH_HANOVER_TOKEN);
    }

    private String getRequestUrlParam(String paramName) {
        URI uri;
        try {
            uri = requestUrl.toURI();
        } catch (URISyntaxException e) {
            throw new SsoException(TECHNICAL_GENERAL, "Request URL is not a valid URI");
        }
        List<String> values = new URIBuilder(uri).getQueryParams()
                .stream()
                .filter(param -> param.getName().equals(paramName))
                .map(NameValuePair::getValue)
                .toList();
        if (values.isEmpty()) {
            return null;
        }
        if (values.size() > 1) {
            throw new SsoException(USER_INPUT, "Request URL contains more than 1 parameter with name \"" + paramName + "\"");
        }
        return values.get(0);
    }

}
