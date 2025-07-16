package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import ee.ria.govsso.session.error.ErrorCode;
import ee.ria.govsso.session.error.exceptions.SsoException;
import jakarta.annotation.Nullable;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;

import java.net.URL;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class LoginRequestInfo {
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
        if (StringUtils.isEmpty(acrName)) {
            return null; //I'd rather treat this as an error but let's keep existing behaviour for now.
        }
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

}
