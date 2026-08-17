package ee.ria.govsso.session.token;

import com.fasterxml.jackson.annotation.JsonInclude;
import ee.ria.govsso.session.configuration.jackson.InstantAsEpochSeconds;
import ee.ria.govsso.session.service.hydra.ClientType;
import ee.ria.govsso.session.service.hydra.Representee;
import lombok.Builder;
import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;

import java.time.Instant;

@Data
@Builder
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AccessTokenClaims {

    private String acr;
    private String[] amr;
    private String givenName;
    private String familyName;
    private String birthdate;
    private String phoneNumber;
    private Boolean phoneNumberVerified;
    private Representee representee;
    private ClientType initiator;
    @JsonSerialize(using = InstantAsEpochSeconds.Serializer.class)
    @JsonDeserialize(using = InstantAsEpochSeconds.Deserializer.class)
    private Instant authTime;
    @JsonSerialize(using = InstantAsEpochSeconds.Serializer.class)
    @JsonDeserialize(using = InstantAsEpochSeconds.Deserializer.class)
    private Instant sessionExpiry;

}
