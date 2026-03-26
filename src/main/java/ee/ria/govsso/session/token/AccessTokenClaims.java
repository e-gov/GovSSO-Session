package ee.ria.govsso.session.token;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import ee.ria.govsso.session.configuration.jackson.InstantAsTimestamp;
import ee.ria.govsso.session.service.hydra.ClientType;
import ee.ria.govsso.session.service.hydra.Representee;
import lombok.Builder;
import lombok.Data;

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
    @JsonSerialize(using = InstantAsTimestamp.Serializer.class)
    @JsonDeserialize(using = InstantAsTimestamp.Deserializer.class)
    private Instant authTime;

}
