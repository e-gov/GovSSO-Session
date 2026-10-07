package ee.ria.govsso.session.service.hydra;

import ee.ria.govsso.session.configuration.jackson.InstantAsEpochSeconds;
import lombok.Data;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonNaming;
import tools.jackson.databind.annotation.JsonSerialize;

import java.time.Instant;
import java.util.List;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class LoginSessionInfo {

    private String acr;
    private List<String> amr;
    @JsonSerialize(using = InstantAsEpochSeconds.Serializer.class)
    @JsonDeserialize(using = InstantAsEpochSeconds.Deserializer.class)
    private Instant authTime;
    private String birthdate;
    private String familyName;
    private String givenName;
    private String phoneNumber;
    private Boolean phoneNumberVerified;
    private String subject;
}
