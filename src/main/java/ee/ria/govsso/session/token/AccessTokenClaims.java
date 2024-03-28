package ee.ria.govsso.session.token;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Builder;
import lombok.Data;

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

}
