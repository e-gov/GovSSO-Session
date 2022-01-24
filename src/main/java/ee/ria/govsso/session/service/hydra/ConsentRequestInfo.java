package ee.ria.govsso.session.service.hydra;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.Data;

@Data
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class ConsentRequestInfo {

    //Models selected fields of https://www.ory.sh/hydra/docs/reference/api/#operation/getConsentRequest, Ory Hydra response is deserialized into this class.

    private String challenge;
    private String[] requestedScope;
    private Context context;

}
