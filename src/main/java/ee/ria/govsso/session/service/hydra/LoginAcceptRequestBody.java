package ee.ria.govsso.session.service.hydra;

import lombok.Value;

@Value
public class LoginAcceptRequestBody {

    boolean remember;
    String acr;
    String subject;
}
