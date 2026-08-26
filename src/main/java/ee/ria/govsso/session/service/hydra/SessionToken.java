package ee.ria.govsso.session.service.hydra;

import com.nimbusds.jwt.JWT;
import ee.ria.govsso.session.token.UserAttributes;

public record SessionToken(
        SessionType sessionType,
        JWT token,
        UserAttributes userAttributes
) {}
