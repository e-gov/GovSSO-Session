package ee.ria.govsso.session.service.paasuke;

import lombok.Data;

@Data
public class Person {

    private String type;
    private String firstName;
    private String surname;
    private String legalName;
}
