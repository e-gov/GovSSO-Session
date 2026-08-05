package ee.ria.govsso.session.service.helper;

public class ClientScopes {
    public static final String SCOPE_OPENID = "openid";
    public static final String SCOPE_EMAIL = "email";
    public static final String SCOPE_PHONE = "phone";
    public static final String SCOPE_IDCARD = "idcard";
    public static final String SCOPE_MID = "mid";
    public static final String SCOPE_SMARTID = "smartid";
    public static final String SCOPE_EIDAS = "eidas";
    public static final String SCOPE_EIDAS_ONLY = "eidasonly";
    public static final String SCOPE_REPRESENTEE = "representee.*";
    public static final String SCOPE_REPRESENTEE_LIST = "representee_list";
    public static final String SCOPE_AUTH_HANDOVER = "auth_handover";

    private ClientScopes() {}
}
