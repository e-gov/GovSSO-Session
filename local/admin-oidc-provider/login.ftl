<#--
  Derived from navikt/mock-oauth2-server's MIT-licensed login template.

  Override of the mock-oauth2-server login template used to prefill the editable claims field
  with an example Admin identity. The interactive login form cannot be prefilled through
  config.json, so the initial field value is defined here. The rest follows the standard template.
-->
<#import "main.ftl" as layout />

<@layout.mainLayout title="mock-oauth2-server" description="Just a mock login">
<div class="container">
    <section class="header">
        <h2 class="title">Mock OAuth2 Server Sign-in</h2>
    </section>
    <div class="docs-section" id="sign-in">
        <div class="row">
            <div class="three columns">&nbsp;</div>
            <div class="six columns">
                <form method="post">
                    <label>
                        <input class="u-full-width" required type="text" name="username"
                               placeholder="Enter any user/subject"
                               autofocus="on">
                    </label>
                    <label>
                        <textarea class="u-full-width claims" name="claims" rows="15">{
  "sub": "mock-opaque-oidc-subject",
  "name": "Admin User",
  "given_name": "Admin",
  "family_name": "User",
  "preferred_username": "admin-user",
  "email": "admin.user@example.test",
  "picture": "https://example.test/photo"
}</textarea>
                    </label>
                    <input class="button-primary" type="submit" value="Sign-in">
                </form>
            </div>
            <div class="three columns">&nbsp;</div>
        </div>
    </div>
    <div class="docs-section">
        <div class="row">
            <div class="three columns">&nbsp;</div>
            <div class="six columns">
                <h6 class="docs-header">Authorization Request</h6>
                <#list query as propName, propValue>
                    <div style="text-align: left; color:grey;"><strong>${propName}</strong> = ${propValue}</div>
                </#list>
            </div>
            <div class="three columns">&nbsp;</div>
        </div>
    </div>
</div>
</@layout.mainLayout>
