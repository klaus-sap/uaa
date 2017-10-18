package org.cloudfoundry.identity.uaa.login;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import org.cloudfoundry.identity.uaa.mfa_provider.UserGoogleMfaCredentialsProvisioning;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.security.web.CookieBasedCsrfTokenRepository;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.servlet.http.Cookie;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

public class TotpEndpointMockMvcTests extends InjectedMockContextTest{

    private String adminToken;
    private UserGoogleMfaCredentialsProvisioning userGoogleMfaCredentialsProvisioning;
    private JdbcScimUserProvisioning userProvisioning;

    @Before
    public void setup() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken("admin", "adminsecret",
                "clients.read clients.write clients.secret clients.admin uaa.admin");
        userProvisioning = getWebApplicationContext().getBean(JdbcScimUserProvisioning.class);
        userGoogleMfaCredentialsProvisioning = (UserGoogleMfaCredentialsProvisioning) getWebApplicationContext().getBean("userGoogleMfaCredentialsProvisioning");
    }

    @Test
    public void testQRCodeGetsSubmitted() throws Exception {
        ScimUser user = new ScimUser(null, new RandomValueStringGenerator(5).generate(), "first", "last");

        String password = "sec3Tas";
        user.setPrimaryEmail(user.getUserName());
        user.setPassword(password);
        user = createUser(user);

        MockHttpSession session = new MockHttpSession();
        String csrfValue = "12345";
        Cookie csrfCookie = new Cookie(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrfValue);
        MockHttpServletRequestBuilder validPost = post("/uaa/login.do")
                .session(session)
                .contextPath("/uaa")
                .param("username", user.getUserName())
                .param("password", user.getPassword())
                .cookie(csrfCookie)
                .param(CookieBasedCsrfTokenRepository.DEFAULT_CSRF_COOKIE_NAME, csrfValue);
        Cookie jsessionid = getMockMvc().perform(validPost)
                .andDo(print())
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/uaa/")).andReturn().getResponse().getCookie("JSESSIONID");

        getMockMvc().perform(get("/uaa/totp_qr_code")
            .cookie(jsessionid, csrfCookie)
            .contextPath("/uaa")).andReturn();

        List<ScimUser> scimUsers = userProvisioning.query("userName eq \"" + user.getUserName() + "\"", IdentityZoneHolder.get().getId());
        String secretKey = userGoogleMfaCredentialsProvisioning.retrieve(scimUsers.get(0).getId()).getSecretKey();
        GoogleAuthenticator authenticator = new GoogleAuthenticator(new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder().build());
       int code = authenticator.getTotpPassword(secretKey);

        getMockMvc().perform(post("/uaa/totp_qr_code.do")
                .param("code", Integer.toString(code))
                .cookie(jsessionid, csrfCookie)
                .contextPath("/uaa"))
                .andExpect(view().name("/home"))
                .andReturn();
    }

    private ScimUser createUser(ScimUser user) throws Exception{
        return MockMvcUtils.createUser(getMockMvc(), adminToken, user);
    }
}
