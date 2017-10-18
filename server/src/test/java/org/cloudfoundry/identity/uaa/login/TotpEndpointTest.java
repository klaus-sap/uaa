package org.cloudfoundry.identity.uaa.login;


import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mfa_provider.UserGoogleMfaCredentialsProvisioning;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.ui.Model;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TotpEndpointTest {
    private String userId;
    private TotpEndpoint endpoint = new TotpEndpoint();
    private GoogleAuthenticator authenticator = spy(GoogleAuthenticator.class);
    private UserGoogleMfaCredentialsProvisioning userGoogleMfaCredentialsProvisioning;
    private UaaAuthentication uaaAuthentication;


    @Rule
    public ExpectedException expection = ExpectedException.none();

    @Before
    public void setup() {
        userGoogleMfaCredentialsProvisioning = mock(UserGoogleMfaCredentialsProvisioning.class);
        endpoint.setUserGoogleMfaCredentialsProvisioning(userGoogleMfaCredentialsProvisioning);
        userId = new RandomValueStringGenerator(5).generate();
        endpoint.setAuthenticator(authenticator);
        uaaAuthentication = mock(UaaAuthentication.class);
    }

    @Test
    public void testCreateCredentials() {
        endpoint.createCredentials(userId);

        verify(authenticator, times(1)).createCredentials(userId);
    }

    @Test
    public void testGenerateQrUrl() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        when(userGoogleMfaCredentialsProvisioning.userCredentialExists(userId)).thenReturn(false);

        String returnView = endpoint.generateQrUrl(mock(Model.class), uaaAuthentication);

        assertEquals("qr_code", returnView);
    }

    @Test
    public void testGenerateQrUrlForNewUserRegistration() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        when(userGoogleMfaCredentialsProvisioning.userCredentialExists(userId)).thenReturn(true);

        String returnView = endpoint.generateQrUrl(mock(Model.class), uaaAuthentication);

        assertEquals("enter_code", returnView);
    }

    @Test
    public void testValidOTPTakesToHomePage() throws Exception{
        authenticator = mock(GoogleAuthenticator.class);
        endpoint.setAuthenticator(authenticator);
        int code = 1234;
        when(authenticator.authorizeUser(userId, code)).thenReturn(true);
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);

        String returnView = endpoint.validateCode(mock(Model.class), uaaAuthentication, Integer.toString(code));

        assertEquals("home", returnView);
    }

    @Test
    public void testInvalidOTPReturnsError() throws Exception{
        authenticator = mock(GoogleAuthenticator.class);
        endpoint.setAuthenticator(authenticator);
        int code = 1234;
        when(authenticator.authorizeUser(userId, code)).thenReturn(false);
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        String returnView = endpoint.validateCode(mock(Model.class), uaaAuthentication, Integer.toString(code));

        assertEquals("enter_code", returnView);
    }

    @Test
    public void testValidateCodeThrowsException() throws Exception{
        authenticator = mock(GoogleAuthenticator.class);
        endpoint.setAuthenticator(authenticator);
        int code = 1234;
        when(authenticator.authorizeUser(userId, code)).thenThrow(new GoogleAuthenticatorException("Thou shall not pass"));
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        String returnView = endpoint.validateCode(mock(Model.class), uaaAuthentication, Integer.toString(code));

        assertEquals("enter_code", returnView);
    }

    @Test
    public void testEmptyOTP() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        String returnView = endpoint.validateCode(mock(Model.class), uaaAuthentication, "");
        assertEquals("enter_code", returnView);
    }

    @Test
    public void testNonNumericOTP() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        String returnView = endpoint.validateCode(mock(Model.class), uaaAuthentication, "asdf123");
        assertEquals("enter_code", returnView);
    }
}