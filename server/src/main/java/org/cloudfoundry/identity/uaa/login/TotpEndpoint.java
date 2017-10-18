package org.cloudfoundry.identity.uaa.login;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorException;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mfa_provider.UserGoogleMfaCredentialsProvisioning;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;

@Controller
public class TotpEndpoint {
    private GoogleAuthenticatorConfig config = new GoogleAuthenticatorConfig.GoogleAuthenticatorConfigBuilder().build();
    private GoogleAuthenticator authenticator = new GoogleAuthenticator(config);
    private UserGoogleMfaCredentialsProvisioning userGoogleMfaCredentialsProvisioning;
    private Log logger = LogFactory.getLog(TotpEndpoint.class);

    public GoogleAuthenticatorKey createCredentials(String userId) {
        if(authenticator.getCredentialRepository() == null) {
            authenticator.setCredentialRepository(userGoogleMfaCredentialsProvisioning);
        }
        return authenticator.createCredentials(userId);
    }



    @RequestMapping(value = {"/totp_qr_code"}, method = RequestMethod.GET)
    public String generateQrUrl(Model model, Principal principal) throws NoSuchAlgorithmException, IOException {

        UaaPrincipal uaaPrincipal = (principal instanceof UaaAuthentication) ? ((UaaAuthentication) principal).getPrincipal() : null;

        if(userGoogleMfaCredentialsProvisioning.userCredentialExists(uaaPrincipal.getId())) {
            return "enter_code";
        } else{
            String url = GoogleAuthenticatorQRGenerator.getOtpAuthURL("UAA", uaaPrincipal.getName(), createCredentials(uaaPrincipal.getId()));
            model.addAttribute("qrurl", url);
            return "qr_code";
        }
    }

    public void setAuthenticator(GoogleAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    public void setUserGoogleMfaCredentialsProvisioning(UserGoogleMfaCredentialsProvisioning userGoogleMfaCredentialsProvisioning) {
        this.userGoogleMfaCredentialsProvisioning = userGoogleMfaCredentialsProvisioning;
    }

    @RequestMapping(value = {"/totp_qr_code.do"}, method = RequestMethod.POST)
    public String validateCode(Model model,
                               Principal principal,
                               @RequestParam("code") String code)
            throws NoSuchAlgorithmException, IOException {
        int codeValue;
        UaaPrincipal uaaPrincipal = (principal instanceof UaaAuthentication) ? ((UaaAuthentication) principal).getPrincipal() : null;
        try {
            codeValue = Integer.valueOf(code);
            if(authenticator.authorizeUser(uaaPrincipal.getId(), codeValue)) {
                return "home";
            }
            logger.debug("Code authorization failed for user: " + uaaPrincipal.getId());
            model.addAttribute("error", "QR code can be number only");
        } catch (NumberFormatException e) {
            logger.debug("Error validating the code for user: " + uaaPrincipal.getId() + ". Error: " + e.getMessage());
            model.addAttribute("error", "QR code can be number only");
        } catch (GoogleAuthenticatorException e) {
            logger.debug("Error validating the code for user: " + uaaPrincipal.getId() + ". Error: " + e.getMessage());
            model.addAttribute("error", "Invalid QR code");
        }
        return "enter_code";
    }
}
