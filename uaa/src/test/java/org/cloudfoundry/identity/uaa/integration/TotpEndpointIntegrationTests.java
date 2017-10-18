package org.cloudfoundry.identity.uaa.integration;

import com.dumbster.smtp.SimpleSmtpServer;
import org.cloudfoundry.identity.uaa.integration.feature.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.integration.feature.TestClient;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.test.TestAccounts;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class)
public class TotpEndpointIntegrationTests {

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Autowired
    TestAccounts testAccounts;

    private static final String USER_PASSWORD = "sec3Tas";

    @Autowired
    private SimpleSmtpServer simpleSmtpServer;

    @Autowired
    private TestClient testClient;

    @Test
    public void testQRCodeGetsGenerated() {
        String user = createAnotherUser();
        webDriver.get(baseUrl + "/logout.do");
        webDriver.get(baseUrl + "/totp_qr_code");
        webDriver.findElement(By.name("username")).sendKeys(user);
        webDriver.findElement(By.name("password")).sendKeys(USER_PASSWORD);
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();
        assertEquals(baseUrl + "/totp_qr_code", webDriver.getCurrentUrl());
        assertThat(webDriver.findElement(By.id("qr")).getAttribute("src"), Matchers.containsString("chart.googleapis"));
    }

    private String createAnotherUser() {
        return IntegrationTestUtils.createAnotherUser(webDriver, USER_PASSWORD, simpleSmtpServer, baseUrl, testClient);
    }

}
