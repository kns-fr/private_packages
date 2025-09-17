package fr.kns.authenticators.ExternalRedirect;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.crypto.KeyUse;
import org.keycloak.events.Details;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import jakarta.ws.rs.core.Response;
import org.keycloak.provider.ProviderConfigProperty;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static java.util.Arrays.asList;
import static org.keycloak.provider.ProviderConfigProperty.*;


@JBossLog
public class ExternalRedirect extends AbstractUsernameFormAuthenticator implements Authenticator {

    static final String ID = "external-redirect";



    @Override
    public void authenticate(AuthenticationFlowContext context) {


        var config = context.getAuthenticatorConfig().getConfig();

        String redirectUrl = config.get("url");
        boolean homeUrl = Boolean.parseBoolean(config.get("homeUrl"));
        if (homeUrl) {
            var baseUrl = context.getAuthenticationSession().getClient().getBaseUrl();
            if (!baseUrl.trim().isEmpty()) {
                redirectUrl = baseUrl;
            }
        }


        Response redirect = Response.status(Response.Status.FOUND)
                .location(URI.create(redirectUrl))
                .build();
        context.getEvent().detail(Details.REDIRECT_URI, redirectUrl);
        context.failure(AuthenticationFlowError.ACCESS_DENIED);  // Optionnel : signaler fin de flow
        context.challenge(redirect);
    }


    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

}