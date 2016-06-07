package org.jenkinsci.plugins;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.api.RedmineApiService;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Header;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.HttpResponses;
import org.kohsuke.stapler.StaplerRequest;
import org.scribe.model.Token;
import org.springframework.dao.DataAccessException;

import com.thoughtworks.xstream.converters.ConversionException;
import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException;
import jenkins.model.Jenkins;

public class RedmineSecurityRealm extends SecurityRealm {

    private static final String REFERER_ATTRIBUTE = RedmineSecurityRealm.class.getName() + ".referer";
    private static final String ACCESS_TOKEN_ATTRIBUTE = RedmineSecurityRealm.class.getName() + ".access_token";
    private static final Logger LOGGER = Logger.getLogger(RedmineSecurityRealm.class.getName());

    private String redmineUrl;
    private String clientID;
    private String clientSecret;

    @DataBoundConstructor
    public RedmineSecurityRealm(String redmineUrl, String clientID, String clientSecret) {
        super();
        this.redmineUrl = redmineUrl;
        this.clientID = Util.fixEmptyAndTrim(clientID);
        this.clientSecret = Util.fixEmptyAndTrim(clientSecret);
    }

    public RedmineSecurityRealm() {
        super();
        LOGGER.log(Level.FINE, "RedmineSecurityRealm()");
    }

    /**
     * @return the redmineUrl
     */
    public String getRedmineUrl() {
        return redmineUrl;
    }

    /**
     * @param redmineUrl the redmineUrl to set
     */
    public void setRedmineUrl(String redmineUrl) {
        this.redmineUrl = redmineUrl;
    }

    /**
     * @return the clientID
     */
    public String getClientID() {
        return clientID;
    }

    /**
     * @param clientID the clientID to set
     */
    public void setClientID(String clientID) {
        this.clientID = clientID;
    }

    /**
     * @return the clientSecret
     */
    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * @param clientSecret the clientSecret to set
     */
    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public HttpResponse doCommenceLogin(StaplerRequest request, @Header("Referer") final String referer) throws IOException {

        request.getSession().setAttribute(REFERER_ATTRIBUTE, referer);

        Jenkins jenkins = Jenkins.getInstance();
        if (jenkins == null) {
            throw new RuntimeException("Jenkins is not started yet.");
        }
        String rootUrl = jenkins.getRootUrl();
        if (StringUtils.endsWith(rootUrl, "/")) {
            rootUrl = StringUtils.left(rootUrl, StringUtils.length(rootUrl) - 1);
        }
        String callback = rootUrl + "/securityRealm/finishLogin";

        RedmineApiService redmineApiService = new RedmineApiService(redmineUrl, clientID, clientSecret, callback);

        Token requestToken = redmineApiService.createRquestToken();
        request.getSession().setAttribute(ACCESS_TOKEN_ATTRIBUTE, requestToken);

        return new HttpRedirect(redmineApiService.createAuthorizationCodeURL(requestToken));
    }

    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        String code = request.getParameter("oauth_verifier");

        if (StringUtils.isBlank(code)) {
            LOGGER.log(Level.SEVERE, "doFinishLogin() code = null");
            return HttpResponses.redirectToContextRoot();
        }

        Token requestToken = (Token) request.getSession().getAttribute(ACCESS_TOKEN_ATTRIBUTE);

        Token accessToken = new RedmineApiService(redmineUrl, clientID, clientSecret).getTokenByAuthorizationCode(code, requestToken);

        if (!accessToken.isEmpty()) {

            RedmineAuthenticationToken auth = new RedmineAuthenticationToken(accessToken, redmineUrl, clientID, clientSecret);
            SecurityContextHolder.getContext().setAuthentication(auth);

            User u = User.current();
            if (u != null) {
                u.setFullName(auth.getName());
            }

        } else {
            LOGGER.log(Level.SEVERE, "doFinishLogin() accessToken = null");
        }

        // redirect to referer
        String referer = (String) request.getSession().getAttribute(REFERER_ATTRIBUTE);
        if (referer != null) {
            return HttpResponses.redirectTo(referer);
        } else {
            return HttpResponses.redirectToContextRoot();
        }
    }

    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityRealm.SecurityComponents(new AuthenticationManager() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                if (authentication instanceof RedmineAuthenticationToken) {
                    return authentication;
                }

                throw new BadCredentialsException("Unexpected authentication type: " + authentication);
            }
        }, new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UserMayOrMayNotExistException, DataAccessException {
                throw new UserMayOrMayNotExistException("Cannot verify users in this context");
            }
        });
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        UserDetails result = null;
        Authentication token = SecurityContextHolder.getContext().getAuthentication();
        if (token == null) {
            throw new UsernameNotFoundException("RedmineAuthenticationToken = null, no known user: " + username);
        }
        if (!(token instanceof RedmineAuthenticationToken)) {
            throw new UserMayOrMayNotExistException("Unexpected authentication type: " + token);
        }
        result = new RedmineApiService(redmineUrl, clientID, clientSecret).getUserByToken(((RedmineAuthenticationToken) token).getAccessToken());
        if (result == null) {
            throw new UsernameNotFoundException("User does not exist for login: " + username);
        }
        return result;
    }

    @Override
    public GroupDetails loadGroupByGroupname(String groupName) {
        throw new UsernameNotFoundException("groups not supported");
    }

    @Override
    public boolean allowsSignup() {
        return false;
    }

    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    public static final class ConverterImpl implements Converter {

        @Override
        public boolean canConvert(Class type) {
            return type == RedmineSecurityRealm.class;
        }

        @Override
        public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {

            RedmineSecurityRealm realm = (RedmineSecurityRealm) source;

            writer.startNode("redmineUrl");
            writer.setValue(realm.getRedmineUrl());
            writer.endNode();

            writer.startNode("clientID");
            writer.setValue(realm.getClientID());
            writer.endNode();

            writer.startNode("clientSecret");
            writer.setValue(realm.getClientSecret());
            writer.endNode();
        }

        @Override
        public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {

            String node = reader.getNodeName();

            RedmineSecurityRealm realm = new RedmineSecurityRealm();

            reader.moveDown();
            node = reader.getNodeName();
            String value = reader.getValue();
            setValue(realm, node, value);
            reader.moveUp();

            reader.moveDown();
            node = reader.getNodeName();
            value = reader.getValue();
            setValue(realm, node, value);
            reader.moveUp();

            reader.moveDown();
            node = reader.getNodeName();
            value = reader.getValue();
            setValue(realm, node, value);
            reader.moveUp();

            if (reader.hasMoreChildren()) {
                reader.moveDown();

                node = reader.getNodeName();

                value = reader.getValue();

                setValue(realm, node, value);

                reader.moveUp();
            }
            return realm;
        }

        private void setValue(RedmineSecurityRealm realm, String node, String value) {

            if (node.equalsIgnoreCase("redmineUrl")) {
                realm.setRedmineUrl(value);
            } else if (node.equalsIgnoreCase("clientid")) {
                realm.setClientID(value);
            } else if (node.equalsIgnoreCase("clientsecret")) {
                realm.setClientSecret(value);
            } else {
                throw new ConversionException("invalid node value = " + node);
            }

        }
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {

        @Override
        public String getHelpFile() {
            return "/plugin/redmine-oauth/help/help-security-realm.html";
        }

        @Override
        public String getDisplayName() {
            return "Redmine OAuth Plugin";
        }

        public DescriptorImpl() {
            super();
        }

        public DescriptorImpl(Class<? extends SecurityRealm> clazz) {
            super(clazz);
        }
    }

}
