package org.jenkinsci.plugins;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.api.RedmineApiService;
import org.jenkinsci.plugins.api.RedmineUser;
import org.scribe.model.Token;

public class RedmineAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = -7826610577724673531L;

    private final Token accessToken;
    private final RedmineUser redmineUser;

    public RedmineAuthenticationToken(Token accessToken, String redmineUrl, String apiKey, String apiSecret) {
        this.accessToken = accessToken;
        this.redmineUser = new RedmineApiService(redmineUrl, apiKey, apiSecret).getUserByToken(accessToken);

        boolean authenticated = false;

        if (redmineUser != null) {
            authenticated = true;
        }

        setAuthenticated(authenticated);
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return (redmineUser != null ? redmineUser.getAuthorities() : new GrantedAuthority[0]);
    }

    /**
     * @return the accessToken
     */
    public Token getAccessToken() {
        return accessToken;
    }

    @Override
    public Object getCredentials() {
        return StringUtils.EMPTY;
    }

    @Override
    public Object getPrincipal() {
        return getName();
    }

    @Override
    public String getName() {
        return (redmineUser != null ? redmineUser.getUsername() : null);
    }

}
