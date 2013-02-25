package org.jenkinsci.plugins.api;

import org.apache.commons.lang.StringUtils;
import org.scribe.builder.api.DefaultApi10a;
import org.scribe.model.Token;

public class RedmineApi extends DefaultApi10a {
    private String redmineUrl;
    
    public RedmineApi(String redmineUrl) {
        this.redmineUrl = redmineUrl;
    }
    
    @Override
    public String getAccessTokenEndpoint() {
        return getAPIEndopint() + "access_token";
    }

    @Override
    public String getAuthorizationUrl(Token oauthToken) {
        return getAPIEndopint() + "authorize?oauth_token=" + oauthToken.getToken();
    }

    @Override
    public String getRequestTokenEndpoint() {
        return getAPIEndopint() + "request_token";
    }
    
    private String getAPIEndopint() {
        String endpointUrl = this.redmineUrl;
        if (!StringUtils.endsWith(endpointUrl, "/")) {
            endpointUrl = endpointUrl + "/"; 
        }
        return endpointUrl + "oauth/";
    }
}