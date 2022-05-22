package org.jenkinsci.plugins.api;

import org.apache.commons.lang.StringUtils;
import org.scribe.builder.ServiceBuilder;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;

import net.sf.json.JSONObject;

public class RedmineApiService {

    private final OAuthService service;
    private String redmineUrl;

    public RedmineApiService(String redmineUrl, String apiKey, String apiSecret) {
        this(redmineUrl, apiKey, apiSecret, null);
    }

    public RedmineApiService(String redmineUrl, String apiKey, String apiSecret, String callback) {
        super();
        ServiceBuilder builder = new ServiceBuilder().provider(new RedmineApi(redmineUrl)).apiKey(apiKey).apiSecret(apiSecret);
        if (StringUtils.isNotBlank(callback)) {
            builder.callback(callback);
        }
        service = builder.build();
        this.redmineUrl = redmineUrl;
    }

    public Token createRquestToken() {
        return service.getRequestToken();
    }

    public String createAuthorizationCodeURL(Token requestToken) {
        return service.getAuthorizationUrl(requestToken);
    }

    public Token getTokenByAuthorizationCode(String code, Token requestToken) {
        Verifier v = new Verifier(code);
        return service.getAccessToken(requestToken, v);
    }

    public RedmineUser getUserByToken(Token accessToken) {
        OAuthRequest request = new OAuthRequest(Verb.GET, getAPIEndopint() + "user_info.json");
        service.signRequest(accessToken, request);
        Response response = request.send();
        String json = response.getBody();
        RedmineUserResponse userResponse = RedmineUserResponse.fromJsonString(json);
        if (userResponse != null) {
            return userResponse.user;
        } else {
            return null;
        }
    }

    private String getAPIEndopint() {
        String endpointUrl = this.redmineUrl;
        if (!StringUtils.endsWith(endpointUrl, "/")) {
            endpointUrl = endpointUrl + "/";
        }
        return endpointUrl + "oauth/";
    }

}
