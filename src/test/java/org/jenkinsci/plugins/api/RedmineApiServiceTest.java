package org.jenkinsci.plugins.api;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class RedmineApiServiceTest {
    @Test
    public void testFromJsonString() {
        String json = "{ \"user\": { \"login\": \"jplang\", \"firstname\": \"Jean-Philippe\", \"lastname\": \"Lang\", \"mail\": \"jp_lang@yahoo.fr\", \"password\": \"secret\" }}";
        RedmineUserResponse userResponce = RedmineUserResponse.fromJsonString(json);
        assertEquals(userResponce.user.login, "jplang");
    }
}
