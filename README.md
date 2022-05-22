Jenkins Redmine OAuth Plugin
============================

Overview
--------
This Jenkins plugin enables [OAuth](http://oauth.net) authentication for [Redmine OAuth Provider Plugin](https://github.com/suer/redmine_oauth_provider) users.

Redmine Security Realm (authentication):
--------------------------------------------

First you need to get consumer key/secret from Redmine OAuth Provider Plugin.

1. Log into your Redmine account.
2. Access to [YOUR_REDMINE_HOST]/oauth_clients
3. Click the **Register your application** link.
4. The system requests the following information:
   * **Name** is required. For example, input Jenkins
   * **Main Application URL** is required. For example, input your jenkins url.
   * **Callback URL** is required. For example, input [YOUR_JENKINS_HOST]/securityRealm/finishLogin
   * **Support URL** is not required.
5. Press **Register**.
   The system generates a key and a secret for you.
   Toggle the consumer name to see the generated Key and Secret value for your consumer.

Second, you need to configure your Jenkins.

1. Open Jenkins **Configure System** page.
2. Check **Enable security**.
3. Select **Redmine OAuth Plugin** in **Security Realm**.
4. Input your Redmine Url to **Redmine Url**.
5. Input your Consumer Key to **Client ID**.
6. Input your Consumer Secret to **Client Secret**.
7. Click **Save** button.

Credits
-------
This plugin reuses many codes of [Jenkins Assembla Auth Plugin](https://wiki.jenkins-ci.org/display/JENKINS/Assembla+Auth+Plugin).
Many thanks to Assembla team.
