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


License
-------

	(The MIT License)

	Copyright (c) 2013 mallowlabs

	Permission is hereby granted, free of charge, to any person obtaining
	a copy of this software and associated documentation files (the
	'Software'), to deal in the Software without restriction, including
	without limitation the rights to use, copy, modify, merge, publish,
	distribute, sublicense, and/or sell copies of the Software, and to
	permit persons to whom the Software is furnished to do so, subject to
	the following conditions:

	The above copyright notice and this permission notice shall be
	included in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
	MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
	IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
	CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
	TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
	SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

