If you are still not solid on your understanding of subdomain takeover, the following resources should help get you up to speed:

* [HackTricks - Domain/Subdomain Takeover](https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover)
* [Hackerone - Guide to Subdomain Takeovers](https://www.hackerone.com/application-security/guide-subdomain-takeovers)
* [OWASP Web Application Security Testing - Test for Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)

One this BadDNS doesn't help with very much is the actual takeover process, once a valid takeover is detected. This varies significantly from takeover-to-takeover. There are some excellent resources focused on the exploitation side of subdomain takeovers. 

First and foremost, [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz). The issues pages within this GitHub repo contain most of the current research on individual takeovers.

Another excellent resource for some specific cloud provider based takeovers are the "GoDiego" blog posts, by @secfaults.

* [Subdomain Takeover in Azure](https://godiego.co/posts/STO-Azure/)
* [Subdomain Takeover in AWS](https://godiego.co/posts/STO-AWS/)