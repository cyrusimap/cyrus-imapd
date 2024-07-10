.. _imap-howto-nginx-proxy:

================================
HOWTO: Using an NGINX IMAP Proxy
================================

it is possible to use nginx as imap proxy, unfortunatelly that configuration do not allow to encrypt connection between cyrus and nginx, but only between nginx and the client. To overcome this limitation I will use a stream that encrypt data between impad and nginx. To make things more interesting I will add twi different imapd server and nginx will chose between them based on the imap account
```
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;
include /usr/share/nginx/modules/*.conf;
events {
worker_connections 1024;
}
http {
access_log  /var/log/nginx/access.log  main;
sendfile            on;
tcp_nopush          on;
tcp_nodelay         on;
keepalive_timeout   65;
types_hash_max_size 4096;
include             /etc/nginx/mime.types;
default_type        application/octet-stream;
include /etc/nginx/conf.d/*.conf;
server {
listen       127.0.0.1:80;
server_name  _;
root         /usr/share/nginx/html;
include /etc/nginx/default.d/*.conf;
error_page 404 /404.html;
location = /404.html {
}
error_page 500 502 503 504 /50x.html;
location = /50x.html {
}
}
}
mail {
server_name myimapdproxy;
auth_http   127.0.0.1:80/mail/auth.php;
proxy on;
proxy_pass_error_message on;
server {
listen 993 ssl;
protocol imap;
imap_auth login plain;
ssl_certificate     /etc/ssl/certs/postfix.pem;
ssl_certificate_key /etc/pki/tls/private/postfix.key;
ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_dhparam /etc/nginx/dhparam.pem;
ssl_ciphers EECDH+AESGCM:EDH+AESGCM;
ssl_ecdh_curve secp384r1;
ssl_session_timeout  10m;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
proxy on;
}
}
stream {
upstream  imapsd3_backend{
server server3:993;
}
upstream  imapsd4_backend{
server server4:993;
}
server {
# frontend
listen 127.0.0.1:9143;
proxy_pass imapsd3_backend;
proxy_ssl_certificate     /etc/ssl/certs/postfix.pem;
proxy_ssl_certificate_key /etc/pki/tls/private/postfix.key;
proxy_ssl on;
}
server {
# frontend
listen 127.0.0.1:9144;
proxy_pass imapsd4_backend;
proxy_ssl_certificate     /etc/ssl/certs/postfix.pem;
proxy_ssl_certificate_key /etc/pki/tls/private/postfix.key;
proxy_ssl on;
proxy_ssl_protocols TLSv1.3;
proxy_ssl_ciphers ECDH+AESGCM:EDH+AESGCM;
}
}
```
basically each connection to port 993 will redirect to auth_http at 127.0.0.1:80/mail/auth.php
auth.php
```
<?php
if (!isset($_SERVER["HTTP_AUTH_USER"] ) || !isset($_SERVER["HTTP_AUTH_PASS"] )){
fail();
}
$username=$_SERVER["HTTP_AUTH_USER"] ;
$userpass=$_SERVER["HTTP_AUTH_PASS"] ;
$protocol=$_SERVER["HTTP_AUTH_PROTOCOL"] ;    
if (!authuser($username,$userpass)){
fail();
exit;
}
$backend_ip=getmailserver($username);
$server_ip=$backend_ip['ip'];
$server_port=$backend_ip['port'];
pass($server_ip, $server_port);
function authuser($user,$pass){
$pass = str_replace('%20',' ', $pass);
$pass = str_replace('%25','%', $pass);
return true;
}
function getmailserver($user){
$backend_ip["server3"] = array("ip" => "127.0.0.1", "name" => "server3", "port" => "9143" );
$backend_ip["server4"] = array("ip" => "127.0.0.1", "name" => "server4", "port" => "9144" );
if (strpos(file_get_contents("/usr/share/nginx/html/mail/users.txt"), $user) !== false ){
return $backend_ip["server4"];
} else {
return $backend_ip["server3"];
}
}
function fail(){
header("Auth-Status: Invalid login or password");
exit;
}
function pass($server,$port){
header("Auth-Status: OK");
header("Auth-Server: $server");
header("Auth-Port: $port");
exit;
}
?>
```
auth.php check the presence of an username from a file and redirect to different streams according to it
That's work but lack authentication in the proxy: if a client insert wrong crdential proxy will answer ok to the client, then redirect it to an imap server, that in turn will refuse during authentication. The error is that client receive ok and not fail! so it is rally better implement an authentication algo inside php
