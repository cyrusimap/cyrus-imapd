The process count keeps growing!
================================

If you notice that your imapd process count continues to grow and never decreases, there are a number of options which may be affecting it.

1. Reuse count
--------------

By default, imapd processes will remain alive for 250 new connections before shutting down. Setting this to a lower value will reduce the amount of time unused processes hang around. There is a tradeoff between startup/shutdown overhead and process longevity.

The use setting is the **- U** argument to :cyrusman:`imapd(8)`.

2. Maximum child count
----------------------

By default, Cyrus is allowed to spawn a limitless number of child imapd processes. To control this growth, adjust the **maxchild** option in :cyrusman:`cyrus.conf(5)`.

3. Clean up connections that are no longer in use
-------------------------------------------------

While POP connections are short lived, IMAP connections can be long lived. And then there are processes trying to listen to a client that's no longer alive. 

Setting **tcp_keepalive** option in :cyrusman:`imapd.conf(5)` to **1** can be used to test if connections are still alive. The operating system will send an ACK packet every so often (every 2 hours by default on Linux) which tests if the TCP endpoint is still reachable.

The other **tcp_keepalive_** options help control how and when the test occurs.



 
 