Why does mail delivery go slow or hang sometimes?
-------------------------------------------------

There are a number of things that can affect mail delivery. Here are some common causes. 

    1. Murder Master is overloaded. In a normal setup the murder master is queried for each incoming messages 
    
    2. Delivery.db corruption. A backend will/may reject mail if the delivery.db is corrupt 
    
    3. Slow dns. Some MTAs (like sendmail) talk to dns a lot. If dns is slow, mail delivery appears slow. We run named on each Cyrus machine 
    
    4. Lmtpproxyd is having trouble. Sometimes lmtpproxyd will die and disappear. Sometimes it just hangs. Not sure why, but restarting may help.

If you have a large volume of mail then :ref:`Cyrus Murder Mail Delivery 
<murder-mail-delivery>` has some tips. 

We experienced some filesystem locking problems when allowing to many 
lmtpd-processes to be started. Performance was seriously degraded, 
resulting in timeouts and endless retries. We use a postfix instance 
between to limit parallel deliveries to lmtpd resulting in much higher 
throughput. With berkeley-nosync as duplicate suppression db, 50-100 
Messages/sec are doable. 

