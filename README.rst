QUIC based VPN Proof of concept based on aioquic.

Requirements
------------

``aioquic`` requires Python 3.6 or better, and the OpenSSL development headers.
You also need to generate a pem private key and a x509 certificate for the vpn server and mention their respective paths in the launch command below.

Testing in a LAN environment
------------

On the server side:

.. code-block:: console

   $ sudo python3.8 vpn_server.py --port 443 -k ../tests/ssl_key.pem -c ../tests/ssl_cert.pem

On the client side:

.. code-block:: console

   $ sudo python3 vpn_client.py --host SERVER_LAN_IP --port 443 -k
   
You are then presented with a login/password prompt (root/toor) that you need to complete to authenticate to the server.

On the client side, when typing 

.. code-block:: console

   $ ifconfig
   
You should see a new interface ``mytunnel`` with an ip address of 10.10.10.1 pointing to the destination address 10.10.10.2.

You can then test some programs like ``ping``, ``telnet``, ``ssh`` or even ``http`` to 10.10.10.2 to see if there is connectivity.

You can also verify the QUIC encapsulation process by launching Wireshark on ``eth0``. You should see QUIC traffic on this interface. 
However, when looking on ``mytunnel``, you should see decapsulated/normal traffic between 10.10.10.1 and 10.10.10.2.

TELNET test
-------------

You can try your VPN with ``telnet`` to see if you can connect from the client to 10.10.10.2. Telnet is not encrypted. However, encapsulating it in a QUIC payload encrypts it.
Let's launch Wireshark to listen on ``mytunnel`` to see the telnet decapsulated traffic. 

.. image:: https://raw.githubusercontent.com/sohaib-ouzineb/main/master/TELNET_test.png?sanitize=true

We can verify that the traffic that is interceptable between the client and the host is indeed protected. To this end, we launch Wireshark to listen to on the real interface eth0 and we see that the traffic is indeed QUIC-encapsulated and thus protected.

.. image:: https://raw.githubusercontent.com/sohaib-ouzineb/main/master/QUIC_encapsulated_traffic.png?sanitize=true

