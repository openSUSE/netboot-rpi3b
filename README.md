Network Boot for the Raspberry Pi 3B
====================================

TL;DR Run this program on any host in the same network segment as a Raspberry
Pi 3 Model B to make it boot from network more reliably. Magic.

More Information
----------------

According to official documentation, network boot has been implemented in the
mask ROM since Raspberry Pi 3 Model B. However, this early implementation is
buggy and requires many workarounds.

A great place to start is the official [tutorial](https://www.raspberrypi.org/documentation/hardware/raspberrypi/bootmodes/net_tutorial.md).
It contains you an overview and a step-by-step guide to setting up the server
side.

Next, read the [full documentation](https://www.raspberrypi.org/documentation/hardware/raspberrypi/bootmodes/net.md).
This document contains some useful tips for debugging and a section about
known problems.

If you have a Raspberry Pi 3 Model B+, then these two great documents are all
you need.

On the Raspberry Pi 3 Model B, timeout handling is also buggy. This is
mentioned in the original [blog post](https://www.raspberrypi.org/blog/pi-3-booting-part-ii-ethernet-all-the-awesome/).

Raspberry Pi 3 Model B Timeout Bug
----------------------------------

Network boot on a Raspberry Pi 3 Model B starts by requesting configuration
via DHCP. The ROM code makes up to five attempts. In each attempt, the
Raspberry Pi broadcasts a DHCP DISCOVER packet and then waits for a suitable
reply. This is where things go wrong. Even if your DHCP reply is perfect, it
is not processed as soon as it is received. Instead, the Raspberry Pi
continues waiting for further packets, and if nothing arrives within a time
limit, the DHCP attempt is aborted. This receive timeout has not been quite
stable during testing, but it seems to be at least 1 second.

There is also a timeout for the whole DHCP transaction. This appears to be
exactly 1 second. When a packet is received after this timeout, and if all
required parameters have been configured, then the transaction is successfull.

So, what does this `netboot-rpi3b` program do? It monitors network traffic for
DHCP requests from the buggy Raspberry Pi 3 Model B firmware. If one is
received, it a packet is sent to the requesting Raspberry Pi 0.6 s after the
DHCP request. This first packet ensures that the DHCP attempt will not aborted
prematurely. Then a second packet is sent 1.2 s after the DHCP request. This
second packet triggers successful completion of the transaction. The mask ROM
code then initiates TFTP transfer.

It does not matter what kind of packets are delivered to the Raspberry Pi. I
have chosen to send Wake-on-LAN packets, because:

- A WOL packet operates on the link layer. It does not require a valid IP
  address, which is not known.
- A WOL packet does not have to be broadcast to all stations.
- It is a common protocol, so it is likely to be implemented correctly on all
  switches and not blocked by administrators.
- If somebody monitors network traffic, a WOL packet to a booting system will
  not look suspicious.

Some Common Myths
-----------------

There is some confusion regarding what must be present in a DHCP reply to make
the Raspberry Pi happy.

To my best knowledge, only two pieces of information are configurable:

- own IP address,
- IP address of the TFTP server.

Own IP address is pretty standard. It is taken from the `YIADDR` (Your IP
address) field of the DHCP OFFER message.

The TFTP server address is trickier. There are two ways to configure it:

- DHCP Option 66 (TFTP server name)
- DHCP Option 43 (Vendor-specific information)

The trick with DHCP Option 66 is that this is supposed to be the server
_name_. But the Raspberry Pi firmware boot code does not implement a
resolver. So, it must be in fact an IP address in dotted decimal notation, and
then it is recognized.

For DHCP Option 43, if the string `Raspberry Pi Boot` is found anywhere inside
the data, then the TFTP server is the host which sent the DHCP OFFER message,
i.e. it is taken from the IP header source address field.

If both options are present, they are processed sequentially, and the last one
wins.
