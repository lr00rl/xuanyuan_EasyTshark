TShark is not actually a kernel - it's the command-line version of Wireshark. 
Both Wireshark (the GUI version) and TShark use the same packet capture and analysis engine 
called "libpcap" on Unix-like systems and "WinPcap/Npcap" on Windows systems.

---

Packet capture library (libpcap)
Wireshark/TShark uses libpcap to capture live network data.

As capture filter strings are directly passed from Wireshark/TShark to libpcap,
the available capture filter syntax depends on the libpcap version installed.

More information can be found at the [tcpdump project page](http://www.tcpdump.org/);
libpcap and tcpdump are both developed by tcpdump.org.

On most modern UN\*X platforms libpcap is available.
It comes as part of most non-specialized Linux distributions, the free-software BSDs, and macOS;
It's installed by default on the BSDs and macOS, and it might be installed by default on the Linux distributions as well.
(Specialized Linux distributions such as those for small embedded boxes might omit it.)

Two Windows versions of libpcap are available.
The older one is named WinPcap;
It is no longer actively being maintained, and is based on an older version of libpcap.

The newer one is called Npcap;
It is actively being maintained, and is based on a relatively recent version of libpcap, 
but is only available for Windows 7 and later versions of Windows.

The libpcap file format description can be found at: Development/LibpcapFileFormat

Imported from https://wiki.wireshark.org/libpcap on 2020-08-11 23:15:56 UTC

---

The main components of Wireshark are:

1. Capture Engine (libpcap/WinPcap/Npcap) - handles the actual packet capture
2. Dissectors - decode and analyze different protocols
3. User Interface - either GUI (Wireshark) or CLI (TShark)

So while tshark and Wireshark share the same underlying capture and analysis capabilities, neither is a kernel. 
They're both front-ends to the same packet analysis framework, just with different interfaces for different use cases.

