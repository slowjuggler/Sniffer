
1. Description.

This is a simple sniffer daemon that allows you to hit packets captured by net card on the localhost. It is written in ANSI C so it takes a very little space and can be used on embedded devices.
Objective to capture all frames recieved by a given Ethernet interface using an AF_PACKET socket.


2. Installation.

On Linux compile the software using "make". On Windows use "make" from Cygwin (http://cygwin.com). MinGW will not work, as it does not support fork().	


3. Command line options.

Syntax is ./sniffer -i "interface name, for exmmple wlo1" -f "log filename". Normally, sniffer stay into the foreground. To make it daemon in the background (for logging purposes), use "-f log filename" switch.
Remarke: AF_PACKET sockets are specific to Linux. Programs that make use of them need elevated privileges in order to run.




