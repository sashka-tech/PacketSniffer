# PacketSniffer

A **packet analyzer**, also known as **packet sniffer**, protocol analyzer, or network analyzer, is a computer program or computer hardware such as a packet capture appliance that can analyze and log traffic that passes over a computer network or part of a network.

## csniffer

Test sniffer (capturer of a certain number of packets) written in C using the *pcap* library and its capabilities. The program is executed in the terminal using the following constructs:

```
cd csniffer
make all
sudo ./sniffer [interface] [number of packets captured]

```
