We try to get a MAC address table from MOXA Switches (EDS-518/510A/E) by SNMP, but if the MAC address table is large
And the version of SNMP is V3, MOXA would normally work.
Also, we want to read SFP data from this switches but we can not do it using SNMP.
It is only possible via HTTP/HTTPS.
We make a simple application which retrieves MAC addresses and SFP DDM data.
(Now tested only on EDS-518A and EDS-510A with Firmware Version 2.7 3.6 3.8).
Additionally, this util can be used for getting the serial number and model and more info.

Command line arguments:
-a <ip address or fqdn without http or https>
-u <username>
-p <password>
-s <1 for use https, 0 for use http>
-f <1 for get SFP data,>
-m <1 for get switch data>
-d <1 enable debug mode>

example:
moxahttpmactable.exe -u admin -p moxa -f 1 -a 192.168.0.33