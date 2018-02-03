# Scan Detect kernel module
Implementation of a kernel module that detects various port scans that can be generated using nmap utility.
It works by inspecting flags of each packet and maintaining an history of suspecting packets.

## Scans supported
The following scan types are supported:
* SYN scan: When only SYN flag is set and multiple nodes are queried.
* null scan: When no flags are set.
* FIN scan: When only FIN flag is set.
* XMAS scan: When URG, PSH and FIN flags are set.

## Logging
All detection are logged to kernel log. 
To check logs: `tail -f /var/log/kern.log`

## Compile and run
To compile: make
To insert and load module: ` sudo insmod scan_detect.ko `
To unload/remove module: ` sudo rmmod scan_detect `

## To test
* SYN scan: ` sudo nmap -sS <host> `
* null scan: ` sudo nmap -sN <host> `
* FIN scan: ` sudo nmap -sF <host> `
* XMAS scan: ` sudo nmap -sX <host> `

## Notes
* It only detects scan when there are a min threshold of packets per second which is 256 for SYN and 8 for others.
To change that just edit the macros at the top of the code.
* To log all packets change the definitions to 1.
* This is just an educational project and there are several workarounds of this, like using multiple machines, faking IP or sending packets slowly.
