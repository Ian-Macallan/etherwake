# etherwake
Wake Lan Devices

````
       etherwake (x86 Unicode) : Mon May 27 15:32 2024 1.0.04.006

                         Usage : etherwake [Options] MACAddress [MACAddress...]
                         Usage : etherwake [Options] hostname [hostname...]

                 -h, -?, -help : print help
           -hl, -lh, -helplong : print long help

                     -a4, -arp : show arp table for IPv4
                    -a6, -arp6 : show arp table for IPv4 and IPv6
                 -d4, -adapter : show local adapter for IPv4
                -d6, -adapter6 : show local adapter for IPv4 and IPv6
                   -dnsqueryex : Use DnsQueryEx (Windows 8 and Above)
                               : This Enable to use IPV6 DNS Server
                     -l, -list : show ip and mac addresses known in .ini file
                   -mac ipaddr : search mac for an ip address and store it in .ini file
                      -pingsub : Ping All Hosts in Subnet
                -pinglist file : Ping A List Of Host from a file
                               : First Argument is An IP Address
                      -query a : query a dns server (with -s) for an address
                  -querytype t : query type (PTR...)
                       -subnet : Send wake to a specific subnet
                         -wake : wake MAC Address (optional)

                     -4, -ipv4 : before -adapter6 and -arp6 filters output
                     -6, -ipv6 : before -adapter6 and -arp6 filters output
                        -debug : debug mode
                         -down : show only items in DOWN State
                          -imm : IP Match MAC for IPV6 (Generally for NAS and Windows)
                -locale locale : set locale fr-fr or .1252
                        -noimm : IP Does not Match MAC for IPV6
                           -nz : show only items with non zero MAC
                         -ping : Ping Hosts During -arp
                    -q, -quiet : quiet mode
                  -r, -resolve : Resolve Hostname for -arp or -adapter
               -s, -server dns : DNS Server
                    -timeout t : Time Out for Ping
                           -up : show only items in UP State
                  -v, -verbose : verbose mode

                       Example : etherwake AA-AA-AA-AA-AA-AA BB:BB:BB:BB:BB:BB
                               : etherwake -wake AA-AA-AA-AA-AA-AA BB:BB:BB:BB:BB:BB
                               : etherwake registers MAC Addresses in a etherwake.arp file.
                               : etherwake for wake purpose stores hostnames and MAC Addresses in etherwake.ini file.

                       -readme : Show Read Me Text
````
