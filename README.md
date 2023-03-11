# Detecting routing loops on the Internet [![badge](https://img.shields.io/badge/In%20Proceedings-Passive%20and%20Active%20Measurement%202023-blue)](https://link.springer.com/book/10.1007/978-3-031-28486-1)

Routing loops are the phenomenon in which packets never reach their intended destination because they loop among a sequence of routers. They are the result of network misconfigurations, inconsistencies, and errors in routing protocol implementations. In addition to being a pernicious threat to Internet reliability and reachability, routing loops can even enable or exacerbate denial of service attacks.

In this work, we scan the entire IPv4 address space to detect persistent routing loops. The paper and its results can be found here: [A Global Measurement of Routing Loops on the Internet](https://link.springer.com/chapter/10.1007/978-3-031-28486-1_16)

## Detect routing loops yourself

You can use "[Yarrp](https://www.cmand.org/yarrp/)", an Internet topology discovery tool, to detect routing loops. First, you need to clone this repository where a submodule of a specific branch of Yarrp exists.

```sh
git clone --recursive git@github.com:RoutingLoops/code-and-data.git
```

Then inside yarrp directory, follow the installation steps provided by Yarrp in its README.md, which are:

```sh
./bootstrap
./configure
make
```

Once Yarrp is installed, run the following after replacing what's inside the angle brackets <> with the appropriate value:

```sh
for ttl in {246..255}; do yarrp -i <ip_list_file> -r 100000 -l $ttl -m $ttl -F $ttl -a <scanning_machine_IP> -I <network_interface> -s -o $ttl.yrp; done

```

Then process the resulting .yrp files using the following commands:

```sh
for i in {246..255}; do awk -v var=$i '$4==11 && $6==var {print $0}' $i.yrp | sort -u -t " " -k1,1 > strict-uniq-$i.yrp; done
sort -k1,1 -k6,6  strict-uniq* > sorted_output.yrp
```

Finally, to print routing loops and their traceroutes, run:

```sh
python3 routing_loops_finder.py -f sorted_output.yrp -m 246 -l 255
```
Note that you can change the definition of a routing loop by trying different values for the option "-d" i.e. the delta between the hop numbers of two repeating router IPs

The output will be in the format of:

```
dst_IP:
hop# router_IP
```
