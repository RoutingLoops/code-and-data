import sys
import argparse
import time

modules = {}

def system_can_process(min_ttl, max_ttl, file_length):
    """
    Returns true if memory required to run this code is available. Returns false otherwise
    """
    factor = 1.5 ### we assume more than one ICMP TTL exceeded message is received per hop, on average
    ttl_range = max_ttl - min_ttl
    looping_ips_exp_nb = (file_length // ttl_range) * factor

    hops_dict_size = sys.getsizeof(pre_construct_traceroute_hops(min_ttl, max_ttl))
    ips_dict_size = looping_ips_exp_nb * 55 # rough estimate of dict size with key length = 32 bytes
    hops_dict_values_size = looping_ips_exp_nb * ((32 * ttl_range//2) + (24 * ttl_range//2)) # assumes half of each traceroute is 0 (24 bytes) and half contains an IP (32 bytes), on average

    mem_needed = ips_dict_size + (hops_dict_size * looping_ips_exp_nb) + hops_dict_values_size

    if mem_needed > check_available_mem():
        return False
    return True


def check_available_mem():
    """
    Returns available memory on the underlying system
    """
    return modules["psutil"].virtual_memory().available


def import_lib(lib):
    """
    Imports modules
    """
    try:
       module =  __import__(lib)
       return module
    except ImportError:
        pip.main(["install", lib])


def prereq():
    """
    Imports necessary modules via import_lib()
    """
    try:
        import pip
    except ImportError:
        sys.stderr.write("Please install pip...\n")
        exit(1)

    modules["tqdm"] = import_lib("tqdm")
    modules["psutil"] = import_lib("psutil")


def get_len(f):
    """
    Returns number of lines in the given file
    """
    with open(f, 'r') as f:
        return len(f.readlines())


def pre_construct_traceroute_hops(min_ttl, max_ttl):
    """
    Returns a predefined dictionary containing hop numbers
    """
    hops = {}
    for i in range(min_ttl, max_ttl + 1):
        hops[i] = 0
    return hops


def int_to_ip(n):
    """
    Returns an IPv4 equivalent to the decimal value n
    """
    byte_4 = int(n/(256**3)) % 256
    byte_3 = int(n/(256**2)) % 256
    byte_2 = int(n/(256**1)) % 256
    byte_1 = int(n/(256**0)) % 256
    ip = str(byte_4) + '.' + str(byte_3) + '.' + str(byte_2) + '.' + str(byte_1)
    return ip


def ip_to_int(ip):
    """
    Returns a decimal value equivalent to the IPv4 ip
    """
    a, b, c, d = ip.split('.')
    n = int(a)* (256**3) + int(b) * (256**2) + int(c) * 256 + int(d)
    return n


def is_loop(ip_trace, delta):
    """
    Returns true if ip_trace has a loop. Return false otherwise
    """
    for hop in ip_trace.keys():
        if ip_trace[hop] != 0:
            for hop_b in ip_trace.keys():
                if ip_trace[hop_b] != 0 and abs(hop - hop_b) > delta:
                    if ip_trace[hop] == ip_trace[hop_b]:
                        return True
    return False


def process_file(args):
    """
    Processes given yarrp file
    """
    to_analyze = args["file"]
    min_ttl = args["min_ttl"]
    max_ttl = args["max_ttl"]
    d = args["delimeter"]

    if min_ttl > max_ttl:
        sys.stderr.write("min_ttl cannot be greater than max_ttl\n")
        exit(1)

    sys.stderr.write("Calculating total length of file to analyze:\n")
    file_length = get_len(to_analyze)

    if not system_can_process(min_ttl, max_ttl, file_length): 
        sys.stderr.write("The system doesn't have sufficient memory to run this code...\n...Proceeding anyway!\n")
        time.sleep(1)

    sys.stderr.write("%d total lines to process.\n" % file_length)
    pbar = modules["tqdm"].tqdm(total=file_length, leave=False)

    ips = {}

    with open(to_analyze, "r") as fd:
        line = fd.readline()
        while line:
            pbar.update(1)
            # 100.3.71.100 1650218570 935332 11 0 252 172.99.45.250 211626 21085 40 96 245 0 24226:1 239158637
            target, _, _, icmp_type, _, hop_nb, hop_ip, _, _, _, _, _, _, _, _ = line.split(d)
            hop_nb = int(hop_nb)
            target = ip_to_int(target)
            hop_ip = ip_to_int(hop_ip)
            if(icmp_type == "11"):
                try:
                    ### A try-except block is a lot faster than checking if an ip is in ips or not, given the large number of keys
                    hops = ips[target]
                    if hop_nb in hops.keys():
                        hops[hop_nb] = hop_ip
                except:
                    ips[target] = pre_construct_traceroute_hops(min_ttl, max_ttl)
                    hops = ips[target]
                    if hop_nb in hops.keys():
                        hops[hop_nb] = hop_ip
            line = fd.readline()
    pbar.close()

    ### Now print routing loops
    rl_count = 0
    for ip in ips:
        if is_loop(ips[ip], args["delta"]):
            str_ip = int_to_ip(ip)
            print(str_ip + ":")
            for hop in sorted(ips[ip].keys()):
                if ips[ip][hop] == 0:
                    print(hop, "*")
                else:
                    print(hop, int_to_ip(ips[ip][hop]))
            rl_count += 1

    sys.stderr.write("Out of %d IPs that have an ICMP Time Exceeded meassage sent for, you found %d IPs with qualifying routing loops on path\n" % (len(ips), rl_count))
    del ips


def get_args():
    """
    Parses args
    """
    parser = argparse.ArgumentParser(description='Find routing loops in a single/combined .yrp file')
    parser.add_argument('-f', '--file', action='store', required=True)
    parser.add_argument('-m', '--min_ttl', action='store', required=True, type=int)
    parser.add_argument('-l', '--max_ttl', action='store', required=True, type=int)
    parser.add_argument('-d', '--delimeter', action='store', default=' ')
    parser.add_argument('-t', '--delta', action='store', default=2, type=int)
    return parser.parse_args()


def main():
    prereq()
    process_file(vars(get_args()))


if __name__ == "__main__":
    main()
