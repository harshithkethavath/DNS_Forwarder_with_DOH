import argparse
import os
import logging
import socket
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR
import dns.resolver
import requests
import base64
from scapy.all import DNS, DNSQR, DNSRR



# Set default server settings
DNS_PORT = 5323
DNS_SERVER_HOSTNAME = socket.gethostname() + '.cs.uga.edu'

# Define DNS query type mappings
dns_qtype_map = {
    1: "A",
    28: "AAAA",
    15: "MX",
    2: "NS",
    5: "CNAME"
}

# Parser for creating command line of DoH-capable DNS forwarder
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="A simple DNS forwarder with domain blocking and DoH capabilities"
    )

    parser.add_argument(
        "-d", metavar="--DST_IP",
        type=str,
        help="Destination DNS server IP address for standard DNS forwarding (required if neither --doh nor --doh_server is provided)."
    )

    parser.add_argument(
        "-f", metavar="--DENY_LIST_FILE",
        type=str,
        required=True,
        help="Path to the file containing the list of domains to block"
    )

    parser.add_argument(
        "-l", metavar="--LOG_FILE",
        type=str,
        help="Path and name of log file to record all DNS requests and their status (append-only)."
    )

    parser.add_argument(
        "--doh",
        action="store_true",
        help="Use the default upstream DNS server"
    )

    parser.add_argument(
        "--doh_server",
        type=str,
        help="Use this upstream DoH server"
    )

    args = parser.parse_args()

    # Validation Logic

    # Ensure either a -d or -doh or -doh_server is provided
    if not args.d and not args.doh and not args.doh_server:
        parser.error("Either --DST_IP (-d) or a DoH option (--doh or --doh_server) must be provided.")

    # Ensure deny list file exists
    if not os.path.isfile(args.f):
        parser.error(f"The deny list file '{args.f}' does not exist. Please provide a valid file path.")
    
    return args

#############################################################################################

def load_deny_domains_to_list(deny_list_file):
    if not os.path.exists(deny_list_file):
        raise FileNotFoundError(f"Deny list file '{deny_list_file}' not found.")
    
    with open(deny_list_file, 'r') as file:
        deny_list = {line.strip() for line in file}
    return deny_list

#############################################################################################

def setup_logger(log_file_path):
    log_format = "%(message)s"
    
    # Configure the logging with the specified file and format
    logging.basicConfig(
        filename=log_file_path,
        filemode='a',  # Append mode
        format=log_format,
        level=logging.INFO
    )
    
    # Create the logger instance and return it
    logger_instance = logging.getLogger()
    return logger_instance

#############################################################################################

# Function to initialize the server socket
def initialize_dns_server():
    try:

        #creting a Socket (UDP)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Binding  socket to teh histname and the port
        server_socket.bind((DNS_SERVER_HOSTNAME, DNS_PORT))

        print(f'DNS Server initialized on {DNS_SERVER_HOSTNAME}:{DNS_PORT}.')
        print(f'Usage: dig -p {DNS_PORT} @{DNS_SERVER_HOSTNAME} <query_type> <domain>')

        return server_socket
    
    except socket.error as err:
        print(f"Error initializing the DNS server: {err}")
        return None

#############################################################################################

# main script
args = parse_arguments()
deny_list = load_deny_domains_to_list(args.f) # set of denied domains
# print(deny_list)
logger = setup_logger(args.l)


############################################################################################# -d refactoring


def create_nxdomain_response(dns_query):
    #Generate an NXDOMAIN response for blocked domains
    return DNSRecord(
        DNSHeader(
            id=dns_query.header.id,
            qr=1,
            aa=1,
            ra=1,
            rcode=3
            ),  # rcode 3 = NXDOMAIN

        q = DNSQuestion(
            str(dns_query.q.qname)[:-1],
            qtype=dns_query.q.qtype
            )
    )


def forward_dns_query(dns_query, dns_server):
    #Forward DNS query to an external DNS server
    dns_reslvr = dns.resolver.Resolver()
    dns_reslvr.nameservers = [dns_server]

    answer = dns_reslvr.resolve(str(
                                dns_query.q.qname)[:-1],
                                dns_query.q.qtype
                            )

    flags = extr_flg(answer.response.flags)

    response = DNSRecord(

        DNSHeader(
            id=dns_query.header.id,
            qr=flags['QR'],
            aa=flags['AA'],
            ra=flags['RA'],
            rd=flags['RD'],
            ad=flags['AD'],
            rcode=answer.response.rcode()
        ),

        q=DNSQuestion(str(
                        dns_query.q.qname)[:-1],
                        qtype=dns_query.q.qtype
                    )
    )

    # Check if the query type is MX and requires further resolution
    if dns_query.q.qtype == dns.rdatatype.MX:
        mx_record = answer.response.answer[0][0].to_text()[2:-1]  # Extract MX target domain

        # Perform a second query to resolve the IP address of the mail server
        smtp_answer = dns_reslvr.resolve(mx_record, 'A')

        # Add the SMTP server's A records to the response
        for record in smtp_answer.response.answer:
            response.add_answer(*RR.fromZone(str(record)))
    else:
        # For non-MX queries, directly add the answer records to the response
        for record in answer.response.answer:
            response.add_answer(*RR.fromZone(str(record)))

    return response


def extr_flg(flags):
    #Extract specific flags from the DNS response flags
    return {flag: int(flags & getattr(dns.flags, flag) != 0)
            for flag in ['AA', 'TC', 'RD', 'RA', 'AD', 'CD', 'QR']}


#############################################################################################


# Handle DNS forwarding or blocking based on arguments
if args.d:
    print(f"Opening UDP DNS server mode on {args.d}")
    server_socket = initialize_dns_server()

    while True:
        data, client_address = server_socket.recvfrom(4096)

        dns_query = DNSRecord.parse(data)
        domain_name = str(dns_query.q.qname)[:-1]
        query_type = dns_qtype_map.get(dns_query.q.qtype, "UNKNOWN")

        # Check if the domain is in the deny list
        if domain_name in deny_list:
            logger.info(f'{domain_name} {query_type} DENY')
            response = create_nxdomain_response(dns_query)

        else:
            logger.info(f'{domain_name} {query_type} ALLOW')
            response = forward_dns_query(dns_query, args.d)

        # Send response back to the client
        server_socket.sendto(response.pack(), client_address)


#############################################################################################


elif (args.doh or args.doh_server) :
    
    sock = initialize_dns_server()
    data = ''

    while True :
        data, client_address = sock.recvfrom(4096)
        query = DNSRecord.parse(data)       

        # Extract the domain name from the query
        domain_name = str(query.q.qname)[:-1]
        domain_type = query.q.qtype
        qtype = dns_qtype_map.get(query.q.qtype, "UNKNOWN")

        req = DNS(rd=1, qd = DNSQR(qname = domain_name, qtype = domain_type))
        b = bytes(req)

        if (args.doh):
            url = ''.join(['https://','8.8.8.8','/dns-query','?dns=', base64.urlsafe_b64encode(b).rstrip(b'=').decode()])

        else:
            url = ''.join(['https://',args.doh_server,'/dns-query','?dns=', base64.urlsafe_b64encode(b).rstrip(b'=').decode()])
        

        headers = {'content-type': 'application/dns-message'}
        r = requests.get(url, headers=headers, timeout=10) # send r.content to client

        output = DNS(r.content)
        flags = [output.qr,
                    output.rd,
                    output.ra,
                    output.ad,
                    output.aa]


        response = DNSRecord(DNSHeader
                                (id=query.header.id,
                                    qr = flags[0],
                                    rd = flags[1],
                                    ra = flags[2],
                                    ad = flags[3],
                                    aa = flags[4],
                                    rcode= output.rcode), 
                                    q = DNSQuestion(domain_name, qtype = query.q.qtype))
        

        if domain_name in deny_list :

            # logging 
            logger.info(f'{domain_name} {qtype} DENY')

            # setting rcode to NXDomain
            response.header.rcode = 3

        else :

            logger.info(f'{domain_name} {qtype} ALLOW')

            for dns_rr in output[DNSRR]:
                rr_data = f"{domain_name} {dns_rr.ttl} IN {qtype} {dns_rr.rdata}"
                response.add_answer(*RR.fromZone(str(rr_data)))

        sock.sendto(response.pack(), client_address)