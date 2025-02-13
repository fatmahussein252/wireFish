
			/* The network layer (IP protocol)*/
class IP{
	protected:
	struct iphdr *ip;
	
	public:
	void print_ip_header();
	unsigned int get_ip_protocol();
	IP(const unsigned char *packet);
	~IP(){}

};


			/* The transport layer */
			
class TransportLayer: virtual public IP{
public:
    //TransportLayer() {printf("transportlayer constructor\n");}	
    virtual void print_transport_header() = 0;  // Pure virtual function
    virtual unsigned int get_src_port() = 0;
    virtual unsigned int get_dest_port() = 0;
    virtual unsigned int get_hdr_len() = 0;
    virtual ~TransportLayer() {/*printf("transportlayer destructor\n");*/}  // Virtual destructor
};
			
/* The TCP protocol */
class TCP: public TransportLayer{
	
	protected:
	struct tcphdr *tcp;
	public:
	
	TCP(const unsigned char *packet);
	~TCP(){}
	
	
	// The TCP header print method
	void print_transport_header() override;

	unsigned int get_src_port()override;

	unsigned int get_dest_port()override;
	unsigned int get_hdr_len()override;
};


/* The UDP protocol */
class UDP: public TransportLayer{
	
	protected:
	struct udphdr *udp;
	
	public:
	UDP(const unsigned char *packet);
	~UDP(){}
	
	// The UDP header print method
	void print_transport_header()override;


	unsigned int get_src_port()override;
	unsigned int get_dest_port()override;

	unsigned int get_hdr_len()override;
};




/* The ICMP protocol */
class ICMP: public IP{
	protected:
	struct icmphdr *icmp;
	
	public:
	ICMP(const unsigned char *packet);
	void print_icmp_header();
	~ICMP(){}
};


			/* The application layer */
class http: public TCP{
	public:
	http(const unsigned char *packet);
	void print_http_header(const unsigned char *packet);
	~http(){}
};


// Structure to represent a DNS Header (12 bytes)
struct dnshdr {
    uint16_t id;       // Identification
    uint16_t flags;    // Flags
    uint16_t qdcount;  // Number of Questions
    uint16_t ancount;  // Number of Answers
    uint16_t nscount;  // Number of Authority Records
    uint16_t arcount;  // Number of Additional Records
};


class DNS: public IP{
	private:
	struct dnshdr *dns;
	const unsigned char* payload;

	
	public:
	DNS(const unsigned char *packet, TransportLayer* transport);
	void parse_dns_header();
	void parse_domain_name();
	~DNS(){}

};



char* filter_type(int argc, char **argv);


