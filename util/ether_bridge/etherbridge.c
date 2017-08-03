/*
 * Based on tcpdump sniffer, arpsniffer code and Micky Holdorf's packetforward project.
 *
 */

#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include "headers.h"

char *dev = NULL;						/* capture device1 name */
char *dev2 = NULL;						/* capture device2 name */

pcap_t *handler=NULL;			    /* packet capture handler */
pcap_t *handler2=NULL;				/* packet sending handler2 */

int hide_hdr = 0;
int hide_payload = 1;
int capture_only = 1;
int unidirectional = 0;
int num_pkts = -1;					/* number of packets to capture */
char *bpfFilter = NULL;				    /* filter expression */

extern char *optarg;
extern int optind, opterr;

void fwd_to_handler2(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet);
void fwd_to_handler(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet);
void fwd_packet(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet, pcap_t *fwd_dev);

/**
 * Compile and apply the filter expression.
 */
int set_filter(pcap_t *handle,struct bpf_program *fp,const char*bpfFilter){
    if(bpfFilter != NULL) {
        printf("Packet Filter: %s\n", bpfFilter);
        if (pcap_compile(handle, fp, bpfFilter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", bpfFilter, pcap_geterr(handle));
            return(2);
        }
        if (pcap_setfilter(handle, fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", bpfFilter, pcap_geterr(handle));
            return(2);
        }
    }
    return 0;
}

/**
 * open a pcap handler and init it.
 */
pcap_t * open_and_init(const char *dev_name, const char *bpfFilter) {
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];			/* error buffer */
    struct bpf_program fp;					/* compiled filter program (expression) */
    /* open capture device*/
    if((handle= pcap_open_live(dev_name, BUFSIZ, 1, 100, errbuf))==NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev_name, errbuf);
        return NULL;
    }

    /* make sure we're capturing on an Ethernet device */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet hdrs - not supported\n", dev_name);
        return NULL;
    }

    pcap_setdirection(handle,PCAP_D_IN);

    /* compile and apply the filter expression */
    if(set_filter(handle,&fp,bpfFilter)!=0){
        fprintf(stderr, "Error when setting filter to %s\n", dev_name);
        return NULL;
    }
    return handle;
}

/**
 * got packet at dev, and try to fwd to dev2.
 */
void fwd_to_handler2(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet) {
    if(_DEBUG_) printf("fwd_to_handler2\n");
    fwd_packet(args, hdr, packet,handler2);
}

/**
 * got packet at dev2, and try to fwd to dev.
 */
void fwd_to_handler(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet) {
    if(_DEBUG_) printf("fwd_to_handler\n");
    fwd_packet(args, hdr, packet,handler);
}
/**
 * try to see if need to send out the given pkt. 
 */
void fwd_packet(u_char *args, const struct pcap_pkthdr *hdr, const u_char *packet,pcap_t *fwd_dev) {
    if(_DEBUG_) {
        static int count = 1;    /* packet counter */
        printf("Received pkt F#%i:\n",count++);
    }
    if (parse_pkt(packet,hide_hdr,hide_payload)>=0) {
        if (!capture_only && fwd_dev != NULL) {
            send_packet(fwd_dev,packet,hdr->len);
        }
    }
    return;
}

/**
 * processing for a thread.
 */
void *got_pkt(void *device_name) {
    if(strcmp(device_name,dev)==0){
        if(pcap_loop(handler, num_pkts, fwd_to_handler2, NULL)==-1) {
             fprintf(stderr, "ERROR: %s\n", pcap_geterr(handler));
             return NULL;
        }
        if (handler != NULL) pcap_close(handler);
    } else if(strcmp(device_name,dev2)==0){
        if(pcap_loop(handler2, num_pkts, fwd_to_handler, NULL)==-1) {
            fprintf(stderr, "ERROR: %s\n", pcap_geterr(handler2));
            return NULL;
        }
        if (handler2 != NULL) pcap_close(handler2);
    }
    return NULL;
}

int main(int argc, char **argv) {
    int c;
    pthread_t t1,t2;

    /* check command-line options */
    while ((c = getopt(argc, argv, "i:I:n:uhpf:")) != EOF) {
        switch (c) {
            case 'i':
                dev = optarg; //the capture device
                dev2 = dev;	
                break;
            case 'I':
                dev2 = optarg; //the forward device
                if(dev2 == dev){
                    fprintf(stderr, "Should use different interface to forward\n");
                    return 0;
                } else {
                    capture_only = 0;
                }
                break;
            case 'n':
                num_pkts = atoi(optarg);
                break;
            case 'f':
                printf("num_pkts= %d, dev2=%s\n", num_pkts, dev2);
                bpfFilter = strdup(optarg);
                break;
            case 'h':
                hide_hdr = 1;
                break;
            case 'p':
                hide_payload = 1;
                break;
            case 'u':
                unidirectional = 1;
                break;
            default:
                print_usage(argv[0]);
                return 0;
        }
    }

    if (dev == NULL) {
        print_usage(argv[0]);
        return -1;
    }

    if(num_pkts > 0) printf("Packets to capture: %d\n", num_pkts);

    handler = open_and_init(dev,bpfFilter);
    if (!capture_only){
        handler2 = open_and_init(dev2,bpfFilter);
    }
    if (!unidirectional) {
        printf("Bidirectional process between: %s, %s\n", dev, dev2);
        pthread_create(&t1, NULL, got_pkt, (void*) dev);
        pthread_create(&t2, NULL, got_pkt, (void*) dev2);
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
    } else {
        printf("unidirectional process from %s to %s\n", dev, dev2);
        pthread_create(&t1, NULL, got_pkt, (void*) dev);
        pthread_join(t1, NULL);
        /*
        if(pcap_loop(handler, num_pkts, fwd_to_handler2, NULL)==-1){
            fprintf(stderr, "ERROR: %s\n", pcap_geterr(handler));
            return 2;
        }
        */
    }
    /* cleanup */
    if (handler != NULL) pcap_close(handler);
    if (handler2 != NULL) pcap_close(handler2);
    printf("\n\n--- Process complete. ---\n\n");
    return 0;
}
