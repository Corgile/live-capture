//demo
#include <pcap.h>
#include <pthread.h>
#include "stdlib.h"

#include "unistd.h"
#define SNAP_LEN 65535

/* prototype of the headers handler */
void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);
void *thr_fn1(void *arg);
void *thr_fn2(void *arg);
void *thr_fn3(void *arg);

pcap_t *handle1, *handle2;                /* headers capture handle */
int CAP_TIME = 600;
pthread_t t1, t2, t3;

int main(int argc, char **argv)
{
    char *dev1 = NULL;
    char *dev2 = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];        /* error buffer */
    pcap_if_t *alldev, *p;
    char filter_exp[] = "tcp";        /* filter expression [3] */
    struct bpf_program fp1,fp2;            /* compiled filter program (expression) */
    bpf_u_int32 mask;            /* subnet mask */
    bpf_u_int32 net;            /* ip */
    /* check for capture device name on command-line */
    if (argc == 3) {    //pre-define the two device's names to be captured
        dev1 = argv[1];
        dev2 = argv[2];
    }
    else if (argc > 3 || argc == 2) {
        fprintf(stderr, "error: unrecognized command-line options\n\n");
        exit(EXIT_FAILURE);
    }
    printf("please input the capture time\n");
    scanf("%d",&CAP_TIME);
    /* print capture info */
    printf("1st device: %s\n", dev1);
    /* open capture device */
    handle1 = pcap_open_live(dev1, SNAP_LEN, 1, 1000, errbuf);
    if (handle1 == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev1, errbuf);
        exit(EXIT_FAILURE);
    }
    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle1) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev1);
        exit(EXIT_FAILURE);
    }
    /* compile the filter expression */
    if (pcap_compile(handle1, &fp1, filter_exp, 0, 24) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle1));
        exit(EXIT_FAILURE);
    }
    /* apply the compiled filter */
    if (pcap_setfilter(handle1, &fp1) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle1));
        exit(EXIT_FAILURE);
    }
    /* print capture info */
    printf("2nd device: %s\n", dev2);
    printf("Filter expression: %s\n", filter_exp);
    printf("Caputre time: %d\n", CAP_TIME);
    /* open capture device */
    handle2 = pcap_open_live(dev2, SNAP_LEN, 1, 1000, errbuf);
    if (handle2 == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev2, errbuf);
        exit(EXIT_FAILURE);
    }
    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle2) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev2);
        exit(EXIT_FAILURE);
    }
    /* compile the filter expression */
    if (pcap_compile(handle2, &fp2, filter_exp, 0, 24) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle2));
        exit(EXIT_FAILURE);
    }
    /* apply the compiled filter */
    if (pcap_setfilter(handle2, &fp2) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle2));
        exit(EXIT_FAILURE);
    }
    pthread_create(&t1, NULL, thr_fn1, NULL);
    pthread_create(&t2, NULL, thr_fn2, NULL);
    pthread_create(&t3, NULL, thr_fn3, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    pcap_freecode(&fp1);
    pcap_freecode(&fp2);
    pcap_close(handle1);
    pcap_close(handle2);
    printf("\nCapture complete.\n");
    return 0;
}
void dispatcher_handler(u_char *temp1,
                        const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    printf("I get one headers!\n");
}
void *thr_fn1(void *arg)
{
    pcap_loop(handle1, 0, dispatcher_handler, NULL);
    //pthread_cancel( t2 );
}
void *thr_fn2(void *arg)
{
    pcap_loop(handle2, 0, dispatcher_handler, NULL);
    //pthread_cancel( t1 );
}
void *thr_fn3(void *arg)
{
    sleep(CAP_TIME);
    pthread_cancel( t1 );
    pthread_cancel( t2 );
}
