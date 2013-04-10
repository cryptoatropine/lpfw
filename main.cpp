#include <unistd.h>
#include <stdlib.h> //for malloc
#include <vector>
#include <string>
#include <cstdio>
#include <iostream>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

enum {
    //random base number. To be used with "iptables ... -j NFQUEUE"
    NFQUEUE_NUMBER_BASE = 11220,
    NFQUEUE_NUMBER_OUT_TCP,
    NFQUEUE_NUMBER_OUT_UDP,
    NFQUEUE_NUMBER_OUT_OTHER,
    NFQUEUE_NUMBER_IN_TCP,
    NFQUEUE_NUMBER_IN_UDP,
    NFQUEUE_NUMBER_IN_OTHER
};

enum {
    NOT_ROOT,
    NFQ_CREATE_ERROR,
    PTHREAD_CREATE_ERROR,
    IPTABLES_ERROR
};

void init_nfq_handlers();
void init_iptables_rules();

main () {
    if (getuid() != 0){
        std::cout << "Please re-run lpfw as root/n";
        exit (NOT_ROOT);
    }
    init_nfq_handlers();
    init_iptables_rules();
    //the main program should never quit.
    while (true){
        sleep (1000);
    }
}


class nfqHandler {
    int m_nfq_number;
    struct nfq_handle* m_nfq_handle;
    struct nfq_q_handle* m_nfq_q_handle;
    int m_nfqfd;
    pthread_t m_thread;
    nfq_callback* m_callback;

public:
    nfqHandler(int nfqueue_number, nfq_callback* callback);
    //static wrapper is needed because we can't call ...? (I really forgot why it was needed)
    static void* wrapper(void* parent){ ((nfqHandler*)parent)->threadFoo();}
private:
    void threadFoo ();
};

nfqHandler::nfqHandler(int nfqueue_number, nfq_callback* callback){

    m_callback = callback;
    m_nfq_number =  nfqueue_number;
    m_nfq_handle = nfq_open();
    if ( !m_nfq_handle ) {std::cout << "error during nfq_open\n" ;}
    if ( nfq_unbind_pf ( m_nfq_handle, AF_INET ) < 0) {std::cout << "error during nfq_unbind\n";}
    if ( nfq_bind_pf ( m_nfq_handle, AF_INET ) < 0 ){std::cout << "error during nfq_bind\n" ;}
    m_nfq_q_handle = nfq_create_queue ( m_nfq_handle, m_nfq_number, m_callback, NULL );
    if ( !m_nfq_q_handle )
      {
    std::cout << "error in nfq_create_queue. Please make sure that any other instances of Leopard Flower are not running and restart the program. Exitting\n" ;
    exit (NFQ_CREATE_ERROR);
      }
    //copy only 40 bytes of packet to userspace - just to extract tcp source field
    if ( nfq_set_mode ( m_nfq_q_handle, NFQNL_COPY_PACKET, 40 ) < 0 )
      {std::cout << "error in set_mode\n" ;}
    //there was some glitchy behaviour around 2012 when queue_maxlen was set above 200, needs looking into
    if ( nfq_set_queue_maxlen ( m_nfq_q_handle, 200 ) == -1 )
      {std::cout << "error in queue_maxlen\n" ;}
    m_nfqfd = nfq_fd ( m_nfq_handle);
    std::cout << "nfqueue handler registered\n";

    if (pthread_create ( &m_thread, NULL, wrapper, this) != 0) {
        std::cout << "pthread_create"; exit(PTHREAD_CREATE_ERROR);
    }
}

void nfqHandler::threadFoo(){
   //endless loop of receiving packets and calling a handler on each packet
     int rv;
     char buf[4096] __attribute__ ( ( aligned ) );
     std::cout << "nfqfd " << m_nfqfd << endl;
     while ( ( rv = recv ( m_nfqfd, buf, sizeof ( buf ), 0 ) ) && rv >= 0 )
       {
         nfq_handle_packet ( m_nfq_handle, buf, rv );
       }
 }


int  nfq_handle_out_tcp ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata ){
    cout << "Hooray! TCP OUT works";
    }
int  nfq_handle_out_udp ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata ){
    cout << "Hooray! UDP OUT works";
    }
int  nfq_handle_out_other ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata ){}
int  nfq_handle_in_tcp ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata ){}
int  nfq_handle_in_udp ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata ){}
int  nfq_handle_in_other ( struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *mdata ){}



void init_nfq_handlers(){
    std::vector<nfqHandler*> nfqHandlers;
    nfqHandlers.push_back (new nfqHandler(NFQUEUE_NUMBER_OUT_TCP, nfq_handle_out_tcp));
    nfqHandlers.push_back (new nfqHandler(NFQUEUE_NUMBER_OUT_UDP, nfq_handle_out_udp));
    nfqHandlers.push_back (new nfqHandler(NFQUEUE_NUMBER_OUT_OTHER, nfq_handle_out_other));
    nfqHandlers.push_back (new nfqHandler(NFQUEUE_NUMBER_IN_TCP, nfq_handle_in_tcp));
    nfqHandlers.push_back (new nfqHandler(NFQUEUE_NUMBER_IN_UDP, nfq_handle_in_udp));
    nfqHandlers.push_back (new nfqHandler(NFQUEUE_NUMBER_IN_OTHER, nfq_handle_in_other));
}

void init_iptables_rules(){
    string fixed_part = " -m state --state NEW -j NFQUEUE --queue-num ";
    char NFQUEUE_NUMBER_OUT_TCP_str[6];
    char NFQUEUE_NUMBER_OUT_UDP_str[6];
    char NFQUEUE_NUMBER_OUT_OTHER_str[6];
    char NFQUEUE_NUMBER_IN_TCP_str[6];
    char NFQUEUE_NUMBER_IN_UDP_str[6];
    char NFQUEUE_NUMBER_IN_OTHER_str[6];
    sprintf (NFQUEUE_NUMBER_OUT_TCP_str, "%d", NFQUEUE_NUMBER_OUT_TCP);
    sprintf (NFQUEUE_NUMBER_OUT_UDP_str, "%d", NFQUEUE_NUMBER_OUT_UDP);
    sprintf (NFQUEUE_NUMBER_OUT_OTHER_str, "%d", NFQUEUE_NUMBER_OUT_OTHER);
    sprintf (NFQUEUE_NUMBER_IN_TCP_str, "%d", NFQUEUE_NUMBER_IN_TCP);
    sprintf (NFQUEUE_NUMBER_IN_UDP_str, "%d", NFQUEUE_NUMBER_IN_UDP);
    sprintf (NFQUEUE_NUMBER_IN_OTHER_str, "%d", NFQUEUE_NUMBER_IN_OTHER);

    if ((system("iptables -A INPUT -d localhost -j ACCEPT") == -1) ||
        (system("iptables -A OUTPUT -d localhost -j ACCEPT") == -1) ||
        (system((string("iptables -A OUTPUT -p tcp") + fixed_part + NFQUEUE_NUMBER_OUT_TCP_str + " ").c_str()) == -1) ||
        (system((string("iptables -A OUTPUT -p udp") + fixed_part + NFQUEUE_NUMBER_OUT_UDP_str + " ").c_str()) == -1) ||
        (system((string("iptables -A OUTPUT -p all") + fixed_part + NFQUEUE_NUMBER_OUT_OTHER_str + " ").c_str()) == -1) ||
        (system((string("iptables -A INPUT -p tcp") + fixed_part + NFQUEUE_NUMBER_IN_TCP_str + " ").c_str()) == -1) ||
        (system((string("iptables -A INPUT -p udp") + fixed_part + NFQUEUE_NUMBER_IN_UDP_str + " ").c_str()) == -1) ||
        (system((string("iptables -A INPUT -p all") + fixed_part + NFQUEUE_NUMBER_IN_OTHER_str + " ").c_str()) == -1)){
        std::cout << "iptables error"; exit(IPTABLES_ERROR);
    }
}
