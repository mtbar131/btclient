#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "bt_lib.h"


void get_piece(int sockfd, int piece, metainfo_t *metainfo) {
    bt_msg_t msg;
    char mbuf[128];
    int remaining = piece_size(piece, metainfo);
    uint32_t block_size = 16384;
    uint32_t offset = 0;
    int REQUEST_MSG_LEN = 17;


    while (remaining > 0) {
	int read_size = min(remaining, block_size);

	bzero((void*) mbuf, 128);
	msg.length = htonl(0xd);
	msg.bt_type = 0x6;
	msg.payload.request.index = htonl(piece);
	msg.payload.request.begin = htonl(offset);
	msg.payload.request.length = htonl(read_size);
	memcpy(mbuf, &msg, REQUEST_MSG_LEN);

	tcp_send(sockfd, mbuf, REQUEST_MSG_LEN);

	remaining -= read_size;
	offset += read_size;
	//free(blk);
    }

}

int main(int argc, char **argv) {
    if (argc != 2) {
	exit(0);
    }

    // first read the the torrent file as a binary string
    metainfo_t *metainfo = parse_metainfo_file(argv[1]);
    
    printf("announce: %s\n", metainfo->announce);
    printf("piece length: %d\n", metainfo->info->piece_length);
    printf("file name: %s\n", metainfo->info->filename);
    printf("file length: %d\n", metainfo->info->file_length);
    printf("Piece count: %d\n", metainfo->info->num_pieces);

    //request_tracker(metainfo);

    // read ip list and connect to peers
    peer_list *pl = get_peer_list();

    // handshake with peer
    char *delim = ":";
    char *ip = strtok(pl->infoarr[0].url, delim);
    int port = atoi(strtok(NULL, delim));
    int sockfd = peer_tcp_connect(ip, port);
    char outbuf[1024];
    char *mbuf;
    handshake_msg_t *hresponse;

    hresponse = bt_handshake(sockfd, metainfo);

    strcpy(outbuf, "Peer ID: ");
    strncat(outbuf, hresponse->peerid, 21);
    printf("%s\n", outbuf);

    int msg_len = bt_unchoke_msg(&mbuf, metainfo);
    msg_len = tcp_send(sockfd, mbuf, msg_len);
    
    msg_len = bt_interested_msg(&mbuf, metainfo);
    msg_len = tcp_send(sockfd, mbuf, msg_len);

    pthread_t receiver;
    recv_data d;
    d.sockfd = sockfd;
    d.metainfo = metainfo;
    pthread_create(&receiver, NULL, tcp_recv, (void*) &d);

    get_piece(sockfd, 0, metainfo);

    sleep(5);
    write_piece(0);

    pthread_join(receiver, NULL);
    return 0;
}


