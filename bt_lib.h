#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <math.h>
#include <curl/curl.h>
#include <poll.h>
#include "bencode/bencode.h"

typedef struct metainfo_t {
    char *announce;
    struct metainfo_info_t *info;
    int creation_time;
    char *comments;
    char *created_by;
    char *encoding;
} metainfo_t;

typedef struct metainfo_info_t {
    unsigned char *infohash;
    int piece_length;
    char *piece_hashes;
    char *filename;
    int file_length;
    int num_pieces;
} metainfo_info_t;


typedef struct peer_info {
    char *url;
    char *id;
} peer_info;

typedef struct peer_list {
    int size;
    peer_info *infoarr;
} peer_list;

typedef struct __attribute__((__packed__)) handshake_msg_t {
    char prtlen;
    char protoname[19];
    char reserved[8];
    char infohash[20];
    char peerid[20];
} handshake_msg_t;


/* Taken from 
   https://www.cs.swarthmore.edu/~aviv/classes/f12/cs43/labs/lab5/lab5.pdf */

typedef struct __attribute__((__packed__)) {
    char * bitfield; //bitfield where each bit represents a piece that
//the peer has or doesn’t have
    size_t size;//size of the bitfiled
} bt_bitfield_t;

typedef struct __attribute__((__packed__)) {
    int index; //which piece index
    int begin; //offset within piece
    int length; //amount wanted, within a power of two
} bt_request_t;

typedef struct __attribute__((__packed__)) {
    int index; //which piece index
    int begin; //offset within piece
    char piece[0]; //pointer to start of the data for a piece
} bt_piece_t;

typedef struct __attribute__((__packed__)) {
    int length; //prefix length, size of remaining message
//0 length message is a keep-alive message
    unsigned char bt_type;//type of bt_mesage
//payload can be any of these
    union __attribute__((__packed__)) {
	bt_bitfield_t bitfiled;//send a bitfield
	int have; //index of piece just completed
	bt_piece_t piece; //a piece message
	bt_request_t request; //requxest messge
	bt_request_t cancel; //cancel message, same type as request
	char data[0];//pointer to start of payload, just for convenience
    } payload;
} bt_msg_t;

typedef enum message_type {
    KEEP_ALIVE,
    CHOKE,
    UNCHOKE,
    INTERESTED,
    NOT_INTERESTED,
    HAVE,
    BITFIELD,
    REQUEST,
    PIECE,
    CANCEL,
    PORT
} message_type;

typedef struct recv_data {
    metainfo_t *metainfo;
    int sockfd;
} recv_data;

int piece_size(int piece, metainfo_t *metainfo);

metainfo_t* parse_metainfo_file(char *filepath);

peer_list* get_peer_list();

unsigned char *getSHA1(char *str, int strlen);

int peer_tcp_connect(char *ip, int port);

int peer_tcp_disconnect(int sockfd);

handshake_msg_t* bt_handshake(int sockfd, metainfo_t *metainfo);

int tcp_send(int sockfd, char *send_buf, int send_buf_len);

void* tcp_recv(void* data);

void* peerlisten(void *args);

int min(int a, int b);

int bt_unchoke_msg(char **mbuf, metainfo_t *metainfo);

int bt_choke_msg(char **mbuf, metainfo_t *metainfo);

int bt_interested_msg(char **mbuf, metainfo_t *metainfo);

int bt_request_msg(char **mbuf, metainfo_t *metainfo,
		   int piece, int offset);

void write_piece(int piece);

void request_tracker(metainfo_t *metainfo);
