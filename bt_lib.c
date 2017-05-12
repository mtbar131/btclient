#include "bt_lib.h"


char **piece_data = NULL;

int min(int a, int b) {
    if (a > b)
	return b;
    return a;
}

void init_storage(metainfo_t *metainfo) {
    int i;
    piece_data = (char**) malloc (sizeof(char*) * metainfo->info->num_pieces);
    for (i = 0; i < metainfo->info->num_pieces; i++)
	piece_data[i] = NULL;
}

int piece_size(int piece, metainfo_t *metainfo) {
    if (piece >= metainfo->info->num_pieces)
	return -1;
    int file_len = metainfo->info->file_length;
    int piece_len = metainfo->info->piece_length;
    return min(file_len - piece_len * piece, piece_len);
}

static void parse_metainfo(metainfo_t *metainfo, bencode_t *value,
			   const char *key) {
    if (strcmp(key, "announce") == 0) {
	int len;
	const char *url;
	bencode_string_value(value, &url, &len);
	metainfo->announce = (char*) malloc (len);
	strncpy(metainfo->announce, url, len);
	metainfo->announce[len] = 0;
    } else if (strcmp(key, "info") == 0) {
	int info_dict_len;
	const char *start;
	bencode_dict_get_start_and_len(value, &start, &info_dict_len);
	char *dict_str = (char*) malloc (info_dict_len + 1);
	memcpy(dict_str, start, info_dict_len);
	metainfo->info->infohash = getSHA1(dict_str, info_dict_len);
	while (bencode_dict_has_next(value)) {
	    const char *tempkey;
	    int templen;
	    bencode_t *tempvalue = (bencode_t*) malloc (sizeof(bencode_t));
	    bencode_dict_get_next(value, tempvalue, &tempkey, &templen);
	    char *keybuf = (char*) malloc (templen + 1);
	    strncpy(keybuf, tempkey, templen);
	    keybuf[templen] = 0;
	    parse_metainfo(metainfo, tempvalue, keybuf);
	}
	metainfo->info->num_pieces = (int) ceil((double) metainfo->info->file_length /
						(double) metainfo->info->piece_length);
    } else if (strcmp(key, "piece length") == 0) {
	long int plen;
	bencode_int_value(value, &plen);
	metainfo->info->piece_length = plen;
    } else if (strcmp(key, "pieces") == 0) {
	const char *piece_hashes;
	int len;
	bencode_string_value(value, &piece_hashes, &len);
	metainfo->info->piece_hashes = (char*) malloc (len);
	strncpy(metainfo->info->piece_hashes, piece_hashes, len);
    } else if (strcmp(key, "name") == 0) {
	const char *name;
	int len;
	bencode_string_value(value, &name, &len);
	metainfo->info->filename = (char*) malloc (len);
	strncpy(metainfo->info->filename, name, len);
    } else if (strcmp(key, "length") == 0) {
	long int plen;
	bencode_int_value(value, &plen);
	metainfo->info->file_length = plen;
    }
}


metainfo_t* parse_metainfo_file(char *filepath) {
    struct stat stat_buf;
    stat(filepath, &stat_buf);
    char *metainfo_buffer = (char*) malloc ((int) (stat_buf.st_size + 1));
    int metainfo_len = 0;
    char read_buf[1024];
    int fd = open(filepath, O_RDONLY);
    if (fd <= 0) {
	perror("Unable to open metainfo file. Exiting\n");
	exit(0);
    }

    int read_count = 0;
    while ((read_count = read(fd, read_buf, 1024)) > 0) {	
    	memcpy(metainfo_buffer + metainfo_len, read_buf, read_count);
    	metainfo_len += read_count;
    }
    metainfo_buffer[metainfo_len] = 0;

    bencode_t *bendata = (bencode_t*) malloc (sizeof(bencode_t));
    bencode_init(bendata, metainfo_buffer, metainfo_len);
    
    metainfo_t *metainfo = (metainfo_t*) malloc (sizeof(metainfo_t));
    metainfo->info = (metainfo_info_t*) malloc (sizeof(metainfo_info_t));

    while (bencode_dict_has_next(bendata)) {
	bencode_t *value = (bencode_t*) malloc (sizeof(bencode_t));
	const char *key;
	char *keybuf;
	int keylen;
	bencode_dict_get_next(bendata, value, &key, &keylen);
	keybuf = (char*) malloc (keylen + 1);
	strncpy(keybuf, key, keylen);
	keybuf[keylen] = 0;
	parse_metainfo(metainfo, value, keybuf);
    }
    return metainfo;
}


void request_tracker(metainfo_t *metainfo) {
    char *request = (char*) malloc (1024);
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    if (curl && request != NULL) {
	char *escaped_info_hash = curl_easy_escape(curl,
						   (const char*) metainfo->info->infohash,
						   20);	
	printf("Escpaed info has: %s\n", escaped_info_hash);
	printf("announce url: %s\n", metainfo->announce);
	printf("file length: %d\n", metainfo->info->file_length);
	/* prepare requst */
	snprintf(request, 1024,
		 "%s/?info_hash=%s&"
		 "peer_id=-LT112-1234567898765&"
		 "port=6881&"
		 "uploaded=0&"
		 "downloaded=0&"
		 "left=%d&"
		 "compact=1&"
		 "event=started",
		 metainfo->announce,
		 escaped_info_hash,
		 metainfo->info->file_length);
	     

    	curl_easy_setopt(curl, CURLOPT_URL, request);
    	/* example.com is redirected, so we tell libcurl to follow redirection */
    	/* curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); */
 
    	/* Perform the request, res will get the return code */
    	res = curl_easy_perform(curl);

    	/* Check for errors */
    	if(res != CURLE_OK)
    	    fprintf(stderr, "curl_easy_perform() failed: %s\n",
    		    curl_easy_strerror(res));
 
    	/* always cleanup */
    	curl_easy_cleanup(curl);
    }
}

peer_list* get_peer_list() {
    peer_list *pl = (peer_list*) malloc (sizeof(peer_list));
    pl->size = 0;
    pl->infoarr = (peer_info*) malloc (50 * sizeof(peer_info));
    
    int peerfile_fd = open("peerlist", O_RDONLY);
    char buf[1024];
    int read_count;
    while (1) {
	int i = 0;
	int ch;
	
	while ((read_count = read(peerfile_fd, &ch, 1)) > 0 &&
	       ch != '\n') {
	    // printf("%c", ch);
	    buf[i++] = ch;
	}	
	buf[i] = 0;

	if (read_count <= 0)
	    break;

	if (pl->size < 50) {
	    pl->infoarr[pl->size].url = (char*) malloc (64);
	    pl->infoarr[pl->size].id = (char*) malloc (128);
	    strncpy(pl->infoarr[pl->size].url, buf, i);
	    pl->size++;
	} else {
	    break;
	}
    }
    return pl;
}

unsigned char *getSHA1(char *str, int strlen) {
    unsigned char *digest = (unsigned char*) malloc (SHA_DIGEST_LENGTH);
    SHA1((const unsigned char*)str, strlen, digest);
    return digest;
}

/* Returns socket discriptor for this tcp connection */
/* Code referred from http://www.linuxhowtos.org/data/6/client.c */
int peer_tcp_connect(char *ip, int port) {
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket\n");
	return -1;
    }

    server = gethostbyname(ip);
    if (server == NULL) {
        perror("ERROR, no such host\n");
	return -1;
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
	  (char *)&serv_addr.sin_addr.s_addr,
	  server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR connecting");
	return -1;
    }

    printf("Successfully connected to %s:%d\n", ip, port);
    return sockfd;
}

int peer_tcp_disconnect(int sockfd) {
    return close(sockfd);
}

/* Returns number of bytes read from socket */
int tcp_send(int sockfd, 
	     char *send_buf, int send_buf_len) {
    int nsent;
    nsent = write(sockfd, send_buf, send_buf_len);
    if (nsent < 0) {
	perror("ERROR writing to socket\n");
	return -1;
    }

    return nsent;
}




handshake_msg_t* bt_handshake(int sockfd, metainfo_t *metainfo) {
    char* mbuf = (char*) malloc (128);
    handshake_msg_t request;
    int HANDSHAKE_MSG_LEN = 68;
	
    bzero((void*) &request, sizeof(handshake_msg_t));
    bzero((void*)mbuf, 128);

    request.prtlen = 0x13; // hex 13 => dec 19 length of protocol name
    memcpy(request.protoname, "BitTorrent protocol", 19); // protocol name
    memcpy(request.infohash, metainfo->info->infohash, 20); // info hash of torrent
    memcpy(request.peerid, "-LT112-1234567898765", 20); // Client ID
    memcpy(mbuf, &request, HANDSHAKE_MSG_LEN);
    
    tcp_send(sockfd, mbuf, HANDSHAKE_MSG_LEN);
    recv(sockfd, mbuf, HANDSHAKE_MSG_LEN, MSG_WAITALL);
    
    /* Handshake was successful. Do initializations */
    init_storage(metainfo);

    return (handshake_msg_t*) (mbuf);
}


int bt_choke_msg(char **mbuf, 
			metainfo_t *metainfo) {

    bt_msg_t request;
    int CHOKE_MSG_LEN = 5;
    *mbuf = (char*) malloc (16);

    bzero((void*) &request, sizeof(bt_msg_t));
    bzero((void*)*mbuf, CHOKE_MSG_LEN);

    request.length = htonl(0x1); // hex 1 => dec 1 == length of unchoke msg
    request.bt_type = 0x0; // type of unchoke msg
    // 5 is length of handshake message:
    // 4 Bytes for length + 1 Byte  for ID
    memcpy(*mbuf, &request, CHOKE_MSG_LEN); 
    
    return CHOKE_MSG_LEN;
}

static int bt_choke_msg_handler() {
    return 0;
}

int bt_unchoke_msg(char **mbuf, metainfo_t *metainfo) {

    bt_msg_t request;
    int UNCHOKE_MSG_LEN = 5;
    *mbuf = (char*) malloc (16);

    bzero((void*) &request, sizeof(bt_msg_t));
    bzero((void*)*mbuf, UNCHOKE_MSG_LEN);
    // all messages should be sent in BigEndian order
    // Hower my machine uses little endian order so conver this 4byte int to
    // Bit endian order
    request.length = htonl(0x1); 
    request.bt_type = 0x1;
    // 5 is length of handshake message:
    // 4 Bytes for length + 1 Byte  for ID
    memcpy(*mbuf, &request, UNCHOKE_MSG_LEN);
    
    return UNCHOKE_MSG_LEN;
}

static int bt_unchoke_msg_handler() {
    return 0;
}

int bt_interested_msg(char **mbuf, metainfo_t *metainfo) {

    bt_msg_t request;
    int INTERESTED_MSG_LEN = 5;
    *mbuf = (char*) malloc (16);

    bzero((void*) &request, sizeof(bt_msg_t));
    bzero((void*)*mbuf, INTERESTED_MSG_LEN);

    request.length = htonl(0x1); // hex 1 => dec 1 == length of unchoke msg
    request.bt_type = 0x2; // type of unchoke msg
    // 5 is length of handshake message:
    // 4 Bytes for length + 1 Byte  for ID
    memcpy(*mbuf, &request, INTERESTED_MSG_LEN); 
    
    return INTERESTED_MSG_LEN;    
}

static int bt_interested_msg_handler() {
    return 0;
}

// write bt_not_interested_msg() function here

static int bt_not_interested_msg_handler() {
    return 0;
}

int bt_request_msg(char **mbuf, metainfo_t *metainfo,
			  int piece, int offset) {

    bt_msg_t request;
    int REQUEST_MSG_LEN = 13;
    *mbuf = (char*) malloc (16);

    bzero((void*) &request, sizeof(bt_msg_t));
    bzero((void*)*mbuf, REQUEST_MSG_LEN);

    request.length = htonl(0xd); // hex 1 => dec 1 == length of unchoke msg
    request.bt_type = 0x6; // type of unchoke msg
    request.payload.request.index = htonl(piece);
    request.payload.request.begin = htonl(offset);
    // 5 is length of handshake message:
    // 4 Bytes for length + 1 Byte  for ID
    memcpy(*mbuf, &request, REQUEST_MSG_LEN); 
    
    return REQUEST_MSG_LEN;    
}


static int bt_piece_msg_handler(metainfo_t *metainfo, int blklen,
				int piece, int offset, char* payload) {
    printf("message contains data for piece :%d "\
	   "with offset: %d, data length: %d\n",
	   piece, offset, blklen);
    if (piece_data[piece] == NULL)
	piece_data[piece] = (char*) malloc (metainfo->info->piece_length);

    memcpy(piece_data[piece] + offset, payload, blklen);
    return 0;
}

void write_piece(int piece) {
    int fd = open("/tmp/file.txt", O_RDWR | O_CREAT);
    write(fd, piece_data[piece], 32768);
    close(fd);
    printf("Data written to file\n");
}



void* tcp_recv(void* data) {
    int sockfd = ((recv_data*) data)->sockfd;
    metainfo_t *metainfo = ((recv_data*) data)->metainfo;
    char msg_header[32];
    int msg_len;
    char *payload;
    int nread = 0;

    while (1) {
	//poll the socket with no timebound to see if data is available for read
	struct pollfd pfd;
	pfd.fd = sockfd;
	pfd.events = POLLIN;
	printf("WAiting for event %d\n", pfd.events); 
	int rv = poll(&pfd, POLLIN, -1);
	printf("Got event %d\n", pfd.revents); 
	if (rv <= 0 || !(pfd.revents & POLLIN))
	    continue;

	nread = recv(sockfd, msg_header, 4,  MSG_WAITALL);
	if (nread <= 0) {
	    printf("Socket terminated by peer\n");
	    break;
	}
	msg_len = ntohl(*((int*)msg_header));
	printf("Message length: %u\n", msg_len);
	if(msg_len == 0) // keep-alive message
	    continue;
	else if (msg_len >= 1) {
	    recv(sockfd, msg_header + 4, 1,  MSG_WAITALL);
	    printf("Got message of type :%02x\n", msg_header[4]);
	    switch (msg_header[4]) {
	    case 0:
		bt_choke_msg_handler();
		break;
	    case 1:
		bt_unchoke_msg_handler();	    
		break;
	    case 2:
		bt_interested_msg_handler();
		break;
	    case 3:
		bt_not_interested_msg_handler();
		break;
	    case 4: // Have message - read piece index
		recv(sockfd, msg_header + 5, 4, MSG_WAITALL);
		break;
		// handle have message
	    case 5: // bit field message
		printf("Bitfield message\n");
		payload = (char*) malloc (msg_len  - 1);
		recv(sockfd, payload, msg_len - 1, MSG_WAITALL);
		break;
	    case 6:
		recv(sockfd, msg_header + 5, 12, MSG_WAITALL);
		break;
	    case 7: {
		// read index and offset
		recv(sockfd, msg_header + 5, 8, MSG_WAITALL);
		int piece = ntohl(*(int*)(msg_header + 5));
		int offset = ntohl(*(int*)(msg_header + 9));
		payload = (char*) malloc (msg_len - 9);
		recv(sockfd, payload, msg_len - 9, MSG_WAITALL);
		bt_piece_msg_handler(metainfo, msg_len - 9,
				     piece, offset, payload);
				 
		break;
	    }
	    case 8: {
		// read index and offset
		recv(sockfd, msg_header + 5, 12, MSG_WAITALL);
		int piece = ntohl(*(int*)(msg_header + 5));
		int offset = ntohl(*(int*)(msg_header + 9));
		int cancel_len = ntohl(*(int*)(msg_header + 13));
		break;
	    }
	    case 9:
		recv(sockfd, msg_header + 5, 4, MSG_WAITALL);
		break;
	    default:
		break;
	    }  
	}

    }
    /* if (nrecv < 0) { */
    /* 	perror("ERROR reading from socket\n"); */
    /* 	return -1; */
    /* } */

    return NULL;
}


/* static char* get_block(int sockfd, int size) { */
/*     int nread = 0; */
/*     char *blk_buf = (char*) malloc(size + 128); */
/*     int remaining = size; */
/*     int offset = 0; */

/*     while (remaining > 0) { */
/* 	nread = tcp_recv(sockfd, blk_buf + offset, remaining); */
/* 	remaining -= nread; */
/* 	offset += nread; */
/*     } */

/*     return blk_buf; */
/* } */


void* peerlisten(void *args) {
    int port = 6881;
    int sockfd, newsockfd, clilen;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    int n;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        perror("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *) &serv_addr,
	     sizeof(serv_addr)) < 0) 
	perror("ERROR on binding");

    listen(sockfd, 5);
    clilen = sizeof(cli_addr);
    
    printf("Listening on port 6881....\n");
    while (1) {
	newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, (socklen_t*)&clilen);
	if (newsockfd < 0) 
	    perror("ERROR on accept");
	printf("Accepted connection\n");
	n = 1;
	while (n < 0) {
	    bt_msg_t *msg;
	    bzero(buffer, 255);
	    msg = (bt_msg_t*) buffer;
	    n = read(newsockfd, buffer, 5);
	    printf("Got message type %x\n", msg->bt_type);
	}
    }

    return 0; 
}
