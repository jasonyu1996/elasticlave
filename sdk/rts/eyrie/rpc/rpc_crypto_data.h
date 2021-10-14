#ifndef __RPC_CRYPTO_DATA_H
#define __RPC_CRYPTO_DATA_H

#define SECRETKEYBYTES 32
#define PUBLICKEYBYTES 32
#define SESSIONKEYBYTES 32

struct create_channel_args {
	unsigned char pubkey[PUBLICKEYBYTES];
};

struct create_channel_ret {
	int success;
	unsigned char pubkey[PUBLICKEYBYTES];
};

#endif


