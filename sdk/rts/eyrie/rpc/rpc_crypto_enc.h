#ifndef __RPC_CRYPTO_ENC_H_
#define __RPC_CRYPTO_ENC_H_

#define NONCEBYTES 32

struct crypto_parcel {
	unsigned char nonce[NONCEBYTES];
	unsigned char data[];
};

size_t rpc_crypto_data_pack(struct crypto_parcel* parcel, void* data, size_t len, size_t size_lim, unsigned char* tx);

size_t rpc_crypto_data_unpack(struct crypto_parcel* parcel, void* data, size_t len, size_t size_lim, unsigned char* rx);

#endif

