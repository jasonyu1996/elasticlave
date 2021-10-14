#include "string.h"
#include "edge_wrapper.h"
#include "edge_wrapper_data.h"
#include "rpc_data.h"
#include "rpc_crypto_data.h"

extern struct rpc_data rpc_data;

unsigned char my_pubkey[PUBLICKEYBYTES];
unsigned char my_seckey[SECRETKEYBYTES];
unsigned char server_pubkey[PUBLICKEYBYTES];
unsigned char my_tx[SESSIONKEYBYTES];
unsigned char my_rx[SESSIONKEYBYTES];



