//

#include "BRCrypto.h"
#include "BRBloomFilter.h"
#include "BRMerkleBlock.h"
#include "BRWallet.h"
#include "BRKey.h"
#include "BRBIP38Key.h"
#include "BRAddress.h"
#include "BRBase58.h"
#include "BRBech32.h"
#include "BRBIP39Mnemonic.h"
#include "BRBIP39WordsEn.h"
#include "BRPeer.h"
#include "BRPeerManager.h"
#include "BRChainParams.h"
#include "BRPaymentProtocol.h"
#include "BRInt.h"
#include "BRArray.h"
#include "BRSet.h"
#include "BRTransaction.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SKIP_BIP38 1

#ifdef __ANDROID__
#include <android/log.h>
#define fprintf(...) __android_log_print(ANDROID_LOG_ERROR, "bread", _va_rest(__VA_ARGS__, NULL))
#define printf(...) __android_log_print(ANDROID_LOG_INFO, "bread", __VA_ARGS__)
#define _va_first(first, ...) first
#define _va_rest(first, ...) __VA_ARGS__
#endif

#if BITCOIN_TESTNET
#define BR_CHAIN_PARAMS BRTestNetParams
#else
#define BR_CHAIN_PARAMS BRMainNetParams
#endif

#define MASTER_KEY 1
#define REQUEST_KEY 2


void hex_to_bytes(const char *hexstring, unsigned char *val, int len_val)
{
    const char *pos = hexstring;

     /* WARNING: no sanitization or error-checking whatsoever */
    for (size_t count = 0; count < len_val; count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2;
    }
}

void print_hex(uint8_t *sig, size_t sigLen)
{
    for(int i=0; i<sigLen; i++){
        printf("%02x", sig[i]);
    }
    printf("\n");
}

typedef struct
{
    BRMasterPubKey mpk;
    BRKey masterPrivKey;
    BRKey authKey;
    UInt512 seed;
} BenKeys;;

    
BenKeys make_keys(const char phrase[])
{
    BRMasterPubKey mpk = BR_MASTER_PUBKEY_NONE;
    UInt512 seed = UINT512_ZERO;
    BenKeys keys;

    // const char phrase[] = "awesome broken silent win sugar thank cruel used service skull steak orbit";
    // const char phrase[] = "view weapon armed army armed space arm twin amused shy poverty benefit";
    // const char phrase[] = "buddy chair fox palm wool glad equal jeans earn result anxiety trouble";
    printf("BIP39 Phrase:\n%s\n",phrase);
    BRBIP39DeriveKey(keys.seed.u8, phrase, NULL);

    // Get master private key from seed
    BRKey key;
    BRBIP32PrivKeyPath(&keys.masterPrivKey, keys.seed.u8, sizeof(keys.seed), 1, 0 | BIP32_HARD);

    // Get master public key
    keys.mpk = BRBIP32MasterPubKey(&keys.seed, sizeof(keys.seed));

    // Get request signing keys
    BRBIP32APIAuthKey(&keys.authKey, &keys.seed, sizeof(keys.seed));
    BRKeyPubKey(&keys.authKey, NULL, 65);

    // Get BIP44 style key for signing transactions (m/44'/0'/0'/1/0)
    // BRBIP32PrivKeyPath(&keys.txKey, keys.seed.u8, sizeof(keys.seed), 5, 44 | BIP32_HARD, 0 | BIP32_HARD, 0 | BIP32_HARD, 0, 0);

    return keys;
}
    
void print_keys(BenKeys *pKeys)
{
    printf("KEYS\nseed:%s%s\n", u256hex(pKeys->seed), u256hex(*(UInt256 *)&(pKeys->seed.u8[sizeof(UInt256)])));
    printf("Master Private Pey:\n%s\n", u256hex(pKeys->masterPrivKey.secret));

    printf("\nMaster Public Key\nfp:        %08x\nchaincode: %s\npubkey:    %02x%s\n", pKeys->mpk.fingerPrint,
           u256hex(pKeys->mpk.chainCode), pKeys->mpk.pubKey[0], u256hex(*(UInt256 *)&(pKeys->mpk.pubKey[1])));

    printf("\nauthkey:   %s\n", u256hex(pKeys->authKey.secret));
    printf("authkeyPub:%02x%s\n", pKeys->authKey.pubKey[0], u256hex(*(UInt256 *)&(pKeys->authKey.pubKey[1])));
}

size_t sign_hash(const char hash[], BenKeys *pKeys, void *sig, size_t sigLen, int keyType)
{
    unsigned char val[32];
    hex_to_bytes(hash, val, 32);    
    UInt256 md2 = UInt256Get(val);

    if (keyType == REQUEST_KEY)
    {
        sigLen = BRKeySign(&(pKeys->authKey), sig, sigLen, md2);
        printf("\nRequest Sig %zu\n", sigLen);
    }
    else
    {
        sigLen = BRKeySign(&(pKeys->masterPrivKey), sig, sigLen, md2);
        printf("Private Key Sig %zu\n", sigLen);
    }
  
    return sigLen;
}

size_t sign_prop(const char prop[], BenKeys *pkeys, void *sig, size_t sigLen)
{
    size_t txLen = strlen(prop)/2;
    printf("TX Len: %zu \n", txLen);

    unsigned char propval[txLen];
    hex_to_bytes(prop, propval, txLen);    

    printf("SIGN TX PROPOSAL\n");
    printf("TX Prop: %s\n", prop);
    UInt256 propmd;
    BRSHA256_2(&propmd, prop, strlen(prop));
    printf("\nTx Proposal  Hash: %s\n\n", u256hex(propmd));

    sigLen = BRKeySign(&(pkeys->authKey), sig, sigLen, propmd);
    printf("\nSigned proposal hash %zu\n", sigLen);

    return sigLen;
}

size_t sign_tx(const char tx_script[], BenKeys *pKeys, const char path[], void *sig, size_t sigLen)
{
    size_t txLen = strlen(tx_script)/2;
    printf("TX Len: %zu \n", txLen);

    unsigned char txval[txLen];
    printf("SIGN TX  WITH BRKeySign\n");

    printf("Path %s\n", path);
    int change, address_index;
    sscanf(path, "m/%d/%d/", &change, &address_index); 
    printf("Change = %d Address Index = %d\n", change, address_index);

    hex_to_bytes(tx_script, txval, txLen);    

    // Make a copy of TX and Append hash type
    unsigned char txval_data[txLen+4];
    memcpy(txval_data, txval, txLen);
 
    UInt32SetLE(&txval_data[txLen], 0x01 ); // hash type (SIGHASH_ALL)

    UInt256 txmd;
    BRSHA256_2(&txmd, txval_data, txLen+4);
    printf("\nTxMD Hash: %s\n", u256hex(txmd));

    // Make key for path
    BRKey tx1;
    BRBIP32PrivKeyPath(&tx1, pKeys->seed.u8, sizeof(pKeys->seed), 3, 0 | BIP32_HARD, change, address_index);
    sigLen = BRKeySign(&tx1, sig, sigLen, txmd);
    printf("Transaction Signature\n");
 
    return sigLen;
}


void sign_tx_with_bw(const char tx_script[], BenKeys *pKeys, const char path[])
{
    uint8_t sig[72];
    size_t sigLen;

    size_t txLen = strlen(tx_script);
    unsigned char txval[txLen];

    int change, address_index;
    sscanf(path, "m/%d/%d/", &change, &address_index); 
    printf("Change = %d Address Index = %d\n", change, address_index);

    hex_to_bytes(tx_script, txval, txLen);    
    printf("PARSE TX WITH SCRIPT\n");
    BRTransaction *tx = BRTransactionParse(txval, txLen);
    printf("In Count: %zu Out Count: %zu\n", tx->inCount, tx->outCount);
    printf("Input 0 Script Len: %zu\n", tx->inputs[0].scriptLen);

    printf("SIGN TX WITH BRTransactionSign\n");
    BRKey tx1, tx2;
    BRBIP32PrivKeyPath(&tx1, pKeys->seed.u8, sizeof(pKeys->seed), 3, 0 | BIP32_HARD, change, address_index);
    BRKey txkeys[1];
    txkeys[0] = tx1;
    BRTransactionSign(tx, 0, txkeys, 1); 
    printf("Tx Sig Len %zu\n", tx->inputs[0].sigLen);
    printf("Tx Hash %s\n", u256hex(tx->inputs[0].txHash));
    printf("Trans Input 0 Sig\n");
    print_hex(tx->inputs[0].signature, tx->inputs[0].sigLen);

    printf("SERIALIZE TX\n");
    size_t bufLen = BRTransactionSerialize(tx, NULL, 0);
    printf("%zu\n", bufLen);
    uint8_t txbuf[bufLen];
    bufLen = BRTransactionSerialize(tx, txbuf, bufLen);
    //print_hex(txbuf, bufLen);
}


int main(int argc, const char *argv[])
{
    int err = 0;
    BRMasterPubKey mpk = BR_MASTER_PUBKEY_NONE;
    BRWallet *wallet;
    uint8_t sig[72];
    size_t sigLen;

    if (argc < 2) {
        printf("WRONG. Do it again!\n");
        return 1;
    }

    BenKeys benKeys = make_keys(argv[1]);

    if (argc < 4)
    {
         print_keys(&benKeys);
         exit(0);
    }

    char opt = argv[2][1];

    switch (opt)
    {
        case 'h':
            sigLen = sign_hash(argv[3], &benKeys, sig, sizeof(sig), REQUEST_KEY);
            print_hex(sig, sigLen);
            break;
        case 'c':
            sigLen = sign_hash(argv[3], &benKeys, sig, sizeof(sig), MASTER_KEY);
            print_hex(sig, sigLen);
            break;
        case 'p':
            sigLen = sign_prop(argv[3], &benKeys, sig, sizeof(sig));
            print_hex(sig, sigLen);
            break;
        case 't':
            sigLen = sign_tx(argv[3], &benKeys, argv[4], sig, sizeof(sig));
            print_hex(sig, sigLen);
            break;
        case 'w':
            sign_tx_with_bw(argv[3], &benKeys, argv[4]);
            break;
        default:
            break;
    }

    return 0;
}
