#ifndef DELEGATEE_H
#define DELEGATEE_H

#include "pbc/pbc.h"
#include "gmp.h"
#include "param.h"
#include "stdio.h"
#include "I_ProxyEncryption.h"

class Delegatee:public I_ProxyEncryption
{
private:
	pairing_t pairing;
	element_t g,h;
	element_t sk,pk;
public:
	Delegatee();
	int KeyGenerate(unsigned int bitsSecurity);
	unsigned int GetPubkeySizeInBytes(void);
	unsigned int GetPrikeySizeInBytes(void);
	unsigned int GetTranskeySizeInBytes(void);
	int GetPubkey(unsigned char *bufPubkey, unsigned int &sizePubkeyInBytes);
	int GetPrikey(unsigned char *bufPrikey, unsigned int &sizePrikeyInBytes);
	int GetTranskeyWithPubkey(unsigned char *bufTranskey, unsigned int &sizeTranskeyInBytes, unsigned char *bufPubkeyDest, unsigned int sizePubkeyDestInBytes);
	int GetTranskeyWithPrikey(unsigned char *bufTranskey, unsigned int &sizeTranskeyInBytes, unsigned char *bufPrikeyDest, unsigned int sizePrikeyDestInBytes);
	int SetPubkey(unsigned char *bufPubkey, unsigned int sizePubkeyInBytes);
	int SetPrikey(unsigned char *bufPrikey, unsigned int sizePrikeyInBytes);
	int SetTranskey(unsigned char *bufTranskey, unsigned int sizeTranskeyInBytes);
	 
	unsigned int GetMsgSizeInBytes(void);
	unsigned int GetCipherISizeInBytes(void);
	unsigned int GetCipherIISizeInBytes(void);
	int Encrypt(unsigned char *bufCipherI, unsigned char *bufMsg,unsigned int MsgSizeInBytes);
	int ReEncrypt(unsigned char *bufCipherII, unsigned char *bufCipherI);
	int ReDecrypt(unsigned char *bufMsg, unsigned char *bufCipherII);
	int Decrypt(unsigned char *bufMsg, unsigned char *bufCipherI);
};

#endif
