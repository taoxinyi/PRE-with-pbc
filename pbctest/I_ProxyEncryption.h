#ifndef I_ProxyEncryption_H
#define I_ProxyEncryption_H

//#include "I_Hash.h"
//#include "I_Random.h"

class I_ProxyEncryption
{
public:
	enum
	{
		e_ProxyEncryption_OK,
		e_ProxyEncryption_NotImp,
		e_ProxyEncryption_Fail_Prikey,
		e_ProxyEncryption_Fail_Pubkey,
		e_ProxyEncryption_Fail_Transkey,
		e_ProxyEncryption_Fail_Hash,
		e_ProxyEncryption_Fail_Encrypt,
		e_ProxyEncryption_Fail_Decrypt
	};

public:
	I_ProxyEncryption(void) {}
	virtual ~I_ProxyEncryption(void) {}

public:
	virtual int KeyGenerate(unsigned int bitsSecurity) = 0;
	//virtual unsigned int GetPubkeySizeInBytes(void) = 0;
	//virtual unsigned int GetPrikeySizeInBytes(void) = 0;
	//virtual unsigned int GetTranskeySizeInBytes(void) = 0;
	//virtual int GetPubkey(unsigned char *bufPubkey, unsigned int &sizePubkeyInBytes) = 0;
	//virtual int GetPrikey(unsigned char *bufPrikey, unsigned int &sizePrikeyInBytes) = 0;
	//virtual int GetTranskeyWithPubkey(unsigned char *bufTranskey, unsigned int &sizeTranskeyInBytes, unsigned char *bufPubkeyDest, unsigned int sizePubkeyDestInBytes) = 0;
	//virtual int GetTranskeyWithPrikey(unsigned char *bufTranskey, unsigned int &sizeTranskeyInBytes, unsigned char *bufPrikeyDest, unsigned int sizePrikeyDestInBytes) = 0;
	//virtual int SetPubkey(unsigned char *bufPubkey, unsigned int sizePubkeyInBytes) = 0;
	//virtual int SetPrikey(unsigned char *bufPrikey, unsigned int sizePrikeyInBytes) = 0;
	//virtual int SetTranskey(unsigned char *bufTranskey, unsigned int sizeTranskeyInBytes) = 0;

	//virtual int SetHashMethod(I_Hash *pHash) = 0;
	//virtual int SetRandomMethod(I_Random *pRandom) = 0;

	virtual unsigned int GetMsgSizeInBytes(void) = 0;
	//virtual unsigned int GetCipherISizeInBytes(void) = 0;
	//virtual unsigned int GetCipherIISizeInBytes(void) = 0;
	virtual int Encrypt(unsigned char *bufCipherI, unsigned char *bufMsg,unsigned int MsgSizeInBytes) = 0;
	//virtual int ReEncrypt(unsigned char *bufCipherII, unsigned char *bufCipherI) = 0;
	//virtual int ReDecrypt(unsigned char *bufMsg, unsigned char *bufCipherII) = 0;
	virtual int Decrypt(unsigned char *bufMsg, unsigned char *bufCipherI) = 0;
};

#endif

