#include "Proxy.h"

Proxy::Proxy()
{
	pairing_init_set_str(pairing, param);
	element_init_G1(g, pairing);
	element_from_bytes(g,g_G1);


	element_init_G2(h, pairing);
	element_from_bytes(h,h_G2);
}

int Proxy::KeyGenerate(unsigned int bitsSecurity = 64)
{
	return e_ProxyEncryption_NotImp;
}

unsigned int Proxy::GetPubkeySizeInBytes(void)
{
	return e_ProxyEncryption_NotImp;
}

unsigned int Proxy::GetPrikeySizeInBytes(void)
{
	return e_ProxyEncryption_NotImp;
}

unsigned int Proxy::GetTranskeySizeInBytes(void)
{
	return element_length_in_bytes(ReKey);
}

int Proxy::GetPubkey(unsigned char *bufPubkey, unsigned int &sizePubkeyInBytes)
{
	return e_ProxyEncryption_NotImp;
}

int Proxy::GetPrikey(unsigned char *bufPrikey, unsigned int &sizePrikeyInBytes)
{
	return e_ProxyEncryption_NotImp;
}

int Proxy::GetTranskeyWithPubkey(unsigned char *bufTranskey, unsigned int &sizeTranskeyInBytes, unsigned char *bufPubkeyDest, unsigned int sizePubkeyDestInBytes)
{
	return e_ProxyEncryption_NotImp;
}

int Proxy::GetTranskeyWithPrikey(unsigned char *bufTranskey, unsigned int &sizeTranskeyInBytes, unsigned char *bufPrikeyDest, unsigned int sizePrikeyDestInBytes)
{
	return e_ProxyEncryption_NotImp;
}

int Proxy::SetPubkey(unsigned char *bufPubkey, unsigned int sizePubkeyInBytes)
{
	return e_ProxyEncryption_NotImp;
}
	
int Proxy::SetPrikey(unsigned char *bufPrikey, unsigned int sizePrikeyInBytes)
{
	return e_ProxyEncryption_NotImp;
}
	
int Proxy::SetTranskey(unsigned char *bufTranskey, unsigned int sizeTranskeyInBytes)
{
	element_init_G2(ReKey,pairing);
	if(sizeTranskeyInBytes != 128)
		return e_ProxyEncryption_Fail_Transkey;
	unsigned char temp_bufTranskey[sizeTranskeyInBytes];
	for(int i=0;i<sizeTranskeyInBytes;i++)
	{
		temp_bufTranskey[i] = bufTranskey[i];
	}
	//load transkey into rekey
	if( element_from_bytes(ReKey,temp_bufTranskey) != sizeTranskeyInBytes )
		return e_ProxyEncryption_Fail_Transkey;
		
	return e_ProxyEncryption_OK;
}
	 
unsigned int Proxy::GetMsgSizeInBytes(void)
{
	return e_ProxyEncryption_NotImp;
}

unsigned int Proxy::GetCipherISizeInBytes(void)
{
	return 448;
}

unsigned int Proxy::GetCipherIISizeInBytes(void)
{
	return 768;
}
	 
int Proxy::Encrypt(unsigned char *bufCipherI, unsigned char *bufMsg,unsigned int MsgSizeInBytes)
{
	return e_ProxyEncryption_NotImp;
}
/* ReEncrypt from CipherI to  CipherII, which is from level 2 to level 1
CipherI: (g^ak,   mZ^k)  -> (Z^ak,     mZ^k)
CipherI: (alphaI, betaI) -> (alphaIII, betaI)
e(alphaI,Rekey)=alphaII
*/  
int Proxy::ReEncrypt(unsigned char *bufCipherII, unsigned char *bufCipherI)
{
	element_t alphaI,betaI,alphaII;
	element_init_G1(alphaI,pairing);
	element_init_GT(betaI,pairing);
	element_init_GT(alphaII,pairing);
	
	unsigned char bufAlphaI[64];
	unsigned char bufBetaI[384];
	unsigned char bufAlphaII[384];
	
	for(int i=0;i<64;i++)
	{
		bufAlphaI[i] = bufCipherI[i];
	}
	
	for(int j=0;j<384;j++)
	{
		bufBetaI[j] = bufCipherI[j+64];
	}
	
	element_from_bytes(alphaI,bufAlphaI);
	element_from_bytes(betaI,bufBetaI);
	
	pairing_apply(alphaII,alphaI,ReKey,pairing);//alphaII=e(alphaI,Rekey)
	element_to_bytes(bufAlphaII,alphaII);
	
	for(int k=0;k<384;k++)
	{
		bufCipherII[k] = bufAlphaII[k];
	}
	for(int l=0;l<384;l++)
	{
		bufCipherII[l+384] = bufBetaI[l];
	}
	
	element_clear(alphaI);
	element_clear(betaI);
	element_clear(alphaII);
	return e_ProxyEncryption_OK;	 	
}
	 
int Proxy::ReDecrypt(unsigned char *bufMsg, unsigned char *bufCipherII)
{
	return e_ProxyEncryption_NotImp;
}
	 
int Proxy::Decrypt(unsigned char *bufMsg, unsigned char *bufCipherI)
{
	return e_ProxyEncryption_NotImp;
}
	 
