#include "Delegatee.h"
#define bufSize 1024
#define ZrSize  32
#define G1Size  64
#define G2Size  128
#define GTSize  384

Delegatee::Delegatee()
{
    pairing_init_set_str(pairing, param); //initialize pairing with settled param

    element_init_G1(g, pairing); //initialize g in G1
    element_from_bytes(g, g_G1); //load g with g_G1 which generates G1
    //element_printf("system parameter g = %B\n\n", g);

    element_init_G2(h, pairing); //initialize h in G2
    element_from_bytes(h, h_G2); //load h with h_G2 which generates G2
    //element_printf("system parameter h = %B\n\n", h);
}
int Delegatee::KeyGenerate(unsigned int bitsSecurity = 64)
{

    element_init_Zr(sk, pairing); //initialize sk in Zr
    element_init_G2(pk, pairing); //initialize pk in G1

    unsigned char temp_zr[ZrSize];
    unsigned char temp_g2[G2Size];

    element_random(sk); //produce a random private key sk
    element_to_bytes(temp_zr,sk);
    printf("B's secret key (%dB) in Bytes is \n",ZrSize);
    for (int i=0;i<ZrSize;i++) printf("%02X",temp_zr[i]);
    printf("\n\n");

    element_pow_zn(pk, h, sk); //public key pk = g ^ sk
    element_to_bytes(temp_g2,pk);
    printf("B's public key (%dB) in Bytes is \n",G2Size);
    for (int i=0;i<G2Size;i++) printf("%02X",temp_g2[i]);
    printf("\n\n");

    return e_ProxyEncryption_OK;

}
unsigned int Delegatee::GetPubkeySizeInBytes(void)
{
        return element_length_in_bytes(pk);
}

unsigned int Delegatee::GetPrikeySizeInBytes(void)
{
        return element_length_in_bytes(sk);
}	
unsigned int Delegatee::GetTranskeySizeInBytes(void)
{
    return e_ProxyEncryption_NotImp;
}
	
int Delegatee::GetPubkey(unsigned char *bufPubkey, unsigned int &sizePubkeyInBytes)
{
    if(sizePubkeyInBytes != GetPubkeySizeInBytes())
        return e_ProxyEncryption_Fail_Pubkey;

    
    if( element_to_bytes(bufPubkey,pk) != sizePubkeyInBytes)
        return e_ProxyEncryption_Fail_Pubkey;
    
    return e_ProxyEncryption_OK;
            
}
//get private key
int Delegatee::GetPrikey(unsigned char *bufPrikey, unsigned int &sizePrikeyInBytes)
{

    if(sizePrikeyInBytes != GetPrikeySizeInBytes())
        return e_ProxyEncryption_Fail_Prikey;
    
    if( element_to_bytes(bufPrikey,sk) != sizePrikeyInBytes )
        return e_ProxyEncryption_Fail_Prikey;
        
    return e_ProxyEncryption_OK;
}
int Delegatee::Encrypt(unsigned char *bufCipherI, unsigned char *bufMsg, unsigned int MsgSizeInBytes)
{   
    return e_ProxyEncryption_NotImp;
}
/* Decrypt from CipherI
CipherI: ((alpha, beta) = (Z^ak, mZ^k)
*/ 
int Delegatee::Decrypt(unsigned char *bufMsg, unsigned char *bufCipherI)
{
    return e_ProxyEncryption_NotImp;
}
unsigned int Delegatee::GetMsgSizeInBytes(void)
{
		return e_ProxyEncryption_NotImp;	
}
int Delegatee::GetTranskeyWithPubkey(unsigned char *bufTranskey, unsigned int &sizeTranskeyInBytes, unsigned char *bufPubkeyDest, unsigned int sizePubkeyDestInBytes)
{
    return e_ProxyEncryption_NotImp;
}
int Delegatee::GetTranskeyWithPrikey(unsigned char *bufTranskey, unsigned int &sizeTranskeyInBytes, unsigned char *bufPrikeyDest, unsigned int sizePrikeyDestInBytes) 
{
    return e_ProxyEncryption_NotImp;
}
int Delegatee::SetPubkey(unsigned char *bufPubkey, unsigned int sizePubkeyInBytes) 
{
    
}
int Delegatee::SetPrikey(unsigned char *bufPrikey, unsigned int sizePrikeyInBytes) 
{
    
}
int Delegatee::SetTranskey(unsigned char *bufTranskey, unsigned int sizeTranskeyInBytes) 
{
    return e_ProxyEncryption_NotImp;
}
int Delegatee::ReEncrypt(unsigned char *bufCipherII, unsigned char *bufCipherI)
{
    return e_ProxyEncryption_NotImp;
}
/* ReDecrypt from CipherII to  msg, which is from level 1 to msg
CipherII: (Z^bk,   mZ^k)  -> m
*/ 
int Delegatee::ReDecrypt(unsigned char *bufMsg, unsigned char *bufCipherII)
{
    unsigned char bufAlpha[384];
    unsigned char bufBeta[384];
    unsigned char temp_bufMsg[bufSize+1] = {0};
    int first_index=0;
    for(int i=0;i<384;i++)
    {
        bufAlpha[i]  = bufCipherII[i];
    }
    for(int j=0;j<384;j++)
    {
        bufBeta[j] = bufCipherII[j+384];
    }
    
    element_t alpha,beta,r_sk;
    element_init_GT(alpha,pairing);
    element_init_GT(beta,pairing);
    element_from_bytes(alpha,bufAlpha);
    element_from_bytes(beta,bufBeta);
    element_init_Zr(r_sk,pairing);
    
    element_invert(r_sk,sk);
    
    element_pow_zn(alpha,alpha,r_sk);
    
    element_invert(alpha,alpha);
    element_mul(beta,beta,alpha);
    
    element_to_bytes(temp_bufMsg,beta);
    if (temp_bufMsg[0]==0x00) first_index=1;
    for (int i = first_index; i < sizeof(temp_bufMsg); i++)
        bufMsg[i-first_index] = temp_bufMsg[i];
}
unsigned int Delegatee::GetCipherISizeInBytes(void)
{
    
}
unsigned int Delegatee::GetCipherIISizeInBytes(void)
{
    
}