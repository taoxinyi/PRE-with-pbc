#include "Delegator.h"
#define bufSize 1024
#define ZrSize  32
#define G1Size  64
#define G2Size  128
#define GTSize  384

Delegator::Delegator()
{
    pairing_init_set_str(pairing, param); //initialize pairing with settled param

    element_init_G1(g, pairing); //initialize g in G1
    element_from_bytes(g, g_G1); //load g with g_G1 which generates G1
    //element_printf("system parameter g = %B\n\n", g);

    element_init_G2(h, pairing); //initialize h in G2
    element_from_bytes(h, h_G2); //load h with h_G2 which generates G2
    //element_printf("system parameter h = %B\n\n", h);

    element_init_G2(ReKey, pairing); //initialize ReKey in G2
}
/*KeyGenerate Process 
  sk: private key in Zr
  pk: public key  in G1 = g ^ sk
*/
int Delegator::KeyGenerate(unsigned int bitsSecurity = 64)
{
    element_init_Zr(sk, pairing); //initialize sk in Zr
    element_init_G1(pk, pairing); //initialize pk in G1
    
    unsigned char temp_zr[ZrSize];
    unsigned char temp_g1[G1Size];

    element_random(sk); //produce a random private key sk
    element_to_bytes(temp_zr,sk);
    printf("A's secret key (%dB) in Bytes is \n",ZrSize);
    for (int i=0;i<ZrSize;i++) printf("%02X",temp_zr[i]);
    printf("\n\n");

    element_pow_zn(pk, g, sk); //public key pk = g ^ sk
    element_to_bytes(temp_g1,pk);
    printf("A's public key (%dB) in Bytes is \n",G1Size);
    for (int i=0;i<G1Size;i++) printf("%02X",temp_g1[i]);
    printf("\n\n");

    return e_ProxyEncryption_OK;
}
//return the size of publickey
unsigned int Delegator::GetPubkeySizeInBytes(void)
{
    return element_length_in_bytes(pk);
}
//return the size of privatekey
unsigned int Delegator::GetPrikeySizeInBytes(void)
{
    return element_length_in_bytes(sk);
}
unsigned int Delegator::GetTranskeySizeInBytes(void)
{
    return element_length_in_bytes(ReKey);
}
//return the MessageSize
unsigned int Delegator::GetMsgSizeInBytes()
{
    return MsgSize;
}
//get public key
int Delegator::GetPubkey(unsigned char *bufPubkey, unsigned int &sizePubkeyInBytes)
{
    if (sizePubkeyInBytes != GetPubkeySizeInBytes())
        return e_ProxyEncryption_Fail_Pubkey;

    if (element_to_bytes(bufPubkey, pk) != sizePubkeyInBytes)
        return e_ProxyEncryption_Fail_Pubkey;

    return e_ProxyEncryption_OK;
}
//get private key
int Delegator::GetPrikey(unsigned char *bufPrikey, unsigned int &sizePrikeyInBytes)
{

    if (sizePrikeyInBytes != GetPrikeySizeInBytes())
        return e_ProxyEncryption_Fail_Prikey;

    if (element_to_bytes(bufPrikey, sk) != sizePrikeyInBytes)
        return e_ProxyEncryption_Fail_Prikey;

    return e_ProxyEncryption_OK;
}

/* Encrypt to CipherI, which is level 2
CipherI: (Z^ak, mZ^k) = (alpha, beta)
*/
int Delegator::Encrypt(unsigned char *bufCipherI, unsigned char *bufMsg, unsigned int MsgSizeInBytes)
{
    element_t k;              //random element k in Zr
    element_t g1_tmp, gt_tmp; //tmp element in G1,GT for storing
    element_t m;              //message element in GT

    element_init_Zr(k, pairing);
    element_init_G1(g1_tmp, pairing);
    element_init_GT(gt_tmp, pairing);
    element_init_GT(m, pairing);
    int first_index = 0;
    MsgSize = MsgSizeInBytes;
    //convert bufMsg in GT
    //if message begins larger than B5 of exact = 0x00, first index = 1 for insert 0x00
    if (bufMsg[0] > 0xB5 || bufMsg[0] == 0x00)
    {
        first_index = 1;
    }

    unsigned char temp_bufMsg[MsgSize+first_index];
    for (int i = first_index; i < MsgSize+first_index; i++)
    {
        temp_bufMsg[i] = bufMsg[i-first_index];
    }
   
    //first index = 1 means insert 0x00 at the start
    if (first_index == 1)
        temp_bufMsg[0] = 0x00;
    element_from_bytes(m, temp_bufMsg);
    //random k in Zq*

    element_random(k);
    //Z=e(g,h)
    pairing_apply(gt_tmp, g, h, pairing); //gt_tmp=e(g,h)
    element_pow_zn(gt_tmp, gt_tmp, k);    //gt_tmp=e(g,h)^k
    element_mul(gt_tmp, m, gt_tmp);       //gt_tmp=m*e(g,h)^k

    element_pow_zn(g1_tmp, pk, k); //g1_tmp=pk^k=g^(ak)

    int alpha_len = element_length_in_bytes(g1_tmp);
    int beta_len = element_length_in_bytes(gt_tmp);
    if ((alpha_len) != 64 || (beta_len) != 384)
        return e_ProxyEncryption_NotImp;

    CipherISize = alpha_len + beta_len;
    unsigned char bufAlpha[alpha_len];
    unsigned char bufBeta[beta_len];
    element_to_bytes(bufAlpha, g1_tmp);
    element_to_bytes(bufBeta, gt_tmp);
    for (int i = 0; i < alpha_len; i++)
    {
        bufCipherI[i] = bufAlpha[i];
    }
    for (int j = 0; j < beta_len; j++)
    {
        bufCipherI[j + alpha_len] = bufBeta[j];
    }
}
/* Decrypt from CipherI
CipherI: ((alpha, beta) = (g^ak, mZ^k)
2nd level Cipher1  alpha len 64, beta len 384
*/
int Delegator::Decrypt(unsigned char *bufMsg, unsigned char *bufCipherI)
{
    unsigned char bufAlpha[64];
    unsigned char bufBeta[384];
    unsigned char temp_bufMsg[bufSize+1] = {0};

    int first_index=0;
    for (int i = 0; i < 64; i++)
    {
        bufAlpha[i] = bufCipherI[i];
    }
    for (int j = 0; j < 384; j++)
    {
        bufBeta[j] = bufCipherI[64 + j];
    }
    element_t g1_tmp, gt_tmp, beta, zr_tmp; //tmp element in G1,GT,Zr for storing
    element_init_G1(g1_tmp, pairing);
    element_init_GT(gt_tmp, pairing);
    element_init_GT(beta, pairing);
    element_init_Zr(zr_tmp, pairing);

    element_from_bytes(g1_tmp, bufAlpha); //g1_tmp=alpha
    element_from_bytes(beta, bufBeta);    //beta=beta=m*e(g,h)^k

    element_invert(zr_tmp, sk);         //zr_tmp=1/a
    element_pairing(gt_tmp, g1_tmp, h); //gt_tmp=e(alpha,h)=e(g^(ak),h)

    element_pow_zn(gt_tmp, gt_tmp, zr_tmp); //gt_tmp=e(g^(ak),h)^(1/a)=e(g,h)^k
    element_invert(gt_tmp, gt_tmp);         //gt_tmp=1/e(g,h)^k

    element_mul(beta, beta, gt_tmp); //beta=m

    element_to_bytes(temp_bufMsg, beta);
    //if begins = 0x00 remove it
    if (temp_bufMsg[0]==0x00) first_index=1;
    for (int i = first_index; i < MsgSize+first_index; i++)
        bufMsg[i-first_index] = temp_bufMsg[i];
    
    return 0;
}
//Produce the tanskey with own private key and given transkey
//TransKey is used to turn CipherI to II,level 2 to 1
//rA->B=h^(b/a)=pubkeyB^(1/priKeyA)
int Delegator::GetTranskeyWithPubkey(unsigned char *bufTranskey, unsigned int &sizeTranskeyInBytes, unsigned char *bufPubkeyDest, unsigned int sizePubkeyDestInBytes)
{
    if (sizePubkeyDestInBytes != 128)
        return e_ProxyEncryption_Fail_Transkey;

    sizeTranskeyInBytes = GetTranskeySizeInBytes();
    element_t pkDest;
    element_init_G2(pkDest, pairing); //initialize pubkey in G2

    //load bufPubkeyDest into pkDest in G2
    if (element_from_bytes(pkDest, bufPubkeyDest) != sizePubkeyDestInBytes)
        return e_ProxyEncryption_Fail_Transkey;

    element_t r_ska; //invert of ska, r_ska=1/ska
    element_init_Zr(r_ska, pairing);
    element_invert(r_ska, sk);
    element_pow_zn(ReKey, pkDest, r_ska); //Rekey=pkb^r_ska=h^(b/a)

    if (element_to_bytes(bufTranskey, ReKey) != sizeTranskeyInBytes)
        return e_ProxyEncryption_Fail_Transkey;

    element_clear(pkDest);
    element_clear(r_ska);

    return e_ProxyEncryption_OK;
}

int Delegator::GetTranskeyWithPrikey(unsigned char *bufTranskey, unsigned int &sizeTranskeyInBytes, unsigned char *bufPrikeyDest, unsigned int sizePrikeyDestInBytes)
{
}
int Delegator::SetPubkey(unsigned char *bufPubkey, unsigned int sizePubkeyInBytes)
{
}
int Delegator::SetPrikey(unsigned char *bufPrikey, unsigned int sizePrikeyInBytes)
{
}
int Delegator::SetTranskey(unsigned char *bufTranskey, unsigned int sizeTranskeyInBytes)
{
}
int Delegator::ReEncrypt(unsigned char *bufCipherII, unsigned char *bufCipherI)
{
}
int Delegator::ReDecrypt(unsigned char *bufMsg, unsigned char *bufCipherII)
{
}
unsigned int Delegator::GetCipherISizeInBytes(void)
{
    return 448;
}
unsigned int Delegator::GetCipherIISizeInBytes(void)
{
    return e_ProxyEncryption_NotImp;
}