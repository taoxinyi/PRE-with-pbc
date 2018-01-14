#include "iostream"
#include "param.h"
#include "pbc/pbc.h"
#include "stdio.h"
#include "cstring"
#include "I_ProxyEncryption.h"
using namespace std;
int testpbc()
{
    //printf(param);

    pairing_t pairing;

    element_t g, gx;
    element_t h, hx;
    element_t tx, ty;
    element_t r1, r2, rm;

    pairing_init_set_str(pairing, param);
    element_init_G1(g, pairing);
    element_init_G1(gx, pairing);

    element_init_G2(h, pairing);
    element_init_G2(hx, pairing);

    element_init_GT(tx, pairing);
    element_init_GT(ty, pairing);

    element_init_Zr(r1, pairing);
    element_init_Zr(r2, pairing);
    element_init_Zr(rm, pairing);

    element_from_bytes(g, g_G1);
    element_from_bytes(h, h_G2);
    element_printf("g is %B\n", g);
    element_printf("h is %B\n", h);

    element_random(r1);      //r1 in Zq*
    element_random(r2);      //r2 in Zq*
    element_mul(rm, r1, r2); //rm=r1*r2

    pairing_apply(tx, g, h, pairing); //tx=e(g,h)
    element_pow_zn(ty, tx, rm);       //ty=e(g,h)^(r1*r2)

    element_pow_zn(gx, g, r1);          //gx=g^r1
    element_pow_zn(hx, h, r2);          //hx=h^r2
    pairing_apply(tx, gx, hx, pairing); //tx=e(gx,hx)=e(g^r1,h^r2)

    //tx and ty are supposed to be the same;
    element_printf("tx=%B\n", tx);
    element_printf("ty=%B\n", ty);

    if (element_cmp(tx, ty))
        printf("Error");
    else
        printf("Success");
    return 0;
}
class Delegator:public I_ProxyEncryption
{
private:
	pairing_t pairing;
	element_t g,h;
	element_t sk,pk;
	element_t ReKey;
	int MsgSize,CipherISize;
public:
	Delegator();
    int KeyGenerate(unsigned int bitsSecurity);
    int Encrypt(unsigned char *bufCipherI, unsigned char *bufMsg,unsigned int MsgSizeInBytes);
    int Decrypt(unsigned char *bufMsg, unsigned char *bufCipherI);
    unsigned int GetMsgSizeInBytes(void);
};

Delegator::Delegator()
{
    pairing_init_set_str(pairing, param);
    element_init_G1(g, pairing);
    element_from_bytes(g,g_G1);
    element_printf("system parameter g = %B\n\n", g);


    element_init_G2(h, pairing);
    element_from_bytes(h,h_G2);
    element_printf("system parameter h = %B\n\n", h);
}
int Delegator::KeyGenerate(unsigned int bitsSecurity = 64)
{
    element_init_Zr(sk,pairing);
    element_init_G1(pk,pairing);
    element_random(sk);
    element_printf("A's secret key = %B\n\n", sk);
    element_pow_zn(pk,g,sk);
    element_printf("A's public key = %B\n\n", pk);
    
    return e_ProxyEncryption_OK;
}
unsigned int Delegator::GetMsgSizeInBytes()
{
    return MsgSize;
}
int Delegator::Encrypt(unsigned char *bufCipherI, unsigned char *bufMsg,unsigned int MsgSizeInBytes)
{  
    element_t k;
    element_t Z, Z_k, Z_ak, m_Z_k;
    element_t m;
    element_init_GT(Z, pairing);
    element_init_GT(Z_k, pairing);
    element_init_GT(Z_ak, pairing);
    element_init_GT(m_Z_k, pairing);
    element_init_GT(m, pairing);
    element_init_Zr(k, pairing); //random k
    //convert bufMsg in GT
    MsgSize = MsgSizeInBytes;
    unsigned char temp_bufMsg[MsgSize];
    for(int i=0;i<MsgSize;i++)
    {
        temp_bufMsg[i] = bufMsg[i];
    }
    element_from_bytes(m,temp_bufMsg);
    //random k in Zq*

	element_init_Zr(k,pairing);
	element_random(k);
        //Z=e(g,h)
    pairing_apply(Z, g, h, pairing);
    element_pow_zn(Z_k, Z, k);
    element_mul(m_Z_k, m, Z_k);
    element_pow_zn(Z_ak, Z_k, sk);

    int alpha_len = element_length_in_bytes(Z_ak);
	int beta_len = element_length_in_bytes(m_Z_k);
    int CipherISize = alpha_len+beta_len;
    unsigned char bufAlpha[alpha_len];
    unsigned char bufBeta[beta_len];
    element_to_bytes(bufAlpha,Z_ak);
    element_to_bytes(bufBeta,m_Z_k);
    
    for(int i = 0;i<alpha_len;i++)
    {
        bufCipherI[i] = bufAlpha[i];
    }
    for(int j = 0;j<beta_len;j++)
    {
        bufCipherI[j+alpha_len] = bufBeta[j];
    }



}

int Delegator::Decrypt(unsigned char *bufMsg, unsigned char *bufCipherI)
{
    unsigned char bufAlpha[384];
    unsigned char bufBeta[384];
    unsigned char temp_bufMsg[384]={0};
    
    for(int i=0;i<384;i++)
    {
        bufAlpha[i] = bufCipherI[i];
    }
    for(int j=0;j<384;j++)
    {
        bufBeta[j] = bufCipherI[384+j];
    }
    element_t Z_ak,m_Z_k;
    element_init_GT(Z_ak, pairing);
    element_init_GT(m_Z_k, pairing);

    element_from_bytes(Z_ak,bufAlpha);
	element_from_bytes(m_Z_k,bufBeta);
    element_t r_sk;
    element_init_Zr(r_sk, pairing);
    element_invert(r_sk, sk);
    element_pow_zn(Z_ak, Z_ak, r_sk);
    

    element_t r_Zk;
    element_init_GT(r_Zk, pairing);
    element_invert(r_Zk, Z_ak);
    element_mul(r_Zk, m_Z_k, r_Zk);

   
    element_to_bytes(temp_bufMsg,r_Zk);
    for (int i =0;i<MsgSize;i++) bufMsg[i]=temp_bufMsg[i];
    return 0;

}
int main()
{   Delegator A;
    A.KeyGenerate(64);
    unsigned char message[] = 	   {'a','b','c','d'};
    unsigned char bufCipherI[1024];
    unsigned char recvMsg[1024];
    A.Encrypt(bufCipherI,message,sizeof(message));
    A.Decrypt(recvMsg,bufCipherI);
    cout<<"CipherI decrypted by A:";
    for (int i =0;i<A.GetMsgSizeInBytes();i++) cout<<recvMsg[i];
    
   
}