#include "iostream"
#include "param.h"
#include "pbc/pbc.h"
#include "I_ProxyEncryption.h"
#include "Delegator.h"
#include "Delegatee.h"
#include "Proxy.h"
#include "cstring"
#include "cstdlib"
//this is the version of 2nd attempt.
//message maxsize=32B at a time.(if first Byte>B5,31B is the max size)
//G1 64B, G2 128B, GT 384B
//priKeySize A,B 32B in Zr=Zq*
//pubKeySize A 64B in G1, B 128B in G2
//reKeySize 128B in G2
//2nd level CipherI   alpha len 64,  beta len 384
//1st level CipherII  alpha len 384, beta len 384
int main()
{   
    Delegator A;
    Delegatee B;
    Proxy P;

    A.KeyGenerate(64);
    B.KeyGenerate(64);
    //initialize message
    srandom(time(NULL));
    unsigned char message[31];
    for(int i=0;i<sizeof(message);i++) message[i]=(unsigned char)(rand()%256);
    //A Encrypt it to level 2 CI
    unsigned char bufCipherI[A.GetCipherISizeInBytes()];
    A.Encrypt(bufCipherI,message,sizeof(message));
    printf("The level 2 Cipher CI is \n");
    for (int i=0;i<A.GetCipherISizeInBytes();i++) printf("%02X",bufCipherI[i]);
    printf("\n\n");

    //A Decrypt it from level 2 CI
    unsigned int msglen= A.GetMsgSizeInBytes();
    unsigned char bufMsgFromCI[msglen];
    A.Decrypt(bufMsgFromCI,bufCipherI);

    //get pubKey of B
    unsigned int pbBlen=B.GetPubkeySizeInBytes();
    unsigned char bufBPubkey[pbBlen];
    B.GetPubkey(bufBPubkey,pbBlen);
    unsigned int transKeylen=A.GetTranskeySizeInBytes();
    unsigned char bufTranskey[transKeylen];
    //A generates Transkey for B 
    A.GetTranskeyWithPubkey(bufTranskey,transKeylen,bufBPubkey,pbBlen);
    //P receive Transkey
    P.SetTranskey(bufTranskey,transKeylen);
    //P transform level 2 CipherI to level 1 Cipher I using Transkey
    unsigned char bufCipherII[P.GetCipherIISizeInBytes()];
    P.ReEncrypt(bufCipherII,bufCipherI);
    printf("The level 1 Cipher CII is \n");
    for (int i=0;i<P.GetCipherIISizeInBytes();i++) printf("%02X",bufCipherII[i]);
    printf("\n\n");

    //B Decrypt it from level 1 CII
    unsigned char bufMsgFromCII[msglen];
    B.ReDecrypt(bufMsgFromCII,bufCipherII);


    printf("The original message is \n");
    for (int i=0;i<sizeof(message);i++) printf("%02X",message[i]);
    printf("\n\n");
    printf("The message from level 2 CI decrypted by A is \n");
    for (int i=0;i<msglen;i++) printf("%02X",bufMsgFromCI[i]);
    printf("\n\n");
    printf("The message from level 1 CII decrypted by B is \n");
    for (int i=0;i<msglen;i++) printf("%02X",bufMsgFromCII[i]);
    printf("\n\n");

    
    if (!memcmp(message,bufMsgFromCI,msglen)) printf("level 2 CI correct.\n\n");
    if (!memcmp(message,bufMsgFromCII,msglen)) printf("level 1 CII correct.");
    
}
