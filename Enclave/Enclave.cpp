#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
# include <unistd.h>
#include <string.h>

#include "ippcp.h"
#include "ipp_aesgcm.h"
#include "ipp_rijndael.h"
int aes(void)
{
	ipp_aesgcm aes;
	unsigned char pkey[16]={1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};//16||32||64
	unsigned char pIV[16]={1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
	aes.init(pkey,16,pIV,16);
	ocall_print_string("test aesgcm in enclave:");
	char* plain="hello world\n\0";
	unsigned char* cipher=(unsigned char*)malloc(24);
//encrypt
	aes.encrypt((unsigned char*)plain,cipher,24);
	unsigned char* output=(unsigned char*)malloc(24);
	aes.reset();
//decrypt
	aes.decrypt(cipher,output,24);	
	ocall_print_string((char*)output);
//rijndael
	ocall_print_string("test rijndael in enclave:");
	ipp_rijndael rijn;
	rijn.init(pkey,16);
	int cipher_len=0;
	unsigned char* cipher2=(unsigned char*)malloc(24);
//encrypt
	rijn.encrypt((unsigned char*)plain,cipher2,24,&cipher_len,pIV);
	unsigned char* output2=(unsigned char*)malloc(24);
	ipp_rijndael rijn2;
	rijn2.init(pkey,16);
//decrypt
	rijn2.decrypt(cipher2,output2,cipher_len,pIV);	
	ocall_print_string((char*)output2);
	return 0;
/*
	int AES_GCM_ContextSize=0;
	IppStatus istate;
	unsigned char pkey[16]={1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};//16||32||64
	unsigned char pIV[16]={1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
	int keyLen=16;
	Ipp8u* pKey=pkey;
	ippsAES_GCMGetSize(&AES_GCM_ContextSize);

	IppsAES_GCMState* gcm_context=(IppsAES_GCMState*)malloc(AES_GCM_ContextSize);
	istate=ippsAES_GCMInit(pKey,keyLen,gcm_context,AES_GCM_ContextSize);
	char a[12]="hello world";
	unsigned char b[12];
	ippsAES_GCMProcessIV(pIV,16,gcm_context);
	ippsAES_GCMStart(pIV,16,NULL,0,gcm_context);
	istate=ippsAES_GCMEncrypt((unsigned char*)a,b,12,gcm_context);
	ocall_print_buffer(b,12);
	unsigned char c[12];
	IppsAES_GCMState* gcm_context2=(IppsAES_GCMState*)malloc(AES_GCM_ContextSize);
	istate=ippsAES_GCMInit(pKey,keyLen,gcm_context2,AES_GCM_ContextSize);
	ippsAES_GCMProcessIV(pIV,16,gcm_context2);
	ippsAES_GCMStart(pIV,16,NULL,0,gcm_context2);
	istate=ippsAES_GCMDecrypt(b,c,12,gcm_context2);
	ocall_print_buffer(c,12);
	*(c+12)=0;
	ocall_print_string((const char*)c);
	return 0;
*/
}

void encall_print(char **fmt)
{
	char buf[BUFSIZ] = {'\0'};
	char* a="now is in encall\n";
	strncat(buf,fmt[0],100);
	strncat(buf,(fmt[1]),100);
	strncat(buf,(fmt[2]),100);
	strncat(buf,a,100);
	ocall_print_string(buf);
	aes();
}


