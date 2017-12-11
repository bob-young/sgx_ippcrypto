#ifndef IPP_AES_H_
#define IPP_AES_H_


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ippcp.h"

#define errlist_len 15
using namespace std;
class ipp_aes{
public:
	IppStatus init(unsigned char* pwd,int pwdlen,unsigned char* piv,int pivlen);
	IppStatus encrypt(unsigned char* src,unsigned char* dest,int length);
	IppStatus decrypt(unsigned char* src,unsigned char* dest,int length);
	IppStatus reset();
	int block_size=512;
private:
	int AES_GCM_ContextSize=0;
	IppsAES_GCMState* gcm_context;
	unsigned char* t_pwd;
	int t_pwdlen;
	unsigned char* t_piv;
	int t_pivlen;
	int ipp_init;
};
#endif
