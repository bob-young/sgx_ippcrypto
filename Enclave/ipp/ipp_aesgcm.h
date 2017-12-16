#ifndef IPP_AESGCM_H_
#define IPP_AESGCM_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ippcp.h"

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#define errlist_len 15
using namespace std;
class ipp_aesgcm{
public:
	~ipp_aesgcm();
	IppStatus init(const unsigned char* pwd,int pwdlen,unsigned char* piv,int pivlen);
	IppStatus encrypt(unsigned char* src,unsigned char* dest,int length);
	IppStatus decrypt(unsigned char* src,unsigned char* dest,int length);
	IppStatus reset();
	void set_block_size(int size);
	int block_size=10;
private:
	int AES_GCM_ContextSize=0;
	IppsAES_GCMState* gcm_context;
	const unsigned char* t_pwd;
	int t_pwdlen;
	unsigned char* t_piv;
	int t_pivlen;
	int ipp_init;
};
#endif
