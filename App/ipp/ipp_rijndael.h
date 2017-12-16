#ifndef IPP_RIJNDAEL_H_
#define IPP_RIJNDAEL_H_


#include "ippcp.h"
#include "string.h"
#include "App.h"
#define errlist_len 15
using namespace std;
class ipp_rijndael{
public:
	~ipp_rijndael();
	IppStatus init(const unsigned char* pwd,int pwdlen);
	// 明文，密文，明文长度，返回的密文长度（16倍数），向量
	//plaintext,ciphertext,plaintex_length,ciphertext_length(divisible by 16),victor
	IppStatus encrypt(unsigned char* plaintext,unsigned char* ciphertext,int plaintex_length,int* ciphertext_length,unsigned char* pIV);
	//ciphertext,plaintext,ciphertext_length,plaintex_length(restore the original length),victor
	IppStatus decrypt(unsigned char* ciphertext,unsigned char* plaintext,int ciphertext_length,unsigned char* pIV);
	// note : if :length divisible by 16 no padding 
	//	  else: padding tail to 16
	IppStatus reset();
	void ipp_free();
	int block_size=1024;
	void set_block_size(int size);

private:
	int Rijndael_ContextSize=0;
	IppsAESSpec* rijndael_context;
	const unsigned char* t_pwd;
	int t_pwdlen;
	unsigned char* t_piv;
	int t_pivlen;
	int ipp_init;
};
#endif
