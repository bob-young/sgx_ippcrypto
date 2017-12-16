#ifndef IPP_RIJNDAEL_ECB_H_
#define IPP_RIJNDAEL_ECB_H_


#include "ipp_rijndael.h"
#include "App.h"
#define errlist_len 15
using namespace std;

class ipp_rijndael_ECB:public ipp_rijndael
{

public:	
	//
	IppStatus encrypt(unsigned char* src,unsigned char* dest,int length,int* dest_len);
	IppStatus decrypt(unsigned char* src,unsigned char* dest,int length);
	//IppStatus init(const unsigned char* pwd,int pwdlen,enum Mode md=CBC);
};
#endif
