#ifndef IPP_RIJNDAEL_CBC_H_
#define IPP_RIJNDAEL_CBC_H_


#include "ipp_rijndael.h"
#include "App.h"

using namespace std;

class ipp_rijndael_CBC:public ipp_rijndael
{

public:	
	//
	IppStatus encrypt(unsigned char* src,unsigned char* dest,int length,int* dest_len,unsigned char* pIV);
	IppStatus decrypt(unsigned char* src,unsigned char* dest,int length,unsigned char* pIV);
	//IppStatus init(const unsigned char* pwd,int pwdlen,enum Mode md=CBC);
};
#endif
