#ifndef IPP_RIJNDAEL_CFB_H_
#define IPP_RIJNDAEL_CFB_H_


#include "ipp_rijndael.h"
#include "App.h"

using namespace std;

class ipp_rijndael_CFB:public ipp_rijndael
{

public:	
	//
	IppStatus encrypt(unsigned char* src,unsigned char* dest,int length,int* dest_len,int cfbBlkSize,unsigned char* pIV);
	IppStatus decrypt(unsigned char* src,unsigned char* dest,int length,int cfbBlkSize,unsigned char* pIV);
	//IppStatus init(const unsigned char* pwd,int pwdlen,enum Mode md=CBC);
};
#endif
