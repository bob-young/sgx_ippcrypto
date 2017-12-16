#include "ipp_rijndael_CBC.h"

#define CBC_SIZE 16

IppStatus ipp_rijndael_CBC::encrypt(unsigned char* src,unsigned char* dest,int length,int* dest_len,unsigned char* pIV)
{
	IppStatus istate;
	if(length==0){
		printf("ipp rigndael encrypt input data error %s\n",ippcpGetStatusString(istate));
		return -1;
	}
	int real_len=((length-1)/CBC_SIZE+1)*16;
	*dest_len=real_len;
	unsigned char* src_ec=(unsigned char*)calloc(real_len,sizeof(unsigned char));
	memcpy(src_ec,src,length);
	istate=ippsAESEncryptCBC(src_ec,dest,real_len,rijndael_context,pIV );
	//printf("encrypt:%p\n",rijndael_context);
	if(istate != 0){
		printf("ipp rigndael encrypt error %s\n",ippcpGetStatusString(istate));
		return istate;	
	}
	//free(src_ec);
	return istate;
}

IppStatus ipp_rijndael_CBC::decrypt(unsigned char* src,unsigned char* dest,int length,unsigned char* pIV)
{
	IppStatus istate;
	istate=ippsAESDecryptCBC(src,dest,length,rijndael_context,pIV );
	//printf("decrypt:%p\n",rijndael_context);	
	if(istate != 0){
		printf("ipp rigndael decrypt error %s\n",ippcpGetStatusString(istate));
		return istate;	
	}
	return istate;
}
