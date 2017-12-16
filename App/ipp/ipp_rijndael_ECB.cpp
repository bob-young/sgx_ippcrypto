#include "ipp_rijndael_ECB.h"

#define ECB_SIZE 16

IppStatus ipp_rijndael_ECB::encrypt(unsigned char* src,unsigned char* dest,int length,int* dest_len)
{
	IppStatus istate;
	if(length==0){
		printf("ipp rigndael encrypt input data error %s\n",ippcpGetStatusString(istate));
		return -1;
	}
	int real_len=((length-1)/ECB_SIZE+1)*16;
	*dest_len=real_len;
	unsigned char* src_ec=(unsigned char*)calloc(real_len,sizeof(unsigned char));
	memcpy(src_ec,src,length);
	istate=ippsAESEncryptECB(src_ec,dest,real_len,rijndael_context);
	//printf("encrypt:%p\n",rijndael_context);
	if(istate != 0){
		printf("ipp rigndael encrypt error %s\n",ippcpGetStatusString(istate));
		return istate;	
	}
	//free(src_ec);
	return istate;
}

IppStatus ipp_rijndael_ECB::decrypt(unsigned char* src,unsigned char* dest,int length)
{
	IppStatus istate;
	istate=ippsAESDecryptECB(src,dest,length,rijndael_context );
	//printf("decrypt:%p\n",rijndael_context);	
	if(istate != 0){
		printf("ipp rigndael decrypt error %s\n",ippcpGetStatusString(istate));
		return istate;	
	}
	return istate;
}
