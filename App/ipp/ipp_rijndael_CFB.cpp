#include "ipp_rijndael_CFB.h"


IppStatus ipp_rijndael_CFB::encrypt(unsigned char* src,unsigned char* dest,int length,int* dest_len,int cfbBlkSize,unsigned char* pIV)
{
	IppStatus istate;
	if(length==0){
		printf("ipp rigndael encrypt input data error %s\n",ippcpGetStatusString(istate));
		return -1;
	}
	int real_len=((length-1)/cfbBlkSize+1)*16;
	*dest_len=real_len;
	unsigned char* src_ec=(unsigned char*)calloc(real_len,sizeof(unsigned char));
	memcpy(src_ec,src,length);
	//istate=ippsAESEncryptECB(src_ec,dest,real_len,rijndael_context);
	istate=ippsAESEncryptCFB(src_ec,dest,real_len,cfbBlkSize,rijndael_context,pIV);
	//printf("encrypt:%p\n",rijndael_context);
	if(istate != 0){
		printf("ipp rigndael encrypt error %s\n",ippcpGetStatusString(istate));
		return istate;	
	}
	//free(src_ec);
	return istate;
}

IppStatus ipp_rijndael_CFB::decrypt(unsigned char* src,unsigned char* dest,int length,int cfbBlkSize,unsigned char* pIV)
{
	IppStatus istate;
	//istate=ippsAESDecryptECB(src,dest,length,rijndael_context );
	istate=ippsAESDecryptCFB(src,dest,length,cfbBlkSize,rijndael_context,pIV );
	//printf("decrypt:%p\n",rijndael_context);	
	if(istate != 0){
		printf("ipp rigndael decrypt error %s\n",ippcpGetStatusString(istate));
		return istate;	
	}
	return istate;
}
