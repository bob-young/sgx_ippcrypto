#include "ipp_rijndael_CTR.h"


IppStatus ipp_rijndael_CTR::encrypt(unsigned char* src,unsigned char* dest,int length,int* dest_len)
{
	IppStatus istate;
	if(length==0){
		//printf("ipp rigndael encrypt input data error %s\n",ippcpGetStatusString(istate));
		return -1;
	}
	unsigned char pCtrValue=0;
	//int real_len=((length-1)/cfbBlkSize+1)*16;
	int real_len=length;
	*dest_len=real_len;
	unsigned char* src_ec=(unsigned char*)calloc(real_len,sizeof(unsigned char));
	memcpy(src_ec,src,length);
	//istate=ippsAESEncryptECB(src_ec,dest,real_len,rijndael_context);
	istate=ippsAESEncryptCTR(src_ec,dest,real_len,rijndael_context,&pCtrValue,1);
	//ippsAESEncryptCTR(const Ipp8u* pSrc, Ipp8u* pDst, int srcLen,const IppsAESSpec* pCtx, Ipp8u* pCtrValue , int ctrNumBitSize );
	//printf("encrypt:%p\n",rijndael_context);
	if(istate != 0){
		//printf("ipp rigndael encrypt error %s\n",ippcpGetStatusString(istate));
		return istate;	
	}
	//free(src_ec);
	return istate;
}

IppStatus ipp_rijndael_CTR::decrypt(unsigned char* src,unsigned char* dest,int length)
{
	IppStatus istate;
	//istate=ippsAESDecryptECB(src,dest,length,rijndael_context );
	unsigned char pCtrValue=0;
	istate=ippsAESDecryptCTR(src,dest,length,rijndael_context,&pCtrValue,1);
	//IppStatus ippsAESDecryptCTR(const Ipp8u* pSrc, Ipp8u* pDst, int srcLen,const IppsAESSpec* pCtx, Ipp8u* pCtrValue, int ctrNumBitSize );
	//printf("decrypt:%p\n",rijndael_context);	
	if(istate != 0){
		//printf("ipp rigndael decrypt error %s\n",ippcpGetStatusString(istate));
		return istate;	
	}
	return istate;
}
