#include "ipp_rijndael.h"
#define Pivlen_Default 16
#define CBC_SIZE 16
//ipp_aes::ipp_aes(){}

IppStatus ipp_rijndael::init(const unsigned char* pwd,int pwdlen)
{
	IppStatus istate;
	if(pwdlen!=16){
		printf("private key length error\n");
		return -1;
	}
	t_pwd=pwd;
	t_pwdlen=pwdlen;

	ippsAESGetSize(&Rijndael_ContextSize);
	rijndael_context=(IppsAESSpec*)malloc(Rijndael_ContextSize);
	//printf("malloc:%p\n",rijndael_context);
	istate=ippsAESInit(t_pwd,t_pwdlen,rijndael_context,Rijndael_ContextSize);
	if(istate != 0){
		printf("ipp rigndael init error:%s\n",ippcpGetStatusString(istate));
		return -1;	
	}
/*-----------------------
	if(piv == NULL){
		t_pivlen=Pivlen_Default;
		t_piv=(unsigned char*)malloc(Pivlen_Default);
		for(int i=0;i<Pivlen_Default;i++){
			t_piv[i]=0;
		}
	}else{
		t_piv=piv;
		t_pivlen=pivlen;	
	}
	ippsAES_GCMProcessIV(t_piv,t_pivlen,gcm_context);
	istate=ippsAES_GCMStart(t_piv,t_pivlen,NULL,0,gcm_context);
	//ipp_init=1;
*/
	return istate;
}

IppStatus ipp_rijndael::reset()
{
	//return ipp_aes::init(t_pwd,t_pwdlen,t_piv,t_pivlen);
	return 0;
}

IppStatus ipp_rijndael::encrypt(unsigned char* src,unsigned char* dest,int length,int* dest_len,unsigned char* pIV)
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

IppStatus ipp_rijndael::decrypt(unsigned char* src,unsigned char* dest,int length,unsigned char* pIV)
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

void ipp_rijndael::set_block_size(int size)
{
	block_size=size;
	return;
}
void ipp_rijndael::ipp_free()
{
	//printf("free:%p\n",rijndael_context);
	//free(rijndael_context);
}
ipp_rijndael::~ipp_rijndael()
{


}
