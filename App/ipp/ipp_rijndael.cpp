#include "ipp_rijndael.h"
#define Pivlen_Default 16
#define CBC_SIZE 16
//ipp_aes::ipp_aes(){}

IppStatus ipp_rijndael::init(const unsigned char* pwd,int pwdlen,enum Mode md)
{
	IppStatus istate;
	mode=md;
	if(pwdlen!=16){
		printf("private key length error\n");
		return -1;
	}
	t_pwd=pwd;
	t_pwdlen=pwdlen;

	ippsAESGetSize(&Rijndael_ContextSize);
	//rijndael_context=(IppsAESSpec*)malloc(Rijndael_ContextSize);
	rijndael_context = (IppsAESSpec*)( new Ipp8u [Rijndael_ContextSize] );
	//rijndael_context=(IppsAESSpec*) (new unsigned char (Rijndael_ContextSize));
	//printf("malloc:%p\n",rijndael_context);
	istate=ippsAESInit(t_pwd,t_pwdlen,rijndael_context,Rijndael_ContextSize);
	if(istate != 0){
		printf("ipp rigndael init error:%s\n",ippcpGetStatusString(istate));
		return -1;	
	}

	return istate;
}

IppStatus ipp_rijndael::reset()
{
	//return ipp_aes::init(t_pwd,t_pwdlen,t_piv,t_pivlen);
	return 0;
}

int ipp_rijndael::get_Rijndael_ContextSize()
{
	//return ipp_aes::init(t_pwd,t_pwdlen,t_piv,t_pivlen);
	return Rijndael_ContextSize;
}

// IppStatus ipp_rijndael::encrypt_CBC(unsigned char* src,unsigned char* dest,int length,int* dest_len,unsigned char* pIV)
// {
// 	IppStatus istate;
// 	if(length==0){
// 		printf("ipp rigndael encrypt input data error %s\n",ippcpGetStatusString(istate));
// 		return -1;
// 	}
// 	int real_len=((length-1)/CBC_SIZE+1)*16;
// 	*dest_len=real_len;
// 	unsigned char* src_ec=(unsigned char*)calloc(real_len,sizeof(unsigned char));
// 	memcpy(src_ec,src,length);
// 	istate=ippsAESEncryptCBC(src_ec,dest,real_len,rijndael_context,pIV );
// 	//printf("encrypt:%p\n",rijndael_context);
// 	if(istate != 0){
// 		printf("ipp rigndael encrypt error %s\n",ippcpGetStatusString(istate));
// 		return istate;	
// 	}
// 	//free(src_ec);
// 	return istate;
// }

// IppStatus ipp_rijndael::decrypt_CBC(unsigned char* src,unsigned char* dest,int length,unsigned char* pIV)
// {
// 	IppStatus istate;
// 	istate=ippsAESDecryptCBC(src,dest,length,rijndael_context,pIV );
// 	//printf("decrypt:%p\n",rijndael_context);	
// 	if(istate != 0){
// 		printf("ipp rigndael decrypt error %s\n",ippcpGetStatusString(istate));
// 		return istate;	
// 	}
// 	return istate;
// }


// IppStatus ipp_rijndael::encrypt_ECB(unsigned char* src,unsigned char* dest,int length,int* dest_len)
// {
// 	IppStatus istate;
// 	if(length==0){
// 		printf("ipp rigndael encrypt input data error %s\n",ippcpGetStatusString(istate));
// 		return -1;
// 	}
// 	int real_len=((length-1)/CBC_SIZE+1)*16;
// 	*dest_len=real_len;
// 	unsigned char* src_ec=(unsigned char*)calloc(real_len,sizeof(unsigned char));
// 	memcpy(src_ec,src,length);
// 	istate=ippsAESEncryptECB(src_ec,dest,real_len,rijndael_context);
// 	//printf("encrypt:%p\n",rijndael_context);
// 	if(istate != 0){
// 		printf("ipp rigndael encrypt error %s\n",ippcpGetStatusString(istate));
// 		return istate;	
// 	}
// 	//free(src_ec);
// 	return istate;
// }

// IppStatus ipp_rijndael::decrypt_ECB(unsigned char* src,unsigned char* dest,int length)
// {
// 	IppStatus istate;
// 	istate=ippsAESDecryptECB(src,dest,length,rijndael_context );
// 	//printf("decrypt:%p\n",rijndael_context);	
// 	if(istate != 0){
// 		printf("ipp rigndael decrypt error %s\n",ippcpGetStatusString(istate));
// 		return istate;	
// 	}
// 	return istate;
// }


void ipp_rijndael::set_block_size(int size)
{
	block_size=size;
	return;
}

const unsigned char* ipp_rijndael::get_Rijndael_pwd()
{
	return t_pwd;
}
int ipp_rijndael::get_Rijndael_pwdlen()
{
	return t_pwdlen;
}

int ipp_rijndael::ipp_free()
{
	int istate=ippsAESInit(0,get_Rijndael_pwdlen(),rijndael_context,get_Rijndael_ContextSize());

	//memset(rijndael_context,0,get_Rijndael_ContextSize());
	// printf("%s\t %d\n", get_Rijndael_pwd(),get_Rijndael_pwdlen());
	if(istate != 0){
		printf("ipp rigndael init error:%s\n",ippcpGetStatusString(istate));
		return -1;	
	}
	printf("free:%p\n",rijndael_context);
	free(rijndael_context);
	return 0;
	//delete [] ((unsigned char *)rijndael_context);
}
ipp_rijndael::~ipp_rijndael()
{


}
