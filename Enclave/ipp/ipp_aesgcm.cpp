#include "ipp_aesgcm.h"

#define Pivlen_Default 16

//ipp_aes::ipp_aes(){}

IppStatus ipp_aesgcm::init(const unsigned char* pwd,int pwdlen,unsigned char* piv,int pivlen)
{
	IppStatus istate;
	if(pwdlen!=16 && pwdlen!=24 && pwdlen!=32){
		//printf("private key length error\n");
		return -1;
	}
	t_pwd=pwd;
	t_pwdlen=pwdlen;

	ippsAES_GCMGetSize(&AES_GCM_ContextSize);
	gcm_context=(IppsAES_GCMState*)malloc(AES_GCM_ContextSize);
	istate=ippsAES_GCMInit(t_pwd,t_pwdlen,gcm_context,AES_GCM_ContextSize);
	if(istate != 0){
		//printf("ipp aes init error:%s\n",ippcpGetStatusString(istate));
		return -1;	
	}
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
	return istate;
}

IppStatus ipp_aesgcm::reset()
{
	return ipp_aesgcm::init(t_pwd,t_pwdlen,t_piv,t_pivlen);
}

IppStatus ipp_aesgcm::encrypt(unsigned char* src,unsigned char* dest,int length)
{
	IppStatus istate;
	for(int i=0;i<length;i=i+block_size){
		if(length-i<block_size){
			istate=ippsAES_GCMEncrypt(src+i,dest+i,length-i,gcm_context);
		}else{
			istate=ippsAES_GCMEncrypt(src+i,dest+i,block_size,gcm_context);
		}
		
		if(istate != 0){
			//printf("ipp aes encrypt error %s\n",ippcpGetStatusString(istate));
			return istate;	
		}
	}
	return istate;
}

IppStatus ipp_aesgcm::decrypt(unsigned char* src,unsigned char* dest,int length)
{
	IppStatus istate;
	for(int i=0;i<length;i=i+block_size){
		if(length-i<block_size){
			istate=ippsAES_GCMDecrypt(src+i,dest+i,length-i,gcm_context);
		}else{
			istate=ippsAES_GCMDecrypt(src+i,dest+i,block_size,gcm_context);
		}
		
		if(istate != 0){
			//printf("ipp aes decrypt error %s\n",ippcpGetStatusString(istate));
			return istate;	
		}
	}
	return istate;
}

void ipp_aesgcm::set_block_size(int size)
{
	block_size=size;
	return;
}

ipp_aesgcm::~ipp_aesgcm()
{
	free(gcm_context);
}
