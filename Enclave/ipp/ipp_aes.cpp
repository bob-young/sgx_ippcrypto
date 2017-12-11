#include "ipp_aes.h"
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#define Pivlen_Default 16

//ipp_aes::ipp_aes(){}

IppStatus ipp_aes::init(unsigned char* pwd,int pwdlen,unsigned char* piv,int pivlen)
{
	IppStatus istate;
	if(pwdlen!=16 && pwdlen!=24 && pwdlen!=32){
		//printf("private key length error\n");
		ocall_print_string("private key length error");
		return -1;
	}
	t_pwd=pwd;
	t_pwdlen=pwdlen;

	ippsAES_GCMGetSize(&AES_GCM_ContextSize);
	gcm_context=(IppsAES_GCMState*)malloc(AES_GCM_ContextSize);
	istate=ippsAES_GCMInit(t_pwd,t_pwdlen,gcm_context,AES_GCM_ContextSize);
	if(istate != 0){
		//printf("ipp aes init error:%s\n",ippcpGetStatusString(istate));
		ocall_print_string("ipp aes init error:");
		ocall_print_string(ippcpGetStatusString(istate));
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

IppStatus ipp_aes::reset()
{
	return ipp_aes::init(t_pwd,t_pwdlen,t_piv,t_pivlen);
}

IppStatus ipp_aes::encrypt(unsigned char* src,unsigned char* dest,int length)
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
			ocall_print_string("ipp aes encrypt error:");
			ocall_print_string(ippcpGetStatusString(istate));
			return istate;	
		}
	}
	return istate;
}

IppStatus ipp_aes::decrypt(unsigned char* src,unsigned char* dest,int length)
{
	IppStatus istate;
	for(int i=0;i<length;i=i+block_size){
		if(length-i<block_size){
			istate=ippsAES_GCMDecrypt(src+i,dest+i,length-i,gcm_context);
		}else{
			istate=ippsAES_GCMDecrypt(src+i,dest+i,block_size,gcm_context);
		}
		
		if(istate != 0){
			ocall_print_string("ipp aes decrypt error:");
			ocall_print_string(ippcpGetStatusString(istate));
			//printf("ipp aes decrypt error %s\n",ippcpGetStatusString(istate));
			return istate;	
		}
	}
	return istate;
}
