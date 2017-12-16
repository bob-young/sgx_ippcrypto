#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>

#include <iostream>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"


#include "enclave.h"
#include "ipp_aesgcm.h"
#include "ipp_rijndael_ECB.h"
#include "ipp_rijndael_CFB.h"
#include "ipp_rijndael_CBC.h"
sgx_enclave_id_t global_eid = 0;

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
	(void)(argc);
	(void)(argv);

	enclave ecv=enclave(TOKEN_FILENAME,ENCLAVE_FILENAME);

	if(ecv.init(NULL) < 0){
		printf("init failed and exit ...\n");
		getchar();
		return -1; 
	}
//-1
 
	char* start[3];
	start[0]="start\n";
	start[1]="in\n";
	start[2]="app\n";
	//encall_print(global_eid,start);
	ecv.print(start);
	//printf("global eid:%d\n",global_eid);
	std::cout<<"enclave id:"<< ecv.enclave_id<<std::endl;
	std::cout<<"token:"<<ecv.p_token_path<<":"<<ecv.token_filename<<std::endl;
	std::cout<<"enclave file:"<<ecv.enclave_filename<<std::endl;
	//std::cout<<<<std::endl
	ecv.destroy();
//test ipp
	printf("test aes gcm\n");
	ipp_aesgcm aes;
	unsigned char pkey[16]={1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};//16||32||64
	unsigned char pIV[16]={1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
		printf("size  = %d\n",sizeof(pkey) );
	aes.init(pkey,16,pIV,16);
	char* plain="hello the fucking world\0";
	unsigned char* cipher=(unsigned char*)malloc(24);
	aes.encrypt((unsigned char*)plain,cipher,24);
	unsigned char* output=(unsigned char*)malloc(24);
	
	ipp_aesgcm aes2;
	aes2.init(pkey,16,pIV,16);
	aes2.decrypt(cipher,output,24);	
	printf("out:%s\n",output);

	int cipher_len=0;

	printf("test rijndael ecb\n");
	ipp_rijndael_ECB rijn;
	rijn.init(pkey,16);
	unsigned char* cipher2=(unsigned char*)malloc(24);
	//rijn.encrypt_CBC((unsigned char*)plain,cipher2,24,&cipher_len,pIV);
	rijn.encrypt_ECB((unsigned char*)plain,cipher2,24,&cipher_len);
	unsigned char* output2=(unsigned char*)malloc(24);
	printf("----%d----\n",cipher_len);
	ipp_rijndael_ECB rijn2;
	rijn2.init(pkey,16);
	//rijn2.decrypt_CBC(cipher2,output2,cipher_len,pIV);
	rijn2.decrypt_ECB(cipher2,output2,cipher_len);	
	printf("out:%s\n",output2);
	printf("context:%p\n",rijn.rijndael_context);
	printf("context:%p\n",rijn2.rijndael_context);
	//free(rijn.rijndael_context);
	printf("test rijndael cfb\n");
	ipp_rijndael_CFB rijn3;
	rijn3.init(pkey,16);
	unsigned char* cipher3=(unsigned char*)malloc(24);
	//rijn.encrypt_CBC((unsigned char*)plain,cipher2,24,&cipher_len,pIV);
	rijn3.encrypt_CFB((unsigned char*)plain,cipher3,24,&cipher_len,16,pIV);
	unsigned char* output3=(unsigned char*)malloc(24);
	ipp_rijndael_CFB rijn4;
	rijn4.init(pkey,16);
	//rijn2.decrypt_CBC(cipher2,output2,cipher_len,pIV);
	rijn4.decrypt_CFB(cipher3,output3,cipher_len,16,pIV);	
	printf("out:%s\n",output3);
	printf("context:%p\n",rijn3.rijndael_context);
	printf("context:%p\n",rijn4.rijndael_context);

	// printf("test rijndael cbc\n");
	// ipp_rijndael_CBC rijn5;
	// rijn5.init(pkey,16);
	// unsigned char* cipher4=(unsigned char*)malloc(24);
	// //rijn.encrypt_CBC((unsigned char*)plain,cipher2,24,&cipher_len,pIV);
	// rijn5.encrypt((unsigned char*)plain,cipher4,24,&cipher_len,pIV);
	// unsigned char* output4=(unsigned char*)malloc(24);
	// ipp_rijndael_CBC rijn6;
	// rijn6.init(pkey,16);
	// //rijn2.decrypt_CBC(cipher2,output2,cipher_len,pIV);
	// rijn6.decrypt(cipher4,output4,cipher_len,pIV);	
	// printf("out:%s\n",output4);
	// printf("context:%p\n",rijn5.rijndael_context);
	// printf("context:%p\n",rijn6.rijndael_context);


	//rijn2.ipp_free();
	return 0;
}

