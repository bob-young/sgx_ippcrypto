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
#include "ipp_rijndael.h"
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
	aes.init(pkey,16,pIV,16);
	char* plain="hello the fucking world\0";
	unsigned char* cipher=(unsigned char*)malloc(24);
	aes.encrypt((unsigned char*)plain,cipher,24);
	unsigned char* output=(unsigned char*)malloc(24);
	
	ipp_aesgcm aes2;
	aes2.init(pkey,16,pIV,16);
	aes2.decrypt(cipher,output,24);	
	printf("out:%s\n",output);


	printf("test rijndael\n");
//test rijndael
	ipp_rijndael rijn;
	rijn.init(pkey,16);
	int cipher_len=0;
	unsigned char* cipher2=(unsigned char*)malloc(24);
	rijn.encrypt((unsigned char*)plain,cipher2,24,&cipher_len,pIV);
	unsigned char* output2=(unsigned char*)malloc(24);
	printf("----%d----\n",cipher_len);
	ipp_rijndael rijn2;
	rijn2.init(pkey,16);
	rijn2.decrypt(cipher2,output2,cipher_len,pIV);	
	printf("out:%s\n",output2);

	return 0;
}

