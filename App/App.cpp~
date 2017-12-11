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

	return 0;
}

