#include "enclave.h"

enclave::enclave(string tfn,string efn)
{
	token_filename=tfn;
	enclave_filename=efn;
	//enclave_id=global_eid;
}

int enclave::destroy()
{
	sgx_status_t ret;
	ret = sgx_destroy_enclave(enclave_id);
	if(SGX_SUCCESS==ret){
		printf("Enclave %ld destroy success\n",enclave_id);
	}else{
		print_error_message(ret);
		printf("Enclave %ld destroy failure\n",enclave_id);
	}
	return 0;
}

void enclave::print_error_message(sgx_status_t ret)
{
	size_t idx = 0;
	size_t ttl = errlist_len;

	for (idx = 0; idx < ttl; idx++) {
		if(ret == sgx_errlist[idx].err) {
			if(NULL != sgx_errlist[idx].sug)
				printf("Info: %s\n", sgx_errlist[idx].sug);
			printf("Error: %s\n", sgx_errlist[idx].msg);
			break;
		}
	}
	
	if (idx == ttl)
		printf("Error: Unexpected error occurred.\n");
}

void enclave::print(char** str){
	encall_print(enclave_id,str);
}

int enclave::init(char* token_path)
{
	//char token_path[MAX_PATH] = {'\0'};
	sgx_launch_token_t token = {0};
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;
	const char *home_dir = getpwuid(getuid())->pw_dir;
//set token
	if(token_path==NULL){
	token_path=(char*)malloc(MAX_PATH);
	memset(token_path,0, MAX_PATH); 
	if (home_dir != NULL && 
		(strlen(home_dir)+strlen("/")+sizeof(token_filename)+1) <= MAX_PATH) {
		strncpy(token_path, home_dir, strlen(home_dir));
		strncat(token_path, "/", strlen("/"));
		strncat(token_path, token_filename.c_str(), sizeof(token_filename)+1);
	} else {
		/* if token path is too long or $HOME is NULL */
		strncpy(token_path, token_filename.c_str(), sizeof(token_filename));
	}
	}
//load token
	p_token_path=token_path;
	FILE *fp = fopen(token_path, "rb");
	if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
		printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
	}

	if (fp != NULL) {
		size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
		if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
			/* if token is invalid, clear the buffer */
			memset(&token, 0x0, sizeof(sgx_launch_token_t));
			printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
		}
	}
//create
	ret = sgx_create_enclave(enclave_filename.c_str(), SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		enclave_id=0;
		print_error_message(ret);
		if (fp != NULL) fclose(fp);
		return -1;
	}
	enclave_id=global_eid;
	if (updated == FALSE || fp == NULL) {
		if (fp != NULL) fclose(fp);
		return 0;
	}
	fp = freopen(token_path, "wb", fp);
	if (fp == NULL) return 0;
	size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
	if (write_num != sizeof(sgx_launch_token_t))
		printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
	fclose(fp);
	return 0;
}
