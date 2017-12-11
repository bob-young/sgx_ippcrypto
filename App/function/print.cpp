#include "../App.h"
#include "Enclave_u.h"

/* OCall functions */
void ocall_print_buffer(unsigned char* str,int len)
{
	for(int i=0;i<len;i++){
		printf("%x ",*(str+i));
	}
	printf("\n");
}

void ocall_print_string(const char *str)
{
    printf("%s\n", str);
}

