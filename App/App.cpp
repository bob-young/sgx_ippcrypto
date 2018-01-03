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
#include "ipp_rijndael_CTR.h"

#include "ippcp.h"
#include "BigNumber.h"

#include <iomanip> 
using namespace std;
sgx_enclave_id_t global_eid = 0;
struct a1
{
	long a=0;
	long b=0;
};




int PrimeGen_sample(void){//PrimeGen
	int error = 0;
	int ctxSize;
	// define 256-bit Prime Generator
	int maxBitSize = 256;
	ippsPrimeGetSize(256, &ctxSize);
	IppsPrimeState* pPrimeG = (IppsPrimeState*)( new Ipp8u [ctxSize] );
	ippsPrimeInit(256, pPrimeG);
	// define Pseudo Random Generator (default settings)
	ippsPRNGGetSize(&ctxSize);
	IppsPRNGState* pRand = (IppsPRNGState*)(new Ipp8u [ctxSize] );
	ippsPRNGInit(160, pRand);
	do {
	Ipp32u result;
	// test primality of the value (known in advance)
	BigNumber P1("0xDB7C2ABF62E35E668076BEAD208B");
	ippsPrimeTest_BN(P1, 50, &result, pPrimeG, ippsPRNGen, pRand);
	error = IPP_IS_PRIME!=result;
	if(error) {
	cout <<"Primality of the known prime isn't confirmed\n";
	break;
	}
	else cout <<"Primality of the known prime is confirmed\n"<<"size:"<<P1.BitSize()<<
		"\ncontext:"<<BN(P1)<<endl;
	unsigned char* pp=(unsigned char* )&P1;
	for(int i = 0;i<P1.BitSize()/8;i++){
		printf("%02x ",*(pp+i));
	}


	// generate 256-bit prime
	BigNumber P(0, 256/8);
	while( ippStsNoErr != ippsPrimeGen_BN(P, 256, 50, pPrimeG, ippsPRNGen, pRand) ) ;
	// and test it
	ippsPrimeTest_BN(P, 50, &result, pPrimeG, ippsPRNGen, pRand);
	error = IPP_IS_PRIME!=result;
	if(error) {
	cout <<"Primality of the generated number isn't confirmed\n";
	break;
	}
	else cout <<"Primality of the generated number is confirmed\n"<<"size:"<<P.BitSize()<<
		"\ncontext:";
	pp=(unsigned char* )BN(P);
	for(int i = 0;i<P.BitSize()/8;i++){
		printf("%02x ",*(pp+i));
	}
	//BN(P);
	} while(0);
	delete [] (Ipp8u*)pRand;
	delete [] (Ipp8u*)pPrimeG;
}


IppsBigNumState* New_BN(int size, const Ipp32u* pData=0)
{
	// get the size of the Big Number context
	int ctxSize;
	ippsBigNumGetSize(size, &ctxSize);
	// allocate the Big Number context
	IppsBigNumState* pBN = (IppsBigNumState*) (new Ipp8u [ctxSize] );
	// and initialize one
	ippsBigNumInit(size, pBN);
	// if any data was supplied, then set up the Big Number value
	if(pData)
	ippsSet_BN(IppsBigNumPOS, size, pData, pBN);
	// return pointer to the Big Number context for future use
	return pBN;
}

void Type_BN(const char* pMsg, const IppsBigNumState* pBN){
	// size of Big Number
	int size;
	ippsGetSize_BN(pBN, &size);
	// extract Big Number value and convert it to the string presentation
	Ipp8u* bnValue = new Ipp8u [size*4];
	ippsGetOctString_BN(bnValue, size*4, pBN);
	// type header
	if(pMsg)
	cout<<pMsg;
	// type value
	for(int n=0; n<size*4; n++)
	cout<<hex<<std::setfill('0')<<std::setw(2)<<(int)bnValue[n];
	cout<<endl;
	delete [] bnValue;
}

void MontMul_sample(void)
{
	int size;
	// define and initialize Montgomery Engine over Modulus N
	Ipp32u bnuN = 19;
	ippsMontGetSize(IppsBinaryMethod, 1, &size);
	IppsMontState* pMont = (IppsMontState*)( new Ipp8u [size] );
	ippsMontInit(IppsBinaryMethod, 1, pMont);
	ippsMontSet(&bnuN, 1, pMont);
	// define and init Big Number multiplicant A
	Ipp32u bnuA = 12;
	IppsBigNumState* bnA = New_BN(1, &bnuA);
	// encode A into Montfomery form
	ippsMontForm(bnA, pMont, bnA);
	// define and init Big Number multiplicant A
	Ipp32u bnuB = 15;
	IppsBigNumState* bnB = New_BN(1, &bnuB);
	// compute R = A*B mod N
	IppsBigNumState* bnR = New_BN(1);
	ippsMontMul(bnA, bnB, pMont, bnR);
	Type_BN("R = A*B mod N:\n", bnR);
	delete [] (Ipp8u*)pMont;
	delete [] (Ipp8u*)bnA;
	delete [] (Ipp8u*)bnB;
	delete [] (Ipp8u*)bnR;
}


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
	rijn.encrypt((unsigned char*)plain,cipher2,24,&cipher_len);
	unsigned char* output2=(unsigned char*)malloc(24);
	printf("----%d----\n",cipher_len);
	ipp_rijndael_ECB rijn2;
	rijn2.init(pkey,16);
	rijn2.decrypt(cipher2,output2,cipher_len);	
	printf("out:%s\n",output2);
	printf("context:%p\n",rijn.rijndael_context);
	printf("context:%p\n",rijn2.rijndael_context);
	//free((void*)rijn.rijndael_context);
	//delete(rijn.rijndael_context);

	printf("test rijndael ctr\n");
	ipp_rijndael_CTR rijn3;
	rijn3.init(pkey,16);
	unsigned char* cipher3=(unsigned char*)malloc(24);
	//rijn.encrypt_CBC((unsigned char*)plain,cipher2,24,&cipher_len,pIV);
	rijn3.encrypt((unsigned char*)plain,cipher3,24,&cipher_len);
	unsigned char* output3=(unsigned char*)malloc(24);
	ipp_rijndael_CTR rijn4;
	rijn4.init(pkey,16);
	//rijn2.decrypt_CBC(cipher2,output2,cipher_len,pIV);
	rijn4.decrypt(cipher3,output3,cipher_len);	
	printf("out:%s\n",output3);
	printf("context:%p\n",rijn3.rijndael_context);
	printf("context:%p\n",rijn4.rijndael_context);
	printf("test rijndael ctr\n");
/*
	printf("test rijndael cbc\n");
	ipp_rijndael_CBC rijn5;
	rijn5.init(pkey,16);
	unsigned char* cipher4=(unsigned char*)malloc(24);
	rijn5.encrypt((unsigned char*)plain,cipher4,24,&cipher_len,pIV);
	unsigned char* output4=(unsigned char*)malloc(24);
	ipp_rijndael_CBC rijn6;
	rijn6.init(pkey,16);
	rijn6.decrypt(cipher4,output4,cipher_len,pIV);	
	printf("out:%s\n",output4);
	printf("context:%p\n",rijn5.rijndael_context);
	printf("context:%p\n",rijn6.rijndael_context);

*/
	//rijn2.ipp_free();
	printf("test end\n");

	int RSA_Pub_Size=0;
	int RSA_Pri_Size=0;
	BigNumber N("0xBBF82F090682CE9C2338AC2B9DA871F7368D07EED41043A440D6B6F07454F51F"
				  "B8DFBAAF035C02AB61EA48CEEB6FCD4876ED520D60E1EC4619719D8A5B8B807F"
				  "AFB8E0A3DFC737723EE6B4B7D93A2584EE6A649D060953748834B2454598394E"
				  "E0AAB12D7B61A51F527A9A41F6C1687FE2537298CA2A8F5946F8E5FD091DBDCB");
	BigNumber E("0x11");
	ippsRSA_GetSizePublicKey(1024,64,&RSA_Pub_Size);
	printf("rsa size:%d\n",RSA_Pub_Size);
	ippsRSA_GetSizePrivateKeyType1(1024,64,&RSA_Pri_Size);
	printf("rsa size:%d\n",RSA_Pri_Size);
	//ippsRSA_GetSizePrivateKeyType2(1024,64,&RSA_Pri_Size);
	//printf("rsa size:%d\n",RSA_Pri_Size);
	IppsRSAPublicKeyState* pubKey=(IppsRSAPublicKeyState*)malloc(RSA_Pub_Size);
	ippsRSA_InitPublicKey(1024,64,pubKey,RSA_Pub_Size);
	IppsRSAPrivateKeyState* priKey=(IppsRSAPrivateKeyState*)malloc(RSA_Pri_Size);
	ippsRSA_InitPrivateKeyType1(1024,64,priKey,RSA_Pri_Size );
	//ippsRSA_SetPublicKey(const IppsBigNumState* pModulus, const IppsBigNumState* pPublicExp,pubKey );

	int BN_Size=0;
	ippsPrimeGetSize(512,&BN_Size);
	printf("%d\n",BN_Size);
	IppsPrimeState* pCtx=(IppsPrimeState*)malloc(BN_Size);
	ippsPrimeInit(512, pCtx );

	//ippsPrimeGen_BN(IppsBigNumState* pPrime, int nBits, int nTrials,IppsPrimeState* pCtx, IppBitSupplier rndFunc, void* pRndParam );

	PrimeGen_sample();
	MontMul_sample();

	return 0;
}
