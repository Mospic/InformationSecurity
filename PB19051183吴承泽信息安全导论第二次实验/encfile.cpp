#include <memory.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "openssl\aes.h"

int nLoop; 
int nRes;

#pragma comment(lib,"libcrypto.lib")

void encrypt(char inString[], int inLen, char passwd[], int pwdLen)
{
	int i,j, len;
	char enString[35536];
    nLoop = inLen/16;
    nRes = inLen%16;
	unsigned char buf[16];
	unsigned char buf2[16];
	unsigned char aes_keybuf[32];
	AES_KEY aeskey;

	// 准备32字节(256位)的AES密码字节
	memset(aes_keybuf,0x90,32);
	if(pwdLen<32){ len=pwdLen; } else { len=32;}
	for(i=0;i<len;i++) aes_keybuf[i]=passwd[i];
	// 输入字节串分组成16字节的块	
	nLoop=inLen/16; nRes = inLen%16;
	// 加密输入的字节串
	AES_set_encrypt_key(aes_keybuf,256,&aeskey);
	for(i=0;i<nLoop;i++){
		memset(buf,0,16);
		for(j=0;j<16;j++) buf[j]=inString[i*16+j];
		AES_encrypt(buf,buf2,&aeskey);
		for(j=0;j<16;j++) enString[i*16+j]=buf2[j];
	}
	if(nRes>0){
		memset(buf,0,16);
		for(j=0;j<nRes;j++) buf[j]=inString[i*16+j];
		AES_encrypt(buf,buf2,&aeskey);
		for(j=0;j<16;j++) enString[i*16+j]=buf2[j];
		//puts("encrypt");
	}
	enString[i*16+j]=0;

    FILE *fp;
    if((fp = fopen("encrypt.txt", "wb")) == NULL)
        exit(-1);
	fclose(fp);
    if((fp = fopen("encrypt.txt", "ab")) == NULL)
        exit(-1);

	fprintf(fp,"%d %d ", nLoop, nRes);
	int k;
    for(k = 0; k <= i*16 +j;k++)
		//fprintf(fp,"%c",enString[k]);
		fputc(enString[k], fp);

    fclose(fp);


}

void decrypt(char enString[], int enLen, char passwd[], int pwdLen)
{
	int i,j, len;
	char deString[35536];

	unsigned char buf[16];
	unsigned char buf2[16];
	unsigned char aes_keybuf[32];
	AES_KEY aeskey;
	// 密文串的解密	
	memset(aes_keybuf,0x90,32);
	if(pwdLen<32){ len=pwdLen; } else { len=32;}
	for(i=0;i<len;i++) aes_keybuf[i]=passwd[i];
	AES_set_decrypt_key(aes_keybuf,256,&aeskey);
	for(i=0;i<nLoop;i++){
		memset(buf,0,16);
		for(j=0;j<16;j++) buf[j]=enString[i*16+j];
		AES_decrypt(buf,buf2,&aeskey);
		for(j=0;j<16;j++) deString[i*16+j]=buf2[j];
	}
	if(nRes>0){
		memset(buf,0,16);
		for(j=0;j<16;j++) buf[j]=enString[i*16+j];
		AES_decrypt(buf,buf2,&aeskey);
		for(j=0;j<16;j++) deString[i*16+j]=buf2[j];
		//puts("decrypt");
	}
	deString[i*16+nRes]=0;
    FILE *fp;
    if((fp = fopen("decrypt.cpp", "wb")) == NULL)  
		exit(-1);

    fprintf(fp,"%s", deString);
    fclose(fp);

}

int main(int argc, char* argv[])
{
    FILE *fp;
    char str[35536];
    char pwd[128];
	if(strcmp(argv[1], "enc") == 0)
	{
        if((fp = fopen(argv[2], "rb")) == NULL)
            exit(-1);
        char ch = fgetc(fp);
        int i = 0;
        while(ch != EOF)
        {
            str[i] = ch;
            i++;
			//fscanf(fp,"%c",ch);
            ch = fgetc(fp);
        }
		str[i] = 0;
        encrypt(str, strlen(str), argv[3], strlen(argv[3]));
        fclose(fp);
	}
    else if(strcmp(argv[1], "dec") == 0)
    {
        if((fp = fopen("encrypt.txt", "rb")) == NULL)
            exit(-1);

		fscanf(fp,"%d %d ",&nLoop, &nRes);
        char ch = fgetc(fp);
        int i = 0;
		int length = (nRes)? 16 : 0;
		length += 16 * nLoop;
        while(i < length)
        {
            str[i] = ch;
            //printf("%c",ch);
            i++;
            ch = fgetc(fp);
        }
		str[length] = 0;
        decrypt(str, length, argv[3], strlen(argv[3]));
        fclose(fp);       
    }
    else
    {
        printf("error");
        exit(-1);
    }
	return 0;
}