/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sqlite3.h"

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <create_key_ta.h>

#define DATA_SIZE    128

#define AES_TEST_BUFFER_SIZE	128
#define AES_TEST_KEY_SIZE	16
#define AES_BLOCK_SIZE		16

#define DECODE			0
#define ENCODE			1

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

//密钥管理数据结构
struct key_manger{
	char key_1[16];//密钥16字节
	int key_id[4096];//密钥id（一次对应100个数据1对100,对应K_id）
};

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_CREATE_KEY_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

void prepare_aes(struct test_ctx *ctx, int encode)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);

	op.params[0].value.a = TA_AES_ALGO_CTR;
	op.params[1].value.a = TA_AES_SIZE_128BIT;
	op.params[2].value.a = encode ? TA_AES_MODE_ENCODE :
					TA_AES_MODE_DECODE;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_PREPARE,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
			res, origin);
}

void set_key(struct test_ctx *ctx, char *key, size_t key_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = key_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_KEY,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
			res, origin);
}

void set_iv(struct test_ctx *ctx, char *iv, size_t iv_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = iv_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_IV,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
			res, origin);
}

//加密成密文数据库
void cipher_buffer(struct test_ctx *ctx, char *in, char *out, size_t sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = sz;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
			res, origin);
}

//读取数据并根据数据找出是否存在对应密钥
void read_data_manger(char **database_rd, int num){
	sqlite3 *db;
	if(SQLITE_OK != sqlite3_open("book.db",&db) )
    {
        printf("sqlite3_open error\n");
        exit(1);
    }
	char **pResult;
    int row, column, i, j, index;
    char *sql = sqlite3_mprintf("select * from book where book_num = '%d'",num);

    if(SQLITE_OK != sqlite3_get_table(db,sql,&pResult,&row,&column,&errmsg) )
    {
        printf("can not get table\n");
        exit(1);
    }

    index = column;
    for(i=0; i<column; i++)
    {
        printf("%-s\t", pResult[i]);
    }
    printf("\n");
    for(i=0; i<row; i++)
    {
        for(j=0; j<column; j++)
        {
		   database_rd[j] = pResult[index];
           printf("%-5s    \t", pResult[index++]);
		   
        }
        printf("\n");
    }
	printf("byebye!\n");
    sqlite3_close(db);
    exit(0);
}

//把数据存回数据库
void wirte_data_manger(char **database_wd, int num){
	sqlite3 *db;
	if(SQLITE_OK != sqlite3_open("book.db",&db) )
    {
        printf("sqlite3_open error\n");
        exit(1);
    }
	char *sql;

    sql = sqlite3_mprintf("update book set book_name = '%s' where book_num = '%d'",database_wd[0], book_num);

    if(SQLITE_OK != sqlite3_exec(db,sql,NULL,NULL,&errmsg) )
    {
        printf("sqlite3_exec update error\n");
        exit(1);
    }
    else
    {
        printf("更新成功！\n");
    }

    return;
}

//读密钥文件接口（REE文件系统）
char read_key_manger(int *fg_ifdef, char key[], int num_id){
	//打开文件，如果不存在，直接返回
	FILE *km = fopen("key.txt","r");
	if(km == NULL){
		*fg_ifdef = 0;
		printf("no exist filesystem in manger!");
		fclose(km);
		return;	
	}
	char line[1024];
	int count = 0;
	while(!feof(km)){
		//按行读取文件
		fgets(line, 1024, km);
		count++;
		if(num_id <= 100 && count == 1){		
			strcpy(key, line);
			printf("it's useful key in manger!");
			*fg_ifdef = 1;
			fclose(km);
			return;
		}
		else if(num_id > 100 && count-1 == num_id / 100){
			strcpy(key, line);
			printf("it's useful key in manger!");
			*fg_ifdef = 1;
			fclose(km);
			return;
		}
	}
	if(*fg_ifdef == 0){
		printf("it's no useful key in manger!");
	}
	fclose(km);
	return key;
}

//写密钥文件接口（REE文件系统）
void write_key_manger(char *key){
	FILE *fp;
	if ((fp=fopen("key.txt","a"))==NULL)	
	{
		printf("Open Failed.\n");
		return;
	}
	fprintf(fp,"%s\n",key);			
	fclose(fp);						

}


//加载数据库数据到tee加解密进行
void cipher_data(struct test_ctx *ctx, char *in, char *out, size_t sz)
{

	
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = in;//密文
	op.params[0].tmpref.size = sz;
	op.params[1].tmpref.buffer = out;//修改后密文
	op.params[1].tmpref.size = sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_DATA,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
			res, origin);
}


//create_key
void random_key(struct test_ctx *ctx, char *key, size_t key_sz){
	TEEC_Result res;
	TEEC_Operation op = { 0 };
	//TEEC_UUID uuid = TA_CREATE_KEY_UUID;
	uint8_t random_uuid[16] = { 0 };
	uint32_t err_origin;
	int i;

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = random_uuid;
	op.params[0].tmpref.size = sizeof(random_uuid);

	/*
	 * TA_EXAMPLE_RANDOM_GENERATE is the actual function in the TA to be
	 * called.
	 */
	printf("Invoking TA to generate random UUID... \n");
	res = TEEC_InvokeCommand(&ctx->sess, TA_CREATE_KEY_CMD_GENERATE,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	printf("TA generated UUID value = 0x");
	for (i = 0; i < 16; i++)
		printf("%x", random_uuid[i]);
	printf("\n");


}

int main(void)
{
	struct test_ctx ctx;
	char key[AES_TEST_KEY_SIZE];
	char iv[AES_BLOCK_SIZE];
	char clear[AES_TEST_BUFFER_SIZE];
	char ciph[AES_TEST_BUFFER_SIZE];
	char temp[AES_TEST_BUFFER_SIZE];

	int key_ifdev = 0;//是否存在对应密钥标志
	char *database_rd[DATA_SIZE];//数据库读数据
	
	char *database_wd[DATA_SIZE];//数据库写数据

	printf("Prepare session with the TA\n");
	prepare_tee_session(&ctx);

	printf("Prepare encode operation\n");
	prepare_aes(&ctx, ENCODE);

	int num_id = 0;//读取的number号
	//读取数据(从数据库读)
	read_data_manger(database_rd, num_id);
	
	//读取密钥(读文件系统)
	read_key_manger(&key_ifdev, &key, num_id);
	
	if(key_ifdev == 0){
		printf("create key in TA\n");
		//生成密钥(需要下一步加入hash算法)
		random_key(&ctx, key, AES_TEST_KEY_SIZE);
		//写入密钥(从文件系统写)(下一步从安全接口写入)
		write_key_manger(key);
	}

	//加载密钥
	printf("Load key in TA\n");
	//memset(key, 0xa5, sizeof(key)); /* Load some dummy value */
	set_key(&ctx, key, AES_TEST_KEY_SIZE);

	//加载iv
	printf("Reset ciphering operation in TA (provides the initial vector)\n");
	memset(iv, 0, sizeof(iv)); /* Load some dummy value */
	set_iv(&ctx, iv, AES_BLOCK_SIZE);


	//执行变成密文数据库
	printf("Encode buffer from TA\n");
	cipher_buffer(&ctx, database_rd[0], ciph, AES_TEST_BUFFER_SIZE);

	//执行加解密操作
	printf("Encode buffer from TA\n");
	//memset(clear, 0x5a, sizeof(clear)); /* Load some dummy value */
	//cipher_buffer(&ctx, clear, ciph, AES_TEST_BUFFER_SIZE);
	cipher_data(&ctx, database_rd[0], database_wd[0], AES_TEST_BUFFER_SIZE);

	/*//准备解密
	printf("Prepare decode operation\n");
	prepare_aes(&ctx, DECODE);

	//加载密钥
	printf("Load key in TA\n");
	//memset(key, 0xa5, sizeof(key)); 
	set_key(&ctx, key, AES_TEST_KEY_SIZE);

	//加载iv
	printf("Reset ciphering operation in TA (provides the initial vector)\n");
	memset(iv, 0, sizeof(iv)); 
	set_iv(&ctx, iv, AES_BLOCK_SIZE);

	//执行解密操作
	printf("Decode buffer from TA\n");
	cipher_buffer(&ctx, ciph, temp, AES_TEST_BUFFER_SIZE);*/


	//把数据存回数据库
	write_key_manger(database_wd, num_id);

	/* Check decoded is the clear content 
	if (memcmp(clear, temp, AES_TEST_BUFFER_SIZE))
		printf("Clear text and decoded text differ => ERROR\n");
	else
		printf("Clear text and decoded text match\n");*/

	terminate_tee_session(&ctx);
	return 0;
}

