#pragma once

#include <stdlib.h>
#include <stdio.h>
#include "string.h"
#include "malloc.h"

//类型自定义
#define UINT  unsigned int
#define ULONG unsigned long int 
#define UCHAR unsigned char

/* MD5 Class. */
class MyMD5 {
public:
	MyMD5();
	~MyMD5();
	//从文件中读取内容
	bool ReadFile(const char *pFileName);
	//从用户输入中读取内容
	bool ReadInput(char *content);
	//获取封装好的数字摘要
	void getDigest(char *digest);
private:
	/*
	*********数据区*********
	*/
	//四个初始向量
	ULONG state[4];
	//计数，count[0]代表低位，count[1]代表高位，记录已经运算的比特数
	ULONG count[2];
	//输入缓冲区，保存消息被划分后不足64字节的数据
	UCHAR buffer[64];
	//填充位
	UCHAR pad[64];
	char myDigest[129];
	/*
	*********函数区*********
	*/
	//开展MD5的处理流程
	void Workflow(UCHAR *content, UINT length);
	//将输入划分为若干个64字节分组，然后调用transform函数进行MD5计算
	void Update(UCHAR *input, UINT inputLen);
	//对一个512比特消息分组进行MD5计算
	void Tranform(ULONG state[4], UCHAR block[64]);
	//进行末尾部分的处理，形成最终的数字摘要
	void Final(UCHAR digest[16]);
	//将双字转为字节
	void Encode(UCHAR *output, ULONG *input, UINT len);
	//将字节转为双字
	void Decode(ULONG *output, UCHAR *input, UINT len);
};
