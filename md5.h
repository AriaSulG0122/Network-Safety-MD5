#pragma once

/* MD5 Class. */
class MyMD5 {
public:
	MyMD5();
	~MyMD5();
	bool GetFileMd5(char *pMd5, const char *pFileName);
private:
	/*
	*********数据区*********
	*/
	//四个初始向量
	unsigned long int state[4];
	//计数，count[0]代表低位，count[1]代表高位，记录已经运算的比特数
	unsigned long int count[2];
	//输入缓冲区，保存消息被划分后不足64字节的数据
	unsigned char buffer[64];
	//填充位
	unsigned char pad[64];

	/*
	*********函数区*********
	*/
	//初始化向量和填充位
	void Init();
	//将输入划分为若干个64字节分组，然后调用transform函数进行MD5计算
	void Update(unsigned char *input, unsigned int inputLen);
	//对一个512比特消息分组进行MD5计算
	void Tranform(unsigned long int state[4], unsigned char block[64]);
	//进行末尾部分的处理，形成最终的数字摘要
	void Final(unsigned char digest[16]);
	//将双字转为字节
	void Encode(unsigned char *output, unsigned long int *input, unsigned int len);
	//将字节转为双字
	void Decode(unsigned long int *output, unsigned char *input, unsigned int len);
};
