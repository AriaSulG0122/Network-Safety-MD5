#pragma once

#include <stdlib.h>
#include <stdio.h>
#include "string.h"
#include "malloc.h"

//�����Զ���
#define UINT  unsigned int
#define ULONG unsigned long int 
#define UCHAR unsigned char

/* MD5 Class. */
class MyMD5 {
public:
	MyMD5();
	~MyMD5();
	//���ļ��ж�ȡ����
	bool ReadFile(const char *pFileName);
	//���û������ж�ȡ����
	bool ReadInput(char *content);
	//��ȡ��װ�õ�����ժҪ
	void getDigest(char *digest);
private:
	/*
	*********������*********
	*/
	//�ĸ���ʼ����
	ULONG state[4];
	//������count[0]�����λ��count[1]�����λ����¼�Ѿ�����ı�����
	ULONG count[2];
	//���뻺������������Ϣ�����ֺ���64�ֽڵ�����
	UCHAR buffer[64];
	//���λ
	UCHAR pad[64];
	char myDigest[129];
	/*
	*********������*********
	*/
	//��չMD5�Ĵ�������
	void Workflow(UCHAR *content, UINT length);
	//�����뻮��Ϊ���ɸ�64�ֽڷ��飬Ȼ�����transform��������MD5����
	void Update(UCHAR *input, UINT inputLen);
	//��һ��512������Ϣ�������MD5����
	void Tranform(ULONG state[4], UCHAR block[64]);
	//����ĩβ���ֵĴ����γ����յ�����ժҪ
	void Final(UCHAR digest[16]);
	//��˫��תΪ�ֽ�
	void Encode(UCHAR *output, ULONG *input, UINT len);
	//���ֽ�תΪ˫��
	void Decode(ULONG *output, UCHAR *input, UINT len);
};
