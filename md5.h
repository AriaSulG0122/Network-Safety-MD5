#pragma once

/* MD5 Class. */
class MyMD5 {
public:
	MyMD5();
	~MyMD5();
	bool GetFileMd5(char *pMd5, const char *pFileName);
private:
	/*
	*********������*********
	*/
	//�ĸ���ʼ����
	unsigned long int state[4];
	//������count[0]�����λ��count[1]�����λ����¼�Ѿ�����ı�����
	unsigned long int count[2];
	//���뻺������������Ϣ�����ֺ���64�ֽڵ�����
	unsigned char buffer[64];
	//���λ
	unsigned char pad[64];

	/*
	*********������*********
	*/
	//��ʼ�����������λ
	void Init();
	//�����뻮��Ϊ���ɸ�64�ֽڷ��飬Ȼ�����transform��������MD5����
	void Update(unsigned char *input, unsigned int inputLen);
	//��һ��512������Ϣ�������MD5����
	void Tranform(unsigned long int state[4], unsigned char block[64]);
	//����ĩβ���ֵĴ����γ����յ�����ժҪ
	void Final(unsigned char digest[16]);
	//��˫��תΪ�ֽ�
	void Encode(unsigned char *output, unsigned long int *input, unsigned int len);
	//���ֽ�תΪ˫��
	void Decode(unsigned long int *output, unsigned char *input, unsigned int len);
};
