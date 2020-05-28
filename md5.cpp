
#include "md5.h"
#include <stdio.h>
#include "malloc.h"
#include "string.h"
#include <stdlib.h>

//Sij��ʾ��i�ֵ�j������ѭ�����Ƶ�λ��
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

//MD5���ĸ���������
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

//��xѭ������nλ
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

//�����ĸ������������������
#define FF(a, b, c, d, x, s, ac) { \
	(a) += F ((b), (c), (d)) + (x) + (unsigned long int)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
	}
#define GG(a, b, c, d, x, s, ac) { \
	(a) += G ((b), (c), (d)) + (x) + (unsigned long int)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
	}
#define HH(a, b, c, d, x, s, ac) { \
	(a) += H ((b), (c), (d)) + (x) + (unsigned long int)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
	}
#define II(a, b, c, d, x, s, ac) { \
	(a) += I ((b), (c), (d)) + (x) + (unsigned long int)(ac); \
	(a) = ROTATE_LEFT ((a), (s)); \
	(a) += (b); \
	}


/* MD5 initialization. Begins an MD5 operation, writing a new context.
*/

MyMD5::MyMD5()
{
	Init();
}

MyMD5::~MyMD5()
{
}
//��ʼ�����������λ
void MyMD5::Init()
{
	this->count[0] = this->count[1] = 0;
	//�����ĸ���ʼ����
	this->state[0] = 0x67452301;
	this->state[1] = 0xefcdab89;
	this->state[2] = 0x98badcfe;
	this->state[3] = 0x10325476;
	//�������λ����һλΪ1������Ϊ0
	memset(pad, 0, sizeof(pad));
	*pad = 0x80;
}

#define UPDATE_MD5_LEN 16 //ժҪ����Ϊ128λ����16�ֽ�
bool MyMD5::GetFileMd5(char *pMd5, const char *pFileName)
{
	//���ļ�
	FILE * pFile = fopen(pFileName, "rb");
	if (pFile == NULL)
	{
		return false;
	}
	//��λ���ļ�ĩλ
	fseek(pFile, 0, SEEK_END);
	//��ȡ�ļ�ƫ��λ��
	int length = ftell(pFile);
	//�ҵ��ļ���ͷ
	fseek(pFile, 0, SEEK_SET);
	//�����ļ���С����ռ�
	unsigned char *pInPut = (unsigned char *)malloc(length);
	//��ȡ�ļ�����
	fread(pInPut, 1, length, pFile);
	//�����ֶβ�ֲ�����MD5ֵ
	Update(pInPut, length);

	unsigned char chDigest[UPDATE_MD5_LEN] = { 0 };
	//����ĩβ���ֵĴ�������
	Final(chDigest);
	/*if (pInPut)
	{
		free(pInPut);
	}*/
	fclose(pFile);
	//���ֽ�ת��Ϊ16������
	char szmd5[UPDATE_MD5_LEN * 2 + 1] = { 0 };
	char szmd5buf[3] = { 0 };
	for (int i = 0; i < UPDATE_MD5_LEN; i++)
	{
		//������ת��Ϊ�ַ���
		itoa(chDigest[i], szmd5buf, 16);
		if (0 == szmd5buf[1])
		{
			strcat(szmd5, "0");
			strcat(szmd5, szmd5buf);
		}
		else
		{
			strcat(szmd5, szmd5buf);
		}
	}
	strcpy(pMd5, szmd5);
	return true;
}

//�����뻮��Ϊ���ɸ�64�ֽڷ��飬Ȼ�����transform��������MD5����
void MyMD5::Update(unsigned char *input, unsigned int inputLen)
{
	unsigned int i, index, partLen;

	//����buffer�Ѿ���ŵ��ֽ���
	index = (unsigned int)((this->count[0] >> 3) & 0x3F);//��ȡ����λ

	//���¼�����count
	if ((this->count[0] += ((unsigned long int)inputLen << 3))
		< ((unsigned long int)inputLen << 3))
		this->count[1]++;//��λ���֣�������λ
	//��λ����ֱ�Ӽ�
	this->count[1] += ((unsigned long int)inputLen >> 29);

	//���buffer��ʣ��ĳ���
	partLen = 64 - index;

	//�����ݿ�������MD5����
	if (inputLen >= partLen) {
		//��һ��Ҫ����buffer
		memcpy((unsigned char*)&this->buffer[index],
			(unsigned char*)input, partLen);
		Tranform(this->state, this->buffer);
		//����ÿ��64�ֽ�
		for (i = partLen; i + 63 < inputLen; i += 64)
			Tranform(this->state, &input[i]);
		//��ʱbuffer��û�б�����
		index = 0;
	}
	else {//���޷�����buffer����ֱ������
		i = 0;
	}

	//������64�ֽڵ����ݸ��Ƶ�buffer��
	memcpy((unsigned char*)&this->buffer[index], (unsigned char*)&input[i], inputLen - i);
}

//����ĩβ���ֵĴ������γ����յ�����ժҪ
void MyMD5::Final(unsigned char digest[16])
{
	unsigned char bits[8];
	unsigned int index, padLen;

	//��˫��ת��Ϊ�ֽڣ���¼֮ǰ�ĳ���
	Encode(bits, this->count, 8);

	//��ȡ���ڵĳ�������
	index = (unsigned int)((this->count[0] >> 3) & 0x3f);
	//����Ϣ�����һλ1������λ0��120=56+64
	padLen = (index < 56) ? (56 - index) : (120 - index);
	//�������λ����MD5����
	Update(pad, padLen);

	//�������һ��8�ֽڱ�ʾ�����ǰ����Ϣ����
	Update(bits, 8);
	//���ֽ�תΪ˫�֣���¼��digest��
	Encode(digest, this->state, 16);

	//��������Ϣ���㣬���⹥��
	//memset((unsigned char*)this, 0, sizeof(*this));
	//this->Init();
}

//��һ��512������Ϣ�������MD5����
void MyMD5::Tranform(unsigned long int state[4], unsigned char block[64])
{
	//��ABCD����ʼֵ
	unsigned long int a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	//��˫��תΪ�ֽ�
	Decode(x, block, 64);

	//��һ��
	FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
	FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
	FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
	FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
	FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
	FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
	FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
	FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
	FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
	FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
	FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	//�ڶ���
	GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
	GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
	GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
	GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
	GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
	GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
	GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
	GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
	GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
	GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
	GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
	GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	//������
	HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
	HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
	HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
	HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
	HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
	HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
	HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
	HH(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
	HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
	HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */

	//������
	II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
	II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
	II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
	II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
	II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
	II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
	II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
	II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
	II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
	II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */

	//��������ʼ�����ۼӺ����¸�ֵ����ʼ����
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	//��x����
	memset((unsigned char*)x, 0, sizeof(x));
}

//��˫��תΪ�ֽ�
void MyMD5::Encode(unsigned char *output, unsigned long int *input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (unsigned char)(input[i] & 0xff);
		output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
		output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
		output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
	}
}

//���ֽ�תΪ˫��
void MyMD5::Decode(unsigned long int *output, unsigned char *input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[i] = ((unsigned long int)input[j]) | (((unsigned long int)input[j + 1]) << 8) |
			(((unsigned long int)input[j + 2]) << 16) | (((unsigned long int)input[j + 3]) << 24);
	}

}