#include "md5.h"
#include "stdio.h"

int main() {
	MyMD5 md5;
	char result[129] = {'\0'};
	md5.ReadFile("test.txt");
	md5.getDigest(result);
	printf("Result:%s", result);
}