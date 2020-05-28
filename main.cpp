#include "md5.h"
#include "stdio.h"

int main() {
	MyMD5 md5;
	char result[200] = {'\0'};
	md5.GetFileMd5(result, "test.txt");
	printf("Result:%s", result);
}