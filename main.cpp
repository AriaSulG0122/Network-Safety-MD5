#include "md5.h"

void ReadHelp();

int main() 
{
	MyMD5 md5;
	char result[129] = {'\0'};
	char input[300] = {'\0'};
	
	ReadHelp();//读取帮助文件
	
	bool goodInput=false;
	while(!goodInput){
		printf("Please choose a way to read content,F(file) or I(input):");
		scanf("%s", input);
		//input[0] = 'I';
		switch (*input) {
			case 'F': 
			{
				char filename[30] = { '\0' };
				printf("\nPlease input the file name:");
				scanf(" %s", filename);
				md5.ReadFile(filename);
				goodInput = true;
				break;
			}
			case 'I':
			{
				char content[200] = {'\0'};
				printf("\nPlease input the content(End with #):");
				scanf(" %[^#]", &content);
				content[strlen(content)] = '\0';
				md5.ReadInput(content);
				goodInput = true;
				break;
			}
			default:
				printf("Wrong input!Please Input F or I!\n");
		}
	}//end while
	
	
	md5.getDigest(result);
	printf("Digital Digest:%s\n", result);
}

void ReadHelp() {
	FILE * curFile = fopen("help.md", "rb");
	if (curFile == NULL)
	{
		printf("Can't open the help file!");
		return;
	}
	//定位至文件末位
	fseek(curFile, 0, SEEK_END);
	//获取文件偏移位置
	int length = ftell(curFile);
	//找到文件开头
	fseek(curFile, 0, SEEK_SET);
	//根据文件大小分配空间
	UCHAR *fileContent = (UCHAR *)malloc(length+1);
	fileContent[length] = '\0';
	//读取文件内容
	fread(fileContent, 1, length, curFile);
	printf("%s\n", fileContent);
	//关闭文件
	fclose(curFile);
}