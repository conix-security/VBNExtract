// Copyright 2013 Conix Security, Adrien Chevalier
// adrien.chevalier@conix.fr
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define false 0
#define true 1
#define MAX_PATH 260

/**
	VBN files contain a header displaying several information (filename, machine, username, etc.) folowed by 'Z' xored data. Once "unxored", another header is present.
	The 0x0900100000 magic flag indicates 0xFF xored data (0x1000 bytes chunks separated by 5 bytes structs). The old quarantine files only use the 1st layer (xor 'Z').

	This program dumps the header informations, and offers 2 extraction modes :
	- v2 (default) : full extraction (locates and dumps the 0xFF xored data)
	- v1 : old extraction (locates and dumps the 'Z' xored data)
*/

int main(int argc, char** argv)
{
	FILE *f, *fout;
	char *output = NULL;
	char *data = NULL;
	int cpt,cpt2,write2;
	unsigned long offset;
	char buf;
	char buf2[5]={0};
	int mode = 1;
	int i = 0;

	if(argc<2)
	{
		printf("Usage : %s file.VBN [-o output] [-1]\n"
			"\toutput : output file for extraction (if not set, will just display the quarantine intel).\n"
			"\t1 (Version 1) : use \"old\" extraction method (works with several old quarantine files)\n",argv[0]);
		return 0;
	}
	for(i = 2; i<argc; i++)
	{
		if(argv[i][0]=='-')
			switch(argv[i][1])
			{
				case 'o':
					if(i+1 == argc)
					{
						printf(" [!] Error : invalid output argument.\n");
						return -1;
					}
					i++;
					output = argv[i];
				break;
				case '1':
					mode = 2;
				break;
			}
	}

	if(output == NULL)
		mode = 0;

	f=fopen(argv[1],"rb");
	if(f==NULL)
	{
		printf(" [!] Error : cannot open %s\n",argv[1]);
		return -1;
	}


	fread(&offset,4,1,f);

	cpt=0;
	cpt2=0;
	data = (char*)malloc((MAX_PATH+1)*sizeof(char));
	memset(data,0,(MAX_PATH+1)*sizeof(char));
	while(fread(&buf,1,1,f)!=0 && cpt2<=MAX_PATH)
	{
		if(buf != 0x00)
			data[cpt2]=buf;
		cpt2++;
	}
	printf(" [-] Original filename : %s\n",data);
	memset(data,0,(MAX_PATH+1)*sizeof(char));
	fseek(f,0x184,0);
	cpt=0;
	cpt2=0;
	while(fread(&buf,1,1,f)!=0 && cpt<=6)
	{
		if(buf == ',')
		{
			cpt++;
			if(cpt >= 5 && cpt <= 7)
			{
				switch(cpt)
				{
					case 5:
						printf(" [-] Original computer : %s\n",data);
						break;
					case 6:
						printf(" [-] Username : %s\n",data);
						break;
					case 7:
						printf(" [-] Signature : %s\n",data);
						break;
					default:
						break;
				}
				memset(data,0,(MAX_PATH+1)*sizeof(char));
				cpt2=0;
			}
		}
		else
			if((cpt >= 4 && cpt <= 6) && cpt2 < MAX_PATH)
			{
				data[cpt2]=buf;
				cpt2++;
			}
	}
	free(data);

	if(mode != 0)
	{
		fout = NULL;
		if(mode == 2)
		{
			fout = fopen(output,"wb");
			if(fout==NULL)
			{
				printf(" [!] Error : cannot open %s\n",output);
				return -1;
			}
		}

		write2 = false;
		cpt = 0;	
		cpt2 = 0;

		fseek(f,offset,SEEK_SET);

		while(fread(&buf,1,1,f))
		{
			buf = buf^'Z';
			if(mode == 2)
				fwrite(&buf,1,1,fout);
		
			if(write2==true)
			{
				if(cpt == 0x1000)
				{
					if(cpt2==4)
					{
						cpt2=0;
						cpt=0;
					}
					else
						cpt2++;
				}
				else
				{
					buf = buf ^ 0xFF;
					fwrite(&buf,1,1,fout);
					cpt++;
				}
			}
			else if(mode==1)
			{
				buf2[0]=buf2[1];
				buf2[1]=buf2[2];
				buf2[2]=buf2[3];
				buf2[3]=buf2[4];
				buf2[4]=buf;
				if(buf2[0]==0x09 && buf2[1]==0x00 && buf2[2]==0x10 && buf2[3]==0x00 && buf2[4]==0x00)
				{
					write2=true;
					fout = fopen(output,"wb");
					if(fout==NULL)
					{
						printf(" [!] Error : cannot open %s\n",output);
						return -1;
					}
				}
			}
		}

		if(fout != NULL)
			fclose(fout);
		else
		{
			printf(" [!] Error : could not extract the file. Make sure the VBN file is not the quarantine header one.\n");
			return -1;
		}
		printf(" [-] File %s extracted successfully !\n",output);
	}

	fclose(f);

	printf(" [-] FINISHED !\n");
	return 0;

}
