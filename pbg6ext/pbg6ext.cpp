// PBG6 Extractor
// --------------
// pbg6ext.cpp - PBG6 extraction functions (= what you're looking for)
// --------------
// "©" Nmlgc, 2011

#include "main.h"

// Helper
// ------
inline ulong EndianSwap(const ulong& x)
{
	return ((x & 0x000000ff) << 24) |
		   ((x & 0x0000ff00) << 8) |
		   ((x & 0x00ff0000) >> 8) |
		   ((x & 0xff000000) >> 24);
}

inline char* memcpy_advance(void* dest, char** src, size_t size)
{
	char* ret = (char*)memcpy(dest, *src, size);
	*src += size;
	return ret;
}
// ------

// Functions
// ---------
void PBG6Archive::InitCryptPools()
{
	for(ulong c = 0; c < CP1_SIZE; c++)	pool1[c] = c;
	for(ulong c = 0; c < CP2_SIZE; c++)	pool2[c] = 1;
}

bool PBG6Archive::SigCheck()
{
	static const char Sig[4] = {'P', 'B', 'G', '6'};
	char Read[4];

	fseek(ac6, 0, SEEK_SET);
	fread(Read, 4, 1, ac6);
	return !memcmp(Sig, Read, 4);
}

char* PBG6Archive::GetTOCFileInfo(PBG6File* dest, char* source)
{
	char* t = source;

	if(*t = '/')	t++;	// Jump over directory slash, THIS IS IMPORTANT!

	dest->fnlen = strlen(t) + 1;
	MultiByteToWideChar(932, MB_COMPOSITE, t, dest->fnlen, dest->fn, 64);	t += dest->fnlen;
	memcpy_advance(&dest->insize, &t, 4);
	memcpy_advance(&dest->outsize, &t, 4);
	memcpy_advance(&dest->pos, &t, 4);
	t += 4;
	return t;
}

bool PBG6Archive::ReadTOC()
{
	if(!ac6)	return false;

	ulong toc_start, toc_size;
	char* toc, *toc_crypt, *t;
		
	fseek(ac6, 0, SEEK_END);
	ulong toc_insize = ftell(ac6);
	fseek(ac6, 4, SEEK_SET);
	fread(&toc_start, sizeof(ulong), 1, ac6);
	fread(&toc_size, sizeof(ulong), 1, ac6);
	
	if(fseek(ac6, toc_start, SEEK_SET))
	{
		printf("ERROR: archive ToC out of range\n");
		return false;
	}

	// Read ToC
	// --------
	printf("Reading and decrypting archive ToC...\n");

	toc_insize -= toc_start;

	toc_crypt = (char*)malloc(toc_insize);
	toc = (char*)malloc(toc_size);

	fread(toc_crypt, toc_insize, 1, ac6);
	Decrypt(toc, toc_size, toc_crypt, toc_insize);

	memcpy(&filecount, toc, 4);
	t = toc + 4;

	file = (PBG6File*)calloc(filecount, sizeof(PBG6File));
	for(ulong c = 0; c < filecount; c++)	t = GetTOCFileInfo(&file[c], t);

	SAFE_DELETE(toc);

	return true;
}

void PBG6Archive::CryptStep(ulong& ecx)
{
	static const ulong cmp = (CP1_SIZE - 1);

	pool2[ecx]++;
	ecx++;
	while(ecx <= cmp)
	{
		pool1[ecx]++;
		ecx++;
	}

	if(pool1[cmp] < 0x10000)	return;

	pool1[0] = 0;

	for(ushort c = 0; c < cmp; c++)
	{
		pool2[c] = (pool2[c] | 2) >> 1;
		pool1[c + 1] = pool1[c] + pool2[c];
	}

	return;
}


bool PBG6Archive::Decrypt(char* dest, const ulong& destsize, const char* source, const ulong& sourcesize)
{
	ulong ebx = 0, ecx, edi, esi, edx;
	ulong cryptval[2];
	ulong s = 4, d = 0;	// source and destination bytes

	InitCryptPools();
	
	edi = EndianSwap(*(ulong*)source);
	esi = 0xFFFFFFFF;
	
	while(1)
	{
		edx = 0x100;

		cryptval[0] = esi / pool1[0x101];
		cryptval[1] = (edi - ebx) / cryptval[0];

		ecx = 0x80;
		esi = 0;

		while(1)
		{
			while( (ecx != 0x100) && (pool1[ecx] > cryptval[1]))
			{
				ecx--;
				edx = ecx;
				ecx = (esi+ecx) >> 1;
			}

			if(cryptval[1] < pool1[ecx+1])	break;

			esi = ecx+1;
			ecx = (esi+edx) >> 1;
		}

		*(dest + d) = (char)ecx;	// Write!
		if(++d >= destsize)	return true;

		esi = (long)pool2[ecx] * (long)cryptval[0];	// IMUL

		ebx += pool1[ecx] * cryptval[0];
		CryptStep(ecx);

		ecx = (ebx + esi) ^ ebx;

		while(!(ecx & 0xFF000000))
		{
			ebx <<= 8;
			esi <<= 8;
			edi <<= 8;

			ecx = (ebx+esi) ^ ebx;

			edi += *(source + s) & 0x000000FF;
			s++;
			// if(++s >= sourcesize)	return true;
		}
		
		while(esi < 0x10000)
		{
			esi = 0x10000 - (ebx & 0x0000FFFF);

			ebx <<= 8;
			esi <<= 8;
			edi <<= 8;

			edi += *(source + s) & 0x000000FF;
			s++;
			// if(++s >= sourcesize)	return true;
		}
	}
}

void PBG6Archive::Cleanup()
{
	if(ac6)	fclose(ac6);
	ac6 = NULL;
	SAFE_DELETE(file);
}
// ---------
