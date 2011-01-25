// PBG6 Extractor
// --------------
// main.h - the obligatory project header file (= somewhat interesting)
// --------------
// "©" Nmlgc, 2011

typedef unsigned long ulong;
typedef unsigned short ushort;
typedef unsigned char uchar;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <windows.h>
#endif

// Constants
// ---------
const ulong CP1_SIZE = 0x102;
const ulong CP2_SIZE = 0x400;
// ---------

// Helper
// ------
#define SAFE_DELETE(x)      	if((x))	{free((x)); (x) = NULL;}
// ------

// Structures
// ----------
// A single, compressed file inside the archive
struct PBG6File
{
	wchar_t	fn[64];		// Filename
	size_t	fnlen;		// Filename length (not actually needed anywhere)	

	ulong	pos;		// Position inside the archive
	ulong	insize;		// Encrypted file size
	ulong	outsize;	// Decrypted file size
};


// Function class
class PBG6Archive
{
protected:
	// Variables
	// ---------
	ulong pool1[CP1_SIZE];
	ulong pool2[CP2_SIZE];
	// ---------

	void InitCryptPools();
	void CryptStep(ulong& ecx);

public:
	FILE* ac6;
	ulong filecount;

	PBG6File* file;

	PBG6Archive()	{ac6 = NULL;}

	bool SigCheck();

	bool Decrypt(char* dest, const ulong& destsize, const char* source, const ulong& sourcesize);	// decrypts [source] buffer

	bool ReadTOC();
	char* GetTOCFileInfo(PBG6File* dest, char* source);	// returns pointer to next file

	void Cleanup();
};
// ----------