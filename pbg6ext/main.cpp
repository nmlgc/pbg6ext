// PBG6 Extractor
// --------------
// main.cpp - user frontend (= uninteresting)
// --------------
// "©" Nmlgc, 2011

// Includes
// --------
#include <malloc.h>
#include <wchar.h>

#ifdef WIN32
#define chdir(x) (SetCurrentDirectory((x)) != 0)
#define mkdir(x) (CreateDirectory((x), NULL) != 0)

#define DirSlash '\\'
#define SlashString "\\"
#define OtherDirSlash '/'
#define OtherSlashString "/"
#else
#include <direct.h>

#define DirSlash '/'
#define SlashString "/"
#define OtherDirSlash '\\'
#define OtherSlashString "\\"
#endif

#include "main.h"
// --------

// Helper
// ------
// Corrects a filename to be in the current platform's format (Slash Correction)
void CorrectFilename(char* FN)
{
	ushort Length = strlen(FN);
	for(ushort Pos = 0; Pos < Length; Pos++)
	{
		if(FN[Pos] == OtherDirSlash)	FN[Pos] = DirSlash;
	}
}

// Just ensures that a directory name ends with a slash
void CorrectPath(char* Path)
{
	CorrectFilename(Path);
	ushort Length = strlen(Path);
	if(!(Path[Length - 1] == DirSlash))	strcat(Path, SlashString);
	return;
}
// ------

PBG6Archive pbg6;

bool Cleanup()
{
	pbg6.Cleanup();
	printf("\n");
	return 0;
}

int main(int argc, char* argv[])
{
	printf("--------------\n"
		   "PBG6 Extractor\n"
	       "--------------\n\n");

	if(argc < 2)
	{
		printf("Usage: pbg6ext [archive] <target directory, created if not existing (optional)>\n");
		return 0;
	}

	if(!(pbg6.ac6 = fopen(argv[1], "rb")))
	{
		printf("ERROR: Couldn't open %s.\n", argv[1]);
		return 0;
	}

	if(!pbg6.SigCheck())
	{
		printf("ERROR: %s is no valid PBG6 archive.\n", argv[1]);
		return Cleanup();
	}

	if(argc >= 3)
	{
		char extdir[256];
		strcpy(extdir, argv[2]);
		CorrectPath(extdir);

		if(!chdir(extdir))
		{
			int ret = mkdir(extdir);
			if(!ret && GetLastError() != 2)	printf("WARNING: Couldn't change directory to %s. Unpacking in current directory.\n", extdir);
			else							chdir(extdir);
		}
	}

	// -----
	if(!pbg6.ReadTOC())	return Cleanup();

	// Decrypting
	// ----------
	PBG6File* file;
	char* enc = NULL, *dec = NULL;
	FILE* out;

	for(ulong c = 0; c < pbg6.filecount; c++)
	{
		file = &pbg6.file[c];

		printf("[%2d/%2d] %S", c+1, pbg6.filecount, file->fn);	// Split command because Windows eats the remaining format string if a wide string can't be displayed
		printf(" (%d bytes -> %d bytes)\n", file->insize, file->outsize);

		if(!(out = _wfopen(file->fn, L"wb")))
		{
			printf("--> ERROR: Couldn't open file to write. Skipping...\n");
		}
		else
		{
			enc = (char*)malloc(file->insize);
			dec = (char*)malloc(file->outsize);

			fseek(pbg6.ac6, file->pos, SEEK_SET);
			fread(enc, file->insize, 1, pbg6.ac6);
			pbg6.Decrypt(dec, file->outsize, enc, file->insize);

			fwrite(dec, file->outsize, 1, out);
			fclose(out);

			SAFE_DELETE(enc);
			SAFE_DELETE(dec);
		}
	}
	// ----------

	return Cleanup();
}
