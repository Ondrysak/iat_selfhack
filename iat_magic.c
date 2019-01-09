#include <stdio.h>
#include <stdlib.h>
#include <windows.h>



#define LIB_NAME "api-ms-win-crt-heap-l1-1-0.dll"
#define LOG_COUNT 50 

void* (*basicMalloc) (size_t);
void(*basicFree) (void*);
void* (*basicCalloc) (size_t, size_t);
void* (*basicRealloc) (void*, size_t);

//there were some mentions of printf and similar functions using malloc etc. in MI-REV tutorials
//to avoid using those to pass information we set some variables to indicate failures
int invalidFree = 0;
int allocLogsFull = 0;


struct allocation_log {
	void *  ptr;
	size_t alloc_size;
	int freed;
	int used;
} alloc_logs[LOG_COUNT];

/*
Some snippets in this code are taken from here.

http://win32assembly.programminghorizon.com/files/pe1.zip

Huge thx to LUEVELSMEYER for making this available.

*/



DWORD dwOldProtect;
/*
ICZELION
#define adr(rva) ((const void*)((char*)section_base+((DWORD)(rva))-section_rva))
*/
#define adr(section_base,rva) ((const void*)(((char*)(section_base)) +(DWORD) (rva)))


void * MallocDebug_malloc(size_t size) {
	int i = 0;
	while (1) {
		if (i == LOG_COUNT) {
			allocLogsFull = 1;
			break;
		}
		if (!alloc_logs[i].used) {
			break;
		}
		i++;
	}

	void* ptr = basicMalloc(size);
	if (!allocLogsFull) {
		alloc_logs[i].ptr = ptr;
		alloc_logs[i].alloc_size = size;
		alloc_logs[i].freed = 0;
		alloc_logs[i].used = 1;
	}

	return ptr;
}

void * MallocDebug_calloc(size_t num, size_t size) {
	int i = 0;
	while (1) {
		if (i == LOG_COUNT) {
			allocLogsFull = 1;
			break;
		}
		if (!alloc_logs[i].used) {
			break;
		}
		i++;
	}
	void* ptr = basicCalloc(num, size);


	if (!allocLogsFull) {
		alloc_logs[i].ptr = ptr;
		alloc_logs[i].alloc_size = size*num;
		alloc_logs[i].freed = 0;
		alloc_logs[i].used = 1;
	}
	return ptr;
}

void * MallocDebug_realloc(void *  old_ptr, size_t size) {
	void* ptr;
	int i = 0;
	if (old_ptr == NULL && size == 0) {
	//well we are not actually doing anything here 
	ptr = basicRealloc(old_ptr, size);
	}
	else if (old_ptr == NULL) {
	//allocation nonzero sized chunk
		while (1) {
			if (i == LOG_COUNT) {
				//no records in allocLogs left
				allocLogsFull = 1;
				break;
			}
			if (!alloc_logs[i].used) {
				break;
			}
			i++;

		}
		ptr = basicRealloc(old_ptr, size);
		if (!allocLogsFull) {
			alloc_logs[i].ptr = ptr;
			alloc_logs[i].alloc_size = size;
			alloc_logs[i].freed = 0;
			alloc_logs[i].used = 1;
		}

	}
	else if (size == 0) {
	//freeing a nonnull pointer
		while (1) {

			if (i == LOG_COUNT) {
				//freeing memory that was not allocated
				invalidFree = 1;
				break;
			}
			if (alloc_logs[i].ptr == old_ptr && !alloc_logs[i].freed) {
				break;
			}

			i++;

		}
		ptr = basicRealloc(old_ptr, size);
		if (!invalidFree) {
			alloc_logs[i].freed = 1;
		}
	
	}
	else {
	//realloc as normies percieve it, nonnull pointer nonzero size
		while (1) {

			if (i == LOG_COUNT) {
				//freeing memory that was not allocated
				invalidFree = 1;
				break;
			}
			if (alloc_logs[i].ptr == old_ptr && !alloc_logs[i].freed) {
				break;
			}
			i++;

		}
		ptr = basicRealloc(old_ptr, size);

		if (!invalidFree) {
			alloc_logs[i].ptr = ptr;
			alloc_logs[i].alloc_size = size;
			alloc_logs[i].freed = 0;
		}
	
	}

	return ptr;
}

void MallocDebug_free(void* ptr) {
	int i = 0;
	while (1) {
		if (ptr == NULL) {
			break;
		}
		if (i == LOG_COUNT) {
			invalidFree = 1;
			break;
		}
		if (alloc_logs[i].ptr == ptr && !alloc_logs[i].freed) {
			break;
		}
		i++;
	}

	basicFree(ptr);
	if (ptr != NULL || !invalidFree)
		alloc_logs[i].freed = 1;
}


void MallocDebug_Init() {
	printf("MallocDebug_Init() started!\n");


	for (int i = 0; i < LOG_COUNT; i++) {
		alloc_logs[i].ptr = NULL;
		alloc_logs[i].alloc_size = 0;
		alloc_logs[i].freed = 0;
		alloc_logs[i].used = 0;
	}

	HMODULE section_base = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)section_base;
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)adr(section_base, pDosHeader->e_lfanew);

	IMAGE_DATA_DIRECTORY import_table = pNTHeaders->OptionalHeader.DataDirectory[1];
	IMAGE_DATA_DIRECTORY import_adress_table = pNTHeaders->OptionalHeader.DataDirectory[13];


	size_t imageDataDirectorySize = (size_t)pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;


	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)adr(section_base, pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptorEnd = \
		(PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pImportDescriptor) + imageDataDirectorySize);
	if (pImportDescriptor == pImportDescriptorEnd) {
		printf("seems like there are not dll's lets end this before something bad happens!\n");
			return;
	}
	// set to 4 to enable readwrite	
	VirtualProtect((void*)pImportDescriptor, \
		(size_t)pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size, \
		4, &dwOldProtect);

	char * dllName;
	IMAGE_THUNK_DATA * import_left;
	IMAGE_THUNK_DATA * import_right;
	int k = 1;
	while (1) {
		if ((void*)((pImportDescriptor)->Characteristics) == NULL) {
			break;
		}
		dllName = (char*)adr(section_base, pImportDescriptor->Name);
		if (strcmp(dllName, LIB_NAME) != 0) {
			pImportDescriptor++;
			if (pImportDescriptor == pImportDescriptorEnd) {
				break;
			}
			continue;
		}
		printf("Replacing FirstThunks of free, malloc, calloc and realloc in %s!\n", dllName);
		import_left = (IMAGE_THUNK_DATA *)adr(section_base, pImportDescriptor->OriginalFirstThunk);
		import_right = (IMAGE_THUNK_DATA *)adr(section_base, pImportDescriptor->FirstThunk);



		while (import_left->u1.Ordinal)
		{
			if (IMAGE_SNAP_BY_ORDINAL(import_left->u1.Ordinal))
				//nameless function - ICZELION mentioned this, probably not of any use here
				printf("%6lu <ordinal>\n", IMAGE_ORDINAL(import_left->u1.Ordinal));
			else
			{
				const IMAGE_IMPORT_BY_NAME *name_import = adr(section_base, import_left->u1.AddressOfData);
				void** firstThunkPtr = (void**)import_right;

				if (strcmp(name_import->Name, "malloc") == 0) {
					printf("Replacing FirstThunk of malloc!\n");
					basicMalloc = *firstThunkPtr;
					*firstThunkPtr = (void*)&MallocDebug_malloc;
				}

				if (strcmp(name_import->Name, "free") == 0) {
					printf("Replacing FirstThunk of free!\n");
					basicFree = *firstThunkPtr;
					*firstThunkPtr = (void*)&MallocDebug_free;
				}

				if (strcmp(name_import->Name, "calloc") == 0) {
					printf("Replacing FirstThunk of calloc!\n");
					basicCalloc = *firstThunkPtr;
					*firstThunkPtr = (void*)&MallocDebug_calloc;
				}

				if (strcmp(name_import->Name, "realloc") == 0) {
					printf("Replacing FirstThunk of realloc!\n");
					basicRealloc = *firstThunkPtr;
					*firstThunkPtr = (void*)&MallocDebug_realloc;
				}
			}

			import_left++;
			import_right++;
		}
		pImportDescriptor++;
		if (pImportDescriptor == pImportDescriptorEnd) {
			break;
		}

	}
	// set to previous value to disable readwrite
	DWORD dwOldProtect2;
	VirtualProtect((void*)pImportDescriptor, \
		(size_t)pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size, \
		dwOldProtect, &dwOldProtect2);
}

void MallocDebug_Done() {


	HMODULE section_base = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)section_base;
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)adr(section_base, pDosHeader->e_lfanew);

	IMAGE_DATA_DIRECTORY import_table = pNTHeaders->OptionalHeader.DataDirectory[1];
	IMAGE_DATA_DIRECTORY import_adress_table = pNTHeaders->OptionalHeader.DataDirectory[13];

	size_t imageDataDirectorySize = (size_t)pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)adr(section_base, pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptorEnd = \
		(PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pImportDescriptor) + imageDataDirectorySize);
	if (pImportDescriptor == pImportDescriptorEnd) {
		printf("seems like there are not dll's lets end this before something bad happens!\n");
		return;
	}



	//4 means readwrite, enabling readwrite on IAT
	VirtualProtect((void*)pImportDescriptor, \
		(size_t)pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size, \
		4, &dwOldProtect);
	char * dllName;
	IMAGE_THUNK_DATA *import_left;
	IMAGE_THUNK_DATA *import_right;
	while (1) {
		
		if ((void*)((pImportDescriptor)->Characteristics) == NULL) {
			break;
		}
		dllName = (char*)adr(section_base, pImportDescriptor->Name);
		if (strcmp(dllName, LIB_NAME) != 0) {
			pImportDescriptor++;
			if (pImportDescriptor == pImportDescriptorEnd) {
				break;
			}
			continue;
		}
		printf("Restoring FirstThunks of free, malloc, calloc and realloc in %s!\n", dllName);


		import_left = (IMAGE_THUNK_DATA *)adr(section_base, pImportDescriptor->OriginalFirstThunk);
		import_right = (IMAGE_THUNK_DATA *)adr(section_base, pImportDescriptor->FirstThunk);



		while (import_left->u1.Ordinal)
		{
			if (IMAGE_SNAP_BY_ORDINAL(import_left->u1.Ordinal))
				//nameless function - ICZELION mentioned this, probably not of any use here
				printf("%6lu <ordinal>\n", IMAGE_ORDINAL(import_left->u1.Ordinal));
			else
			{
				const IMAGE_IMPORT_BY_NAME *name_import = adr(section_base, import_left->u1.AddressOfData);
				void** firstThunkPtr = (void**)import_right;

				if (strcmp(name_import->Name, "malloc") == 0) {
					printf("Restoring FirstThunk of malloc!\n");
					*firstThunkPtr = (void*)basicMalloc;
				}

				if (strcmp(name_import->Name, "free") == 0) {
					printf("Restoring FirstThunk of free!\n");
					*firstThunkPtr = (void*)basicFree;
				}

				if (strcmp(name_import->Name, "calloc") == 0) {
					printf("Restoring FirstThunk of calloc!\n");
					*firstThunkPtr = (void*)basicCalloc;
				}

				if (strcmp(name_import->Name, "realloc") == 0) {
					printf("Restoring FirstThunk of realloc!\n");
					*firstThunkPtr = (void*)basicRealloc;
				}
			}
			import_left++;
			import_right++;
		}
		pImportDescriptor++;
		if (pImportDescriptor == pImportDescriptorEnd) {
			break;
		}
	}

	// set to previous value to disable readwrite
	DWORD dwOldProtect2;
	VirtualProtect((void*)pImportDescriptor, \
		(size_t)pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size, \
		dwOldProtect, &dwOldProtect2);

	for (int i = 0; i < LOG_COUNT; i++) {
		if (alloc_logs[i].used && !alloc_logs[i].freed) {
			printf("Seems like there is a leak of size %d at 0x%x!\n", alloc_logs[i].alloc_size, (unsigned int)alloc_logs[i].ptr);
		}
	}
	if (invalidFree) {
		printf("There were some attempts to free memory that was not allocated!\n");
	}
	if (allocLogsFull) {
		printf("More than %d allocations were done! Please increase the constant LOG_COUNT to log more allocations!\n", LOG_COUNT);
	}

	printf("MallocDebug_Done() finished!\n");

}

int main(int argc, char ** argv) {
	int *pointerino;
	int *pointerino_2;
	int *pointerino_3;

	MallocDebug_Init();


	pointerino = (int *)malloc(sizeof(int));
	pointerino = (int *)realloc(pointerino, 0);
	pointerino_2 = (int *)calloc(5, sizeof(int));
	*pointerino_2 = 0x0badc0de;
	printf("%x!\n", *pointerino_2);
	pointerino = (int *)realloc(pointerino, 303 * sizeof(int));
	pointerino_2 = (int *)malloc(sizeof(int) * 105);
	*pointerino = 0xdeadbeef;
	printf("%x!\n", *pointerino);

	pointerino_3 = realloc(NULL, 23 * sizeof(int));

	free(NULL);
	MallocDebug_Done();

	printf("Malloc debug finished!\n");



	pointerino = (int *)malloc(sizeof(int));

	if (pointerino == 0)
	{
		printf("ERROR: Out of memory\n");
		return 1;
	}

	*pointerino = 0xdeadbeef;

	printf("%x!\n", *pointerino);


	//free(pointerino);
	printf("No animals were harmed during the making of this masterpiece, only humans!");

	return 0;
}
