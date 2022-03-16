#include "pin.H"
#include "uthash.h"
#include <map>
#include <vector>
#include <stdio.h>
#include <iostream>
#define MAIN "main"
#define FILENO "fileno"


// Taint the memory if the source of input is stdin
#define FGETS "fgets"
#define GETS "gets"

// Propagate if the src is tainted
#define STRCPY "strcpy@plt"
#define STRNCPY "strncpy@plt"
#define STRCAT "strcat@plt"
#define STRNCAT "strncat@plt"
#define MEMCPY "memcpy@plt"

// Reset tainted memory
#define BZERO "bzero@plt"
#define MEMSET "memset@plt"

using namespace std;

typedef int ( *FP_FILENO )(FILE*);
FP_FILENO org_fileno;
int countr = 0;
int isFalsePositive = 0;

using std::vector; using std::string;
struct taint_struct {                 /* key */
    char *byte;
	int taint;
	char *history;
	std::vector<void *> trace;
    UT_hash_handle hh;         /* makes this structure hashable */
};


struct taint_struct *bytes = NULL;    /* important! initialize to NULL */
 
int pu=0;
int po=0;

std::vector<void *> stackTrace;
void* term_addr;
void* main_addr;

void stacktrace_push(void* addr)
{
	term_addr = addr;
	stackTrace.push_back(addr);
}
void stacktrace_pop()
{
	stackTrace.pop_back();
}
void stacktrace_print()
{
	printf("printing... \n");
	printf("trace = ");
	for(unsigned int i=0;i<stackTrace.size();i++)
	{
	    printf("| %p ",stackTrace[i]);
	}
	printf("\n");
}


int find_taints(void *byte) {
    struct taint_struct *st_taint;
    st_taint = (struct taint_struct *)malloc(sizeof(struct taint_struct));
	HASH_FIND_PTR(bytes,&byte,st_taint);

	if(st_taint==NULL)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

void add_tainted_byte(char *byte, int taint, char *history, vector<void* > trace) {
    struct taint_struct *st_taint;
    st_taint = (struct taint_struct *)malloc(sizeof(struct taint_struct));
	HASH_FIND_PTR(bytes,&byte,st_taint);
	if(st_taint==NULL) {
		struct taint_struct *st_taint;
		st_taint = (struct taint_struct *)malloc(sizeof(struct taint_struct));
		st_taint->byte = byte;
		st_taint->taint = taint;
		st_taint->trace = trace;
		if(history!=NULL)
		{
			st_taint->history = history;
		}
		HASH_ADD_PTR( bytes, byte, st_taint );  
	}
	else {
		st_taint->taint = taint;
		st_taint->history = history;
		// st_taint->history.push_back(history);
	}
}

void print_taints() {
    struct taint_struct *st_taint;
    for(st_taint=bytes; st_taint != NULL; st_taint=(struct taint_struct *)(st_taint->hh.next)) {
        printf("-- Byte %p: taint %d mapped to %p ", st_taint->byte, st_taint->taint, st_taint->history);
		for(unsigned int i=0;i<st_taint->trace.size();i++)
		{
			printf(" %p ",st_taint->trace[i]);
		}
		printf("\n");
    }
}

void delete_taint(void *byte) {
	struct taint_struct *st_taint;
    st_taint = (struct taint_struct *)malloc(sizeof(struct taint_struct));
	HASH_FIND_PTR(bytes,&byte,st_taint);

	if(st_taint==NULL)
	{
		// return 0;
	}
	else
	{
		HASH_DEL(bytes, st_taint);  /* user: pointer to deletee */
		free(st_taint);  
	}
}

INT32 Usage()
{
		return -1;
}

bool isStdin(FILE *fd)
{
		int ret = org_fileno(fd);
		if(ret == 0) return true;
		return false;
}

bool fgets_stdin = false;

VOID fgetsTail(char* ret ,void* branch)
{
		if(fgets_stdin) {
			int length = strlen(ret);
			for(int i=0;i<length;i++) {
				add_tainted_byte(ret+i,1,NULL,stackTrace);
			}
			fgets_stdin = false;
		}
}

VOID fgetsHead(void* pot, char* dest, int size, FILE *stream)
{
		if(isStdin(stream)) {
			fgets_stdin = true;
			// no need to mark tainted here
			// for(int i=0;i<size;i++) {
			// 	// add_tainted_byte(dest+i,0,NULL);
			// }
		} 
}

VOID getsTail(char* dest)
{
	int length = strlen(dest);
	for(int i=0;i<length;i++) {
		add_tainted_byte(dest+i,1,NULL,stackTrace);
	}
}

VOID mainHead( int argc, char** argv,void* br)
{	
	main_addr = br;
	stacktrace_push(br);
	for(int i=1; i<argc; i++)
	{
		int argvlen = strlen(argv[i]);
		for(int j=0; j<=argvlen && argv[i]+j !='\0'; j++)
		{
			add_tainted_byte(argv[i]+j,1,NULL,stackTrace);
		}
	}
}

VOID strcpyHead(char* dest, char* src, char* pot)
{
	int length = strlen(src);
	for(int i=0; i<=length;i++) {
		if(find_taints(src+i)==1)
		{
			add_tainted_byte(dest+i,1,src+i,stackTrace);
		}
	}
}

VOID strcatHead(char* dest, char* src)
{
	int length = strlen(src) + strlen(dest);
	for(int i=0;i<=length;i++) {
		if(find_taints(src+i)==1)
		{
			add_tainted_byte(dest+i,1,src+i,stackTrace);
		}
	}
}

VOID strncatHead(char* dest, char* src, int size)
{
	// printf("STRNCAT HEAD \n");
	int length = strlen(dest) + size;
	for(int i=0;i<=length;i++) {
		if(find_taints(src+i)==1)

		{
		add_tainted_byte(dest+i,1,src+i,stackTrace);

		}
	}
}

VOID strcpyTail(char* dest)
{
	// printf("strcypy tail \n");
}

VOID memcpyTail(char* dest, char* src, int size) {
}

VOID memcpyHead(char* dest, char* src, int size)
{
	// printf("MEMCPY HEAD \n");
	unsigned int length = size;
	if (strlen(dest)>length) {
		length = strlen(dest);
	}
	for(unsigned int i=0;i<length;i++) {
		if(find_taints(src+i)==1)
		{
		add_tainted_byte(dest+i,1,src+i,stackTrace);

		}
	}
} 

VOID strncpyHead(char* dest, char* src, int size)
{
	// printf("STRNCPY HEAD %s %s \n",dest,src);
	unsigned int length = size;
	if (length > strlen(src)) {
		length = strlen(src)+1;
	}
	for (unsigned int i=0;i<=length;i++) {
		// if(find_taints(src+i)==1)
		if(find_taints(src+i)==1)
		{
			add_tainted_byte(dest+i,1,src+i,stackTrace);
		}
	}
}

VOID strcatTail(char* dest)
{
	// printf("strcat tail \n");
}

VOID strncatTail(char* dest)
{
	// printf("strn cat tail \n");
}

VOID strncpyTail(char* dest)
{
	// printf("strn cypy tail \n");
}

VOID bzeroHead(char* dest, int n)
{
	// printf("BZERO HEAD \n");
	for(int i=0;i<n;i++)
	{
		delete_taint(dest+i);
	}
}

VOID memsetHead(char* dest, char* src, int size)
{
	// printf("MEMSET HEAD %p,%p,%d\n",dest,src,size);
	// // Check if source is tainted.
	// int isTainted = find_taints(src);
	// printf("istainted = %d\n",isTainted);
	for(int i=0;i<size;i++)
	{
		delete_taint(dest+i);
	}
}

VOID Fini(INT32 code, VOID* v)
{
	// printf("=========================================================================================\n");
	exit(0);
}

// VOID check_false_positives(VOID* branch, VOID* ip, VOID* addr,int stack)
// {
// 	struct taint_struct *taint_st;
// 	taint_st = (struct taint_struct *)malloc(sizeof(struct taint_struct));
// 	HASH_FIND_PTR(bytes,&addr,taint_st);
// 	if(taint_st == NULL)
// 	{
// 		isFalsePositive = 1;
// 		exit(0);
// 	}
// 	void* taint_source = taint_st->history;
// 	if(taint_source!=NULL)
// 	{
// 		check_false_positives(branch,ip,taint_source,stack+1);
// 	}
// }

VOID recursive_check(VOID* branch, VOID* ip, VOID* addr,int stack)
{
	struct taint_struct *taint_st;
	taint_st = (struct taint_struct *)malloc(sizeof(struct taint_struct));
	HASH_FIND_PTR(bytes,&addr,taint_st);
	void* taint_source = taint_st->history;
	int stack_length=taint_st->trace.size();
	printf(" Stack %d: History of Mem(%p): ",stack,addr);
	for( int i=0; i<stack_length;i++)
	{
		printf(" ,%p ",taint_st->trace[i]);
	}
	printf("\n");
	if(taint_source!=NULL)
	{
		recursive_check(branch,ip,taint_source,stack+1);
	}
}

VOID recJump(VOID* branch, VOID* ip, VOID* addr) {

	if(find_taints(addr)==1)
	{
			printf("**************** Attack Detected *******************\n");
			printf(" IndirectBranch(%p): jump to %p, stored in tainted byte(%p) \n",ip,branch,addr);
			recursive_check(branch,ip,addr,0);

			printf("******************************************************\n");

			exit(0);
	}
}

VOID ImageForValidation(IMG img, void* addr, int action) {
	if( IMG_Valid(img) ) 
	{
		if(IMG_IsMainExecutable(img))
		{
			if(action == 1)
			{
				stacktrace_push(addr);
				pu++;
			}
			if(action == 2)
			{
				if(find_taints(addr)==0 && stackTrace.size()>1)
				{
					stacktrace_pop();
					po++;
				}
			}
		}
	}
}

VOID push(ADDRINT addrInt, void* addr)
{
	PIN_LockClient();
    IMG img = IMG_FindByAddress(addrInt);
	ImageForValidation(img, addr, 1);
    PIN_UnlockClient();
}

VOID pop(ADDRINT addrInt, void* addr)
{
	PIN_LockClient();
    IMG img = IMG_FindByAddress(addrInt);
	ImageForValidation(img, addr, 2);
    PIN_UnlockClient();
}

VOID Instruction(INS ins, VOID* v)
{
	if(INS_IsCall(ins))
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)push, IARG_INST_PTR, IARG_INST_PTR, IARG_END);
	}
	if(INS_IsRet(ins))
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)pop, IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TARGET_ADDR, IARG_END);
	}

	if(INS_IsIndirectControlFlow(ins) == true)
	{
		UINT32 memOperands = INS_MemoryOperandCount(ins);
		for (UINT32 memOp = 0; memOp < memOperands; memOp++)
		{
			if (INS_MemoryOperandIsRead(ins, memOp))
			{
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, 
				(AFUNPTR)recJump, 
					IARG_BRANCH_TARGET_ADDR,
					IARG_INST_PTR, 
					IARG_MEMORYOP_EA, 
					memOp, 
					IARG_END);
			}
		}
	}
}

VOID Image(IMG img, VOID *v) {
		RTN rtn;

		rtn = RTN_FindByName(img, FGETS);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fgetsHead, 
				IARG_INST_PTR,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_END);

				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fgetsTail, 
								IARG_FUNCRET_EXITPOINT_VALUE,
								IARG_INST_PTR, 
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, GETS);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getsTail, 
								IARG_FUNCRET_EXITPOINT_VALUE,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, STRCAT);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcatHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_END);
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)strcatTail, 
								IARG_FUNCRET_EXITPOINT_VALUE,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, MEMCPY);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memcpyHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_END);
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)memcpyTail, 
								IARG_FUNCRET_EXITPOINT_VALUE,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, STRNCAT);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncatHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_END);
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)strncatTail, 
								IARG_FUNCRET_EXITPOINT_VALUE,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, STRNCPY);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strncpyHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_END);
				RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)strncpyTail, 
								IARG_FUNCRET_EXITPOINT_VALUE,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, STRCPY);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcpyHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								// IARG_INST_PTR, 
								IARG_BRANCH_TARGET_ADDR,
								// IARG_MEMORYOP_EA,
								IARG_END);
				RTN_Close(rtn);
		}

	rtn = RTN_FindByName(img, BZERO);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)bzeroHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, MEMSET);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)memsetHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
								IARG_END);
				RTN_Close(rtn);
		}

		rtn = RTN_FindByName(img, MAIN);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mainHead, 
								IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
								IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
								IARG_INST_PTR, 
								IARG_END);
				RTN_Close(rtn);
		}


		rtn = RTN_FindByName(img, FILENO);
		if(RTN_Valid(rtn)) {
				RTN_Open(rtn);
				AFUNPTR fptr = RTN_Funptr(rtn);
				org_fileno = (FP_FILENO)(fptr);
				RTN_Close(rtn);
		}
  			
			// BOOL canBeProbed = RTN_IsSafeForProbedInsertion(rtn);
            // if (canBeProbed && RTN_Name(rtn)[0] != '_' && RTN_Name(rtn)[0] != '.')
            // {
            //     RTN_InsertCallProbed( rtn, IPOINT_BEFORE,  AFUNPTR(jumpHead), IARG_PTR, RTN_Name(rtn).c_str(), IARG_TSC, IARG_END);
            // }
}

int main(int argc, char *argv[])
{
	PIN_InitSymbols();

	if(PIN_Init(argc, argv)){
			return Usage();
	}
	INS_AddInstrumentFunction(Instruction, 0);
			
	IMG_AddInstrumentFunction(Image, 0);

	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();

	return 0;
}
