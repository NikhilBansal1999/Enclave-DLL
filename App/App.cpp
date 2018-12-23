#include <stdio.h>
#include <iostream>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include <stdlib.h>
#include <unistd.h>
#include<sys/mman.h>


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
long get_pagesize()
{
  long pagesize = sysconf(_SC_PAGESIZE);
  return pagesize;
}
void protect_memory(long addr, size_t len, int prot)
{
  int err_val=mprotect((void*)addr,len,prot);
  if(err_val == -1)
  {
    printf("Setting memory protections failed\n");
  }
}
void ocall_print(const char* str)
{
    printf("%s", str);
}

char* read_from_file(size_t size_elem,size_t num_elem,char* lib_name,long offset,int *data_sent)
{
  FILE* fd=fopen(lib_name,"r");
  if(fd == NULL)
  {
    printf("Error opening file\n");
    printf("%s\n",lib_name);
    return NULL;
  }
  char* data_buf=(char*)malloc(size_elem*num_elem);
  if(data_buf == NULL)
  {
    printf("Error allocating buffer\n");
    return NULL;
  }
  if(fseek(fd,offset,SEEK_SET) == -1)
  {
    printf("Error parsing library file\n");
    return NULL;
  }
  int data_read=fread(data_buf,size_elem,num_elem,fd);
  *data_sent = data_read;
  /*if(data_read != num_elem)
  {
    printf("Error reading buffer\n");
    return NULL;
  }*/
  fclose(fd);
  return data_buf;
}

void ocall_sleep(int sec)
{
  sleep(sec);
}

int main(int argc, char const *argv[])
{
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    link_info* handle;
    sgx_status_t status = map_library(global_eid, &handle,"./lib_test.so");
    if (status != SGX_SUCCESS) {
        std::cout << "noob" << std::endl;
    }
    else
    {
      printf("Successfully loaded library!\n");
      get_function(global_eid,(long)handle,"fibonacci",10);
    }
    return 0;
}
