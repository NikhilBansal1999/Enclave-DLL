#include "Enclave_t.h"
#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>

long align_down(long addr, long size)
{
  long ans=addr-(addr%size);
  return ans;
}

long align_up(long addr,long size)
{
  if(addr%size==0)
  {
    return addr;
  }
  else
  {
    long ans=align_down(addr,size)+size;
    return ans;
  }
}

link_info* map_library(char* lib_name)
{
  int data_read;
  char* read_buffer;
  Elf_header* header=(Elf_header*)calloc(1,sizeof(Elf_header));
  link_info* info=(link_info*)calloc(1,sizeof(link_info));
  info->file_d=(char*)malloc(strlen(lib_name)+1);
  memcpy(info->file_d,lib_name,strlen(lib_name)+1);
  if(info->file_d == NULL)
  {
    ocall_print("Allocating memory for filename failed\n");
    return NULL;
  }
  long pagesize;
  get_pagesize(&pagesize);

  read_from_file(&read_buffer,sizeof(Elf_header),1,lib_name,0,&data_read);
  memcpy(header,read_buffer,sizeof(Elf_header));

  if(header->e_type != 3)
  {
    ocall_print("The given file is not a shared object\n");
    return NULL;
  }
  info->entry=header->e_entry;
  info->phnum=header->e_phnum;
  Elf64_Program_header prog_heads[header->e_phnum];

  read_from_file(&read_buffer,sizeof(Elf64_Program_header),header->e_phnum,lib_name,header->e_phoff,&data_read);
  memcpy(prog_heads,read_buffer,sizeof(Elf64_Program_header)*header->e_phnum);

  command commands[info->phnum];
  int num_commands=0;
  int gap=0;
  for(int i=0;i<header->e_phnum;i++)
  {
    if(prog_heads[i].p_type==PT_DYNAMIC)  /*Header type PT_DYNAMIC*/
    {
      info->dyn_vaddr=prog_heads[i].p_vaddr;
      info->dyn_num_ents=prog_heads[i].p_memsz/sizeof(Elf64_Dyn);
      info->dyn_num=i+1;
    }
    if(prog_heads[i].p_type==PT_PHDR)  /*Header Type PT_Phdr*/
    {
      info->pht_vaddr=prog_heads[i].p_vaddr;
    }
    if(prog_heads[i].p_type==PT_LOAD)  /*Header Type PT_Load*/
    {
      commands[num_commands].mapstart = align_down(prog_heads[i].p_vaddr,pagesize);
  	  commands[num_commands].mapend = align_up(prog_heads[i].p_vaddr + prog_heads[i].p_filesz,pagesize);
  	  commands[num_commands].dataend = prog_heads[i].p_vaddr + prog_heads[i].p_filesz;
  	  commands[num_commands].allocend = prog_heads[i].p_vaddr + prog_heads[i].p_memsz;
  	  commands[num_commands].mapoff = align_down(prog_heads[i].p_offset,pagesize);
      if((num_commands>1) && (commands[num_commands].mapstart != commands[num_commands-1].mapend))
      {
        gap=1;
      }
      commands[num_commands].prot=0;
      if(prog_heads[i].p_flags & 4)/*Give read permissions*/
      {
        commands[num_commands].prot = commands[num_commands].prot | PROT_READ;
      }
      if(prog_heads[i].p_flags & 2)/*Give write permissions*/
      {
        commands[num_commands].prot = commands[num_commands].prot | PROT_WRITE;
      }
      if(prog_heads[i].p_flags & 1)/*Give execute permissions*/
      {
        commands[num_commands].prot = commands[num_commands].prot | PROT_EXEC;
      }
      num_commands=num_commands+1;
    }
    if(prog_heads[i].p_type==PT_GNU_STACK) /*Header Type PT_GNU_STACK*/
    {
      info->stack_state=prog_heads[i].p_flags;
    }
   /*PT_NOTE and PT_TLS left out*/
  }

  /*Start mapping of library*/
  long length_of_mapping=commands[num_commands-1].allocend-commands[0].mapstart;
  char data_buf[length_of_mapping];

  info->start_of_mapping=(Elf64_Addr)malloc(length_of_mapping+pagesize);
  if(info->start_of_mapping == (Elf64_Addr)NULL)
  {
    ocall_print("Allocating memory for library failed\n");
    return NULL;
  }
  info->start_of_mapping=align_up(info->start_of_mapping,pagesize);

  read_from_file(&read_buffer,1,length_of_mapping,lib_name,commands[0].mapoff,&data_read);
  memcpy(data_buf,read_buffer,data_read);

  for(int i=0;i<data_read;i++)
  {
    *((char*)(info->start_of_mapping)+i)=data_buf[i];
  }
  protect_memory((long int)(info->start_of_mapping),data_read,commands[0].prot);
  /*int err_val=mprotect((void*)(info->start_of_mapping),data_read,commands[0].prot);
  if(err_val == -1)
  {
    ocall_print("Setting memory protections failed\n");
    return NULL;
  }*/
  info->end_of_mapping=info->start_of_mapping+length_of_mapping;
  info->base_addr=info->start_of_mapping-commands[0].mapstart;
  if(commands[0].allocend>commands[0].dataend)
  {
    memset((void *)(commands[0].dataend+info->base_addr),'\0',(commands[0].allocend-commands[0].dataend));
  }
  for(int i=1;i<num_commands;i++)
  {
    length_of_mapping=commands[i].mapend-commands[i].mapstart;

    read_from_file(&read_buffer,1,length_of_mapping,lib_name,commands[i].mapoff,&data_read);
    memcpy(data_buf,read_buffer,data_read);

    for(int j=0;j<data_read;j++)
    {
      *((char*)(info->base_addr+commands[i].mapstart)+j)=data_buf[j];
    }
    if(commands[i].allocend>commands[i].dataend)
    {
      memset((void *)(commands[i].dataend+info->base_addr),'\0',(commands[i].allocend-commands[i].dataend));
    }
  }
  protect_memory((long int)(commands[0].mapend+info->base_addr),commands[num_commands-1].allocend-commands[0].mapend,PROT_NONE);
  /*err_val=mprotect((void *)(commands[0].mapend+info->base_addr),commands[num_commands-1].allocend-commands[0].mapend,PROT_NONE);
  if(err_val == -1)
  {
    ocall_print("Setting memory protections failed\n");
    return NULL;
  }*/
  for(int i=1;i<num_commands;i++)
  {
    protect_memory((long int)(info->base_addr+commands[i].mapstart),data_read,commands[i].prot);
    /*err_val=mprotect((void*)(info->base_addr+commands[i].mapstart),data_read,commands[i].prot);
    if(err_val == -1)
    {
      ocall_print("Setting memory protections failed\n");
      return NULL;
    }*/
  }
  if(info->dyn_vaddr != (Elf64_Addr)NULL)
  {
    info->dyn_vaddr = info->dyn_vaddr + info->base_addr;
  }
  if(info->pht_vaddr != (Elf64_Addr)NULL)
  {
    info->pht_vaddr = info->pht_vaddr + info->base_addr;
  }
  Elf_Section_header section[header->e_shnum];

  read_from_file(&read_buffer,sizeof(Elf_Section_header),header->e_shnum,lib_name,header->e_shoff,&data_read);
  memcpy(section,read_buffer,sizeof(Elf_Section_header)*data_read);

  /*if(fseek(fd,header->e_shoff,SEEK_SET) == -1)
  {
    ocall_print("Parsing Library failed\n");
    return NULL;
  }
  data_read=fread(section,sizeof(Elf_Section_header),header->e_shnum,fd);
  if(data_read != header->e_shnum)
  {
    ocall_print("Error reading Library file\n");
    return NULL;
  }*/
  Elf64_Addr dynamic;
  int num_dyn_ent;
  for(int i=0;i < header->e_shnum ;i++)
  {
    if(section[i].sh_type==SHT_SYMTAB)   /*Symbol Table entry*/
    {
      info->symbol_table = section[i].sh_offset;
      info->num_sym_entry = section[i].sh_size/section[i].sh_entsize;
    }
    if(section[i].sh_type==SHT_STRTAB)   /*String Table entry*/
    {
      info->string_table = section[i].sh_offset;
    }
    if(section[i].sh_type==SHT_DYNAMIC)  /* DYNAMIC Section */
    {
      dynamic=section[i].sh_offset;
      num_dyn_ent=section[i].sh_size/section[i].sh_entsize;
    }
  }
  Elf64_Dyn dyn_entries[num_dyn_ent];
  Elf64_Addr relocation_addr;
  int num_relocations;

  read_from_file(&read_buffer,sizeof(Elf64_Dyn),num_dyn_ent,lib_name,dynamic,&data_read);
  memcpy(dyn_entries,read_buffer,sizeof(Elf64_Dyn)*data_read);

  /*if(fseek(fd,dynamic,SEEK_SET) == -1)
  {
    ocall_print("Parsing Library file failed\n");
    return NULL;
  }
  data_read=fread(dyn_entries,sizeof(Elf64_Dyn),num_dyn_ent,fd);
  if(data_read != num_dyn_ent)
  {
    ocall_print("Error reading library file\n");
    return NULL;
  }*/
  void (*init)();

  Elf64_Addr dyn_sym_offset;
  int sym_tabsize;
  int dyn_sym_num;
  int plt_ents;
  Elf64_Addr plt_offset;
  for(int i=0;i<num_dyn_ent;i++)
  {
    if(dyn_entries[i].d_tag==DT_SYMTAB) /*Symbol Table*/
    {
      dyn_sym_offset=dyn_entries[i].d_un.d_ptr;
    }
    if(dyn_entries[i].d_tag==DT_SYMENT) /*Size of symbol table*/
    {
      sym_tabsize=dyn_entries[i].d_un.d_val;
    }
    if(dyn_entries[i].d_tag==DT_RELA) /* DT_RELA*/
    {
      relocation_addr=dyn_entries[i].d_un.d_ptr;
    }
    if(dyn_entries[i].d_tag==DT_RELASZ) /*DT_RELASZ*/
    {
      num_relocations=dyn_entries[i].d_un.d_val/sizeof(Elf64_Rela);
    }
    if(dyn_entries[i].d_tag==DT_INIT)  /*DT_INIT*/
    {
      init = (void (*)())(info->base_addr+dyn_entries[i].d_un.d_ptr);
    }
    if(dyn_entries[i].d_tag==DT_PLTRELSZ)  /*Size of relocation entries associated with PLT*/
    {
      plt_ents=dyn_entries[i].d_un.d_val;
    }
    if(dyn_entries[i].d_tag==DT_JMPREL) /*DT_JMPREL*/
    {
      plt_offset=dyn_entries[i].d_un.d_ptr;
    }
  }
  plt_ents=plt_ents/sizeof(Elf64_Rela);

  dyn_sym_num=sym_tabsize/sizeof(Elf_Symtab_ent);
  Elf_Symtab_ent symbols[dyn_sym_num];

  read_from_file(&read_buffer,sizeof(Elf_Symtab_ent),info->num_sym_entry,lib_name,dyn_sym_offset,&data_read);
  memcpy(symbols,read_buffer,sizeof(Elf_Symtab_ent)*data_read);

  /*if(fseek(info->file_d,dyn_sym_offset,SEEK_SET) == -1)
  {
    ocall_print("Parsing Library file  failed\n");
    return NULL;
  }
  data_read=fread(symbols,sizeof(Elf_Symtab_ent),info->num_sym_entry,info->file_d);
  if(data_read != info->num_sym_entry)
  {
    ocall_print("Error reading library file\n");
    return NULL;
  }*/

  Elf64_Rela relocations[num_relocations];
  read_from_file(&read_buffer,sizeof(Elf64_Rela),num_relocations,lib_name,relocation_addr,&data_read);
  memcpy(relocations,read_buffer,sizeof(Elf64_Rela)*data_read);

  /*if(fseek(fd,relocation_addr,SEEK_SET) == -1)
  {
    ocall_print("Parsing Library file failed\n");
    return NULL;
  }
  data_read=fread(relocations,sizeof(Elf64_Rela),num_relocations,fd);
  if(data_read != num_relocations)
  {
    ocall_print("Error reading library file\n");
    return NULL;
  }*/
  for(int i=0;i<num_relocations;i++)
  {
    int sym_index=ELF64_R_SYM(relocations[i].r_info);
    int type=ELF64_R_TYPE(relocations[i].r_info);
    Elf64_Addr* reloc_addr=(Elf64_Addr*)(info->base_addr+relocations[i].r_offset);
    if(type==R_X86_64_GLOB_DAT)
    {
      *(reloc_addr)=symbols[sym_index].st_value;
    }
    if(type==R_X86_64_RELATIVE)
    {
      *(reloc_addr)=info->base_addr+relocations[i].r_addend;
    }
  }
  Elf64_Rela plt_relocations[plt_ents];

  read_from_file(&read_buffer,sizeof(Elf64_Rela),plt_ents,lib_name,plt_offset,&data_read);
  memcpy(plt_relocations,read_buffer,sizeof(Elf64_Rela)*data_read);

  /*fseek(fd,plt_offset,SEEK_SET);
  data_read=fread(plt_relocations,sizeof(Elf64_Rela),plt_ents,fd);*/
  for(int i=0;i<plt_ents;i++)
  {
    int sym_index=ELF64_R_SYM(plt_relocations[i].r_info);
    int type=ELF64_R_TYPE(plt_relocations[i].r_info);
    Elf64_Addr* reloc_addr=(Elf64_Addr*)(info->base_addr+plt_relocations[i].r_offset);
    if(type==R_X86_64_JUMP_SLOT)
    {
      *(reloc_addr)=symbols[sym_index].st_value;
    }
  }
  (*init)();

  for(int i=0;i<num_relocations;i++)
  {
    int sym_index=ELF64_R_SYM(relocations[i].r_info);
    int type=ELF64_R_TYPE(relocations[i].r_info);
    Elf64_Addr* reloc_addr=(Elf64_Addr*)(info->base_addr+relocations[i].r_offset);
    if(type==6)
    {
      *(reloc_addr)=info->base_addr+symbols[sym_index].st_value;
    }
    if(type==8)
    {
      *(reloc_addr)=info->base_addr+relocations[i].r_addend;
    }
  }
  for(int i=0;i<plt_ents;i++)
  {
    int sym_index=ELF64_R_SYM(plt_relocations[i].r_info);
    int type=ELF64_R_TYPE(plt_relocations[i].r_info);
    Elf64_Addr* reloc_addr=(Elf64_Addr*)(info->base_addr+plt_relocations[i].r_offset);
    if(type==7)
    {
      *(reloc_addr)=info->base_addr+symbols[sym_index].st_value;
    }
  }
  return info;
}

void get_function(long info_struct,char *func_name,int num)
{
  int data_read;
  link_info* info=(link_info*)info_struct;
  Elf_Symtab_ent* symbols = (Elf_Symtab_ent*)malloc(sizeof(Elf_Symtab_ent)*info->num_sym_entry);
  char* read_buffer;
  read_from_file(&read_buffer,sizeof(Elf_Symtab_ent),info->num_sym_entry,info->file_d,info->symbol_table,&data_read);
  memcpy(symbols,read_buffer,sizeof(Elf_Symtab_ent)*info->num_sym_entry);
  /*fseek(info->file_d,info->symbol_table,SEEK_SET);
  int data_red=fread(symbols,sizeof(Elf_Symtab_ent),info->num_sym_entry,info->file_d);*/
  char str[strlen(func_name)+1];
  for(int i=0;i < info->num_sym_entry;i++)
  {
    read_from_file(&read_buffer,strlen(func_name)+1,1,info->file_d,info->string_table+symbols[i].st_name,&data_read);
    memcpy(str,read_buffer,strlen(func_name)+1);
    /*fseek(info->file_d,info->string_table+symbols[i].st_name,SEEK_SET);
    fread(str,strlen(func_name)+1,1,info->file_d);*/
    if(strncmp(str,func_name,strlen(func_name)+1)==0)
    {
      void *addr=(void *)(info->base_addr+symbols[i].st_value);
      int (*fibo)(int);
      fibo=(int (*)(int))addr;
      char* output=(char*)malloc(100);
      snprintf(output,100,"%d\n\0",(*fibo)(num));
      ocall_print(output);
    }
  }
}
