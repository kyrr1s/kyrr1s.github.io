---
layout: post
title: "Abusing ELF Files' forgotten fields"
date: 2025-12-04 12:00:00 +0300
categories: [MalDev]
tags: [elf, linux, maldev, reverse]
author: kyrr1s
math: false
mermaid: false
pin: false
---

# Abusing ELF Files' forgotten fields

Through my various experiments with ELF files, I noticed that the Linux loader ignores some fields in the ELF Header structure. This led me to the idea of a simple exploitation of this feature by inserting various bytes of code to confuse malware researchers and their tools, without limiting the functionality of the original code. As a result, a specialized utility and library were created. They help to modify code in your programs so that the program fails to launch if these insignificant bytes are altered. Thus, analysts must choose between dynamic and static code analysis.

### **ELF File Loading Process**

First, we need to understand exactly how Linux loads ELF files into memory and which kernel functions are used for this. For this, we'll use the `perf` utility and collect a trace of all functions during the execution of a test file, including those that load the file.

Let's create a legitimate file and start tracing:

![Trace Start](/assets/img/abusingElf/trace-start.png){: width="700" height="auto" }

To view the trace results, enter: `perf script -i perf.data`

We see a clear order of function calls for loading and starting the file:
1. `flush_signal_handlers` - clearing signal handlers of the old process
2. `begin_new_exec` - preparing a new execution context
3. `load_elf_binary` - parsing ELF, loading segments, configuring memory
4. `bprm_execve` - working with the `linux_binprm` structure (arguments, environment)
5. `do_execveat_common.isra.0` - general execution logic
6. `__x64_sys_execve` - system call handler for x86_64
7. `x64_sys_call` → `do_syscall_64` → `entry_SYSCALL_64` - system call dispatcher and hardware entry

![Trace Results](/assets/img/abusingElf/trace-results.png){: width="700" height="auto" }

Thus, our attention should focus on the `load_elf_binary` function.

### **ELF File Architecture**

An ELF file is the basic executable file in the Linux OS. It contains all the information needed by the OS to load and run the file. This information is structured as follows:
- ELF Header
- Segments Headers or Program Headers
- Section Headers

The ELF Header is mostly useless (as we'll see later) and contains basic file information. It and other headers can be viewed using the `readelf` utility:
```

~$ readelf -h sample

ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x411710
  Start of program headers:          64 (bytes into file)
  Start of section headers:          498224 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         8
  Size of section headers:           64 (bytes)
  Number of section headers:         30
  Section header string table index: 27
```

For simplicity, we'll use the field names from the `readelf` output here and later, i.e., instead of `e_ident` we'll say `Magic`, and so on.

Here's a brief description of the purpose of the fields (possible field values are not of interest to us here):
- `Magic` - ELF file identifier
- `Class` - program bitness
- `Data` - program byte order
- `Version` - program version
- `Padding bytes` - 8 zero bytes
- `OS/ABI` - ABI version used in the program
- `ABI Version` - specific ABI version
- `Type` - program type (e.g., executable or library)
- `Machine` - processor type for which the program is intended
- `Version` - program version (second time, always equal to the value above)
- `Entry point address` - program entry point
- `Start of program headers` - offset to Program Headers
- `Start of section headers` - offset to Section Headers
- `Flags` - flags allowing the program to specify additional information needed by the OS
- `Size of this header` - size of ELF header
- `Size of program headers` - size of Program Headers
- `Number of program headers` - number of segments in Program Headers
- `Size of section headers` - size of Section Headers
- `Number of section headers` - number of sections in Section Headers
- `Section header string table index` - index of the section containing all section names as a single string

Program Headers tell the loader how to efficiently transfer the ELF binary into memory. Section Headers provide a logical breakdown of the ELF file. These two headers are not of interest to us here - modifying them requires much more extensive file manipulation, and all their fields are actively used by the loader and interpreter.

### **ELF File Loader Operation**

The loader [source code](https://github.com/torvalds/linux/blob/3f9f0252130e7dd60d41be0802bf58f6471c691d/fs/binfmt_elf.c#L832) is available on GitHub.

The file first undergoes **checks** in this order:

1. Checking the `Magic` field: must always be `0x7fELF`
2. Checking the `Type` field: the file must be either executable (`ET_EXEC`) or a dynamically shared library (`ET_DYN`)
3. Checking program architecture: generally, the `Machine` field must equal one of the values from [this file](https://github.com/torvalds/linux/blob/3f9f0252130e7dd60d41be0802bf58f6471c691d/include/uapi/linux/elf-em.h). However, in some cases additional conditions apply:
   - For `ARCOMPACT` and `ARCV2`: the third byte in the `Flags` field must not equal `3` or `4` (eflags & 0x0x00000f00 != 0x000003(4)00)
   - For `PARISC` and `RISCV`: the `Class` field must equal `1` (`ELF32`) or `2` (`ELF64`)
   - For `ARM`:
     - Both words of the `Entry point address` field are not even
     - The high byte of the `Flags` field is not 0 - an unknown ABI format is used:
       - If the third bit of the `Flags` field is set, the processor must support 26-bit mode
       - If the 10th or 9th bit of the `Flags` field is set, the processor must support VFP
   - For `ARM` and `XTENSA`, check that the `OS/ABI` field equals `65`
4. Checking the file driver: the file driver must use one implementation of the mmap API

![Basic Checks](/assets/img/abusingElf/basic-checks.png){: width="700" height="auto" }

Next follows a lengthy process of handling the rest of the ELF file content: parsing and loading sections and segments. Throughout this process, the `Flags` field is used multiple times, which closes access to its free modification for us. Other fields of the ELF header are used by the program interpreter, which also doesn't allow us to modify them freely.

Thus, almost no checks are performed on the ELF header content. ELF Header fields not checked (ignored) by the loader and interpreter:
1. `Data` field
2. After `Class`
3. `Version` field (both variants)
4. `Padding bytes` field
5. `OS/ABI` field is ignored in most architectures
6. `ABI version` field is ignored in most architectures
7. `Size of this header` field
8. `Size of section headers` field
9. `Number of section headers` field
10. `Section header string table index` field

In Linux architecture, these fields are called respectively:
1. `e_ident[EI_DATA]`
2. `e_ident[EI_CLASS]`
3. `e_ident[EI_VERSION]` and `e_version`
4. `e_ident[EI_PAD]`
5. `e_ident[EI_OSABI]`
6. `e_ident[EI_ABIVERSION]`
7. `e_ehsize`
8. `e_shentsize`
9. `e_shnum`
10. `e_shstrndx`

### **Exploitation Concept and Implementation**

This feature of the ELF header can be easily exploited: if these fields are not checked, they can store ANY data. The disadvantages of this technique include that this data can occupy a total of 24 bytes, and they are not contiguous in the file. These fields can store:

1. Some key for decrypting file content, C2 address, or other similar artifact
2. Any information whose integrity will be checked by the program

In this article, I would like to focus on the second idea. By writing random data into these fields, we can confuse malware analysts and their analysis tools that are incorrectly configured for specific bytes in these fields. At the same time, the program will continue to execute successfully. If these bytes are modified by an analyst, the program will stop executing because it checks the integrity of its code. Thus, the analyst finds themselves in a difficult position: they must rely either only on static or only on dynamic code analysis. 

Of course, one can always find and patch the integrity check function, but various obfuscation mechanisms should help with that.

### **Implementation**

#### **Viewer**

First, a utility called `elfields` was written to modify and view the interesting fields in an ELF file.

Example output of these fields on a normal program:
![Elfields Normal](/assets/img/abusingElf/elfields-normal.png){: width="700" height="auto" }

The utility also allows calculating the hash of these fields, which will be useful to us later:
![Elfields Hash](/assets/img/abusingElf/elfields-hash.png){: width="700" height="auto" }

Now let's change some fields of this file using the utility. In this case, I wrote the string "someMalwareKey" into the fields:
![Elfields Changes](/assets/img/abusingElf/elfields-changes.png){: width="700" height="auto" }

But the file still launches!
![Elfields Launch](/assets/img/abusingElf/elfields-launch.png){: width="700" height="auto" }

Let's try modifying something more complex than a "Hello World!" program. I chose the `ls` utility. As we can see, it also launches without issues:
![Elfields Ls](/assets/img/abusingElf/elfields-ls.png){: width="700" height="auto" }

But the most interesting part is the reaction of various malware analysis tools.

No disassembler can parse our modified program (I used [dogbolt](https://dogbolt.org/) project):
![Disasms](/assets/img/abusingElf/disasms.png){: width="700" height="auto" }

Libraries for analyzing ELF files like `pyelftools` also crash:
![Pyelftools](/assets/img/abusingElf/pyelftools.png){: width="700" height="auto" }

Tools for viewing files like [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) cannot parse the file:
![Die](/assets/img/abusingElf/die.png){: width="700" height="auto" }

IDA 9.2 correctly parsed the file magic:
![Ida Load](/assets/img/abusingElf/ida-load.png){: width="700" height="auto" }

But crashes during further processing:
![Ida Warning](/assets/img/abusingElf/ida-warning.png){: width="700" height="auto" }
![Ida Nothing](/assets/img/abusingElf/ida-nothing.png){: width="700" height="auto" }

GDB also cannot start debugging the file:
![Gdb](/assets/img/abusingElf/gdb.png){: width="700" height="auto" }

#### **Checker**

A header file `elfields.h` was implemented that handles comparing the current hash of unused ELF file fields with one pre-recorded by the developer. This functionality allows checking the file before running the main code - if the file was modified by a malware analyst and the field hash changed, then execution must be terminated. Moreover, implementing through a header file leaves the choice of method for storing the comparison hash, the location for calling the key comparison function, and the handling of the function execution result up to the developer. This makes the file's usage options more flexible.

Below is an example of this header file in action:
1) Compile the program with the `-lssl` `-lcrypto` options for hash function support
2) Calculate the hash of unused fields - it does not change regardless of program content
3) Call the hash check function inside the program, for example before starting the main program, and pass it the obtained hash as an argument
4) Try changing some field of the program - imagine we're an analyst trying to fix the program header
5) Now the program won't launch!

![Checker](/assets/img/abusingElf/checker.png){: width="700" height="auto" }

The complete implementation, including the `elfields` utility and `elfields.h` library, is available on GitHub for further research and development.

## **Conclusion and Future Work**

The research presented demonstrates a practical exploitation of a significant oversight in Linux ELF file loading mechanisms. By targeting the 24 bytes of ignored fields in the ELF header, we've created a technique that:

1. Effectively disrupts static analysis tools without affecting program execution
2. Forces analysts to choose between static and dynamic analysis approaches
3. Provides built-in tamper detection through hash verification
4. Maintains full program functionality while confusing analysis tools

The implications are significant for both offensive and defensive security applications. For malware developers, this provides an additional layer of evasion that's difficult to detect and counter. For defenders and tool developers, it highlights a critical area where ELF parsers need improvement.

In the future I would like to make similar research with PE files.

(This is my first research so if there are some mistakes, dm me in tg)