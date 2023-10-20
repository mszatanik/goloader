# goloader
### a shellcode loader written in GO.
### the aim is to have a tool which is also a collection of different injection methods

```
.\goloader.exe -h
Usage of goloader.exe:
  -k string
        a 32 char long key used to decrypt the file
  -p uint
        pid of a process to inject into
  -t string
        what to do ?
  -w string
        what to load ?
```
```
currently working examples:
.\goloader.exe -t local_process_execution -w .\tmp\calc.raw
.\goloader.exe -t local_process_execution -w .\tmp\calc.enc -k AAAAAAAAAAaaaaaaaaaaAAAAAAAAAAaa
```