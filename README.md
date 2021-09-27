# Resources for testing capa
Data to test capa's [code](https://github.com/mandiant/capa) and [rules](https://github.com/mandiant/capa-rules).

## Naming conventions
We use the following conventions to organize the capa test data.

- File name
  - MD5 or SHA256 hash, all lower case, e.g.
    - `d41d8cd98f00b204e9800998ecf8427e`
    - `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
  - Descriptive name, e.g.
    - `kernel32`
    - `Practical Malware Analysis Lab 01-01`
- File extension
  - `.exe_`
  - `.dll_`
  - `.sys_`
  - `.raw32` (32-bit shellcode)
  - `.raw64` (64-bit shellcode)
