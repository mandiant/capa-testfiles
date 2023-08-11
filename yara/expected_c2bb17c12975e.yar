rule super_rule_50580
{
    meta:
        author = "CAPA Matches"
        date_created = "2023-08-10"
        date_modified = "2023-08-10"
        description = ""
        md5 = "50580ef0b882905316c4569162ea07d9"
    strings:
        /*
Basic Block at 0x140001040@50580ef0b882905316c4569162ea07d9 with 1 features:
          - encode data using XOR
        .text:0x140001040  loc_140001040: [1 XREFS]
        .text:0x140001040  f30f6f0439       movdqu xmm0,oword [rcx + rdi]
        .text:0x140001045  660fefc2         pxor xmm0,xmm2
        .text:0x140001049  f30f7f0439       movdqu oword [rcx + rdi],xmm0
        .text:0x14000104e  f30f6f4c3910     movdqu xmm1,oword [rcx + rdi + 16]
        .text:0x140001054  660fefca         pxor xmm1,xmm2
        .text:0x140001058  f30f7f4c3910     movdqu oword [rcx + rdi + 16],xmm1
        .text:0x14000105e  f30f6f443920     movdqu xmm0,oword [rcx + rdi + 32]
        .text:0x140001064  660fefc2         pxor xmm0,xmm2
        .text:0x140001068  f30f7f443920     movdqu oword [rcx + rdi + 32],xmm0
        .text:0x14000106e  f30f6f443930     movdqu xmm0,oword [rcx + rdi + 48]
        .text:0x140001074  660fefc2         pxor xmm0,xmm2
        .text:0x140001078  f30f7f443930     movdqu oword [rcx + rdi + 48],xmm0
        .text:0x14000107e  4883c140         add rcx,64
        .text:0x140001082  483bc8           cmp rcx,rax
        .text:0x140001085  7cb9             jl 0x140001040
        */
        $c0 = { F3 0F 6F 04 39 66 0F EF C2 F3 0F 7F 04 39 F3 0F 6F 4C 39 ?? 66 0F EF CA F3 0F 7F 4C 39 ?? F3 0F 6F 44 39 ?? 66 0F EF C2 F3 0F 7F 44 39 ?? F3 0F 6F 44 39 ?? 66 0F EF C2 F3 0F 7F 44 39 ?? 48 83 C1 40 48 3B C8 7C ?? }
        /*
Basic Block at 0x140001090@50580ef0b882905316c4569162ea07d9 with 1 features:
          - encode data using XOR
        .text:0x140001090  loc_140001090: [1 XREFS]
        .text:0x140001090  80343862         xor byte [rax + rdi],98
        .text:0x140001094  48ffc0           inc rax
        .text:0x140001097  483d1f030000     cmp rax,799
        .text:0x14000109d  7cf1             jl 0x140001090
        */
        $c1 = { 80 34 38 62 48 FF C0 48 3D 1F 03 00 00 7C ?? }
        /*
Basic Block at 0x14000109f@50580ef0b882905316c4569162ea07d9 with 1 features:
          - allocate RWX memory
        .text:0x14000109f  33c9             xor ecx,ecx
        .text:0x1400010a1  ba1f030000       mov edx,799
        .text:0x1400010a6  41b800100000     mov r8d,0x00001000
        .text:0x1400010ac  448d4940         lea r9d,dword [rcx + 64]
        .text:0x1400010b0  ff154a0f0000     call qword [rip + 3914]    ;kernel32.VirtualAlloc(0,799,0x00001000,64)
        .text:0x1400010b6  41b81f030000     mov r8d,799
        .text:0x1400010bc  488bd7           mov rdx,rdi
        .text:0x1400010bf  488bc8           mov rcx,rax
        .text:0x1400010c2  488bd8           mov rbx,rax
        .text:0x1400010c5  e8650d0000       call 0x140001e2f    ;memmove_140001e2f()
        .text:0x1400010ca  488d0d7f110000   lea rcx,qword [rip + 4479]
        .text:0x1400010d1  c744242020000000 mov dword [rsp + 32],32
        .text:0x1400010d9  c744242401000000 mov dword [rsp + 36],1
        .text:0x1400010e1  48c7442428000000 mov qword [rsp + 40],0
        .text:0x1400010ea  48895c2430       mov qword [rsp + 48],rbx
        .text:0x1400010ef  48c7442438000000 mov qword [rsp + 56],0
        .text:0x1400010f8  ff150a0f0000     call qword [rip + 3850]    ;kernel32.DeleteFileW(0x140002250)
        .text:0x1400010fe  4c8d442420       lea r8,qword [rsp + 32]
        .text:0x140001103  488d1546110000   lea rdx,qword [rip + 4422]
        .text:0x14000110a  488d0d77110000   lea rcx,qword [rip + 4471]
        .text:0x140001111  ff15f90e0000     call qword [rip + 3833]    ;UnknownApi()
        .text:0x140001117  33c0             xor eax,eax
        .text:0x140001119  488b4c2440       mov rcx,qword [rsp + 64]
        .text:0x14000111e  4833cc           xor rcx,rsp
        .text:0x140001121  e82a000000       call 0x140001150    ;__security_check_cookie(0x2b992ddfa232)
        .text:0x140001126  488b5c2460       mov rbx,qword [rsp + 96]
        .text:0x14000112b  4883c450         add rsp,80
        .text:0x14000112f  5f               pop rdi
        .text:0x140001130  c3               ret 
        */
        $c2 = { 33 C9 BA 1F 03 00 00 41 B8 00 10 00 00 44 8D 49 ?? FF 15 ?? ?? ?? ?? 41 B8 1F 03 00 00 48 8B D7 48 8B C8 48 8B D8 E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? C7 44 24 ?? 20 00 00 00 C7 44 24 ?? 01 00 00 00 48 C7 44 24 ?? 00 00 00 00 48 89 5C 24 ?? 48 C7 44 24 ?? 00 00 00 00 FF 15 ?? ?? ?? ?? 4C 8D 44 24 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C0 48 8B 4C 24 ?? 48 33 CC E8 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 C4 50 5F C3 }
        /*
function at 0x140001010@50580ef0b882905316c4569162ea07d9 with 3 features:
          - copy file
          - delete file
          - execute shellcode via CopyFile2
        .text:0x140001010  
        .text:0x140001010  FUNC: int msx64call sub_140001010( ) [2 XREFS] 
        .text:0x140001010  
        .text:0x140001010  Stack Variables: (offset from initial top of stack)
        .text:0x140001010            32: void * shadow3
        .text:0x140001010            24: void * shadow2
        .text:0x140001010            16: void * shadow1
        .text:0x140001010             8: void * shadow0
        .text:0x140001010           -24: int local24
        .text:0x140001010           -32: int local32
        .text:0x140001010           -40: int local40
        .text:0x140001010           -48: int local48
        .text:0x140001010           -52: int local52
        .text:0x140001010           -56: int local56
        .text:0x140001010  
        .text:0x140001010  48895c2408       mov qword [rsp + 8],rbx
        .text:0x140001015  57               push rdi
        .text:0x140001016  4883ec50         sub rsp,80
        .text:0x14000101a  488b05df1f0000   mov rax,qword [rip + 8159]
        .text:0x140001021  4833c4           xor rax,rsp
        .text:0x140001024  4889442440       mov qword [rsp + 64],rax
        .text:0x140001029  660f6f158f120000 movdqa xmm2,oword [rip + 4751]
        .text:0x140001031  488d3d08200000   lea rdi,qword [rip + 8200]
        .text:0x140001038  33c9             xor ecx,ecx
        .text:0x14000103a  b800030000       mov eax,768
        .text:0x14000103f  90               nop 
        .text:0x140001040  loc_140001040: [1 XREFS]
        .text:0x140001040  f30f6f0439       movdqu xmm0,oword [rcx + rdi]
        .text:0x140001045  660fefc2         pxor xmm0,xmm2
        .text:0x140001049  f30f7f0439       movdqu oword [rcx + rdi],xmm0
        .text:0x14000104e  f30f6f4c3910     movdqu xmm1,oword [rcx + rdi + 16]
        .text:0x140001054  660fefca         pxor xmm1,xmm2
        .text:0x140001058  f30f7f4c3910     movdqu oword [rcx + rdi + 16],xmm1
        .text:0x14000105e  f30f6f443920     movdqu xmm0,oword [rcx + rdi + 32]
        .text:0x140001064  660fefc2         pxor xmm0,xmm2
        .text:0x140001068  f30f7f443920     movdqu oword [rcx + rdi + 32],xmm0
        .text:0x14000106e  f30f6f443930     movdqu xmm0,oword [rcx + rdi + 48]
        .text:0x140001074  660fefc2         pxor xmm0,xmm2
        .text:0x140001078  f30f7f443930     movdqu oword [rcx + rdi + 48],xmm0
        .text:0x14000107e  4883c140         add rcx,64
        .text:0x140001082  483bc8           cmp rcx,rax
        .text:0x140001085  7cb9             jl 0x140001040
        .text:0x140001087  660f1f8400000000 nop word [rax + rax]
        .text:0x140001090  loc_140001090: [1 XREFS]
        .text:0x140001090  80343862         xor byte [rax + rdi],98
        .text:0x140001094  48ffc0           inc rax
        .text:0x140001097  483d1f030000     cmp rax,799
        .text:0x14000109d  7cf1             jl 0x140001090
        .text:0x14000109f  33c9             xor ecx,ecx
        .text:0x1400010a1  ba1f030000       mov edx,799
        .text:0x1400010a6  41b800100000     mov r8d,0x00001000
        .text:0x1400010ac  448d4940         lea r9d,dword [rcx + 64]
        .text:0x1400010b0  ff154a0f0000     call qword [rip + 3914]    ;kernel32.VirtualAlloc(0,799,0x00001000,64)
        .text:0x1400010b6  41b81f030000     mov r8d,799
        .text:0x1400010bc  488bd7           mov rdx,rdi
        .text:0x1400010bf  488bc8           mov rcx,rax
        .text:0x1400010c2  488bd8           mov rbx,rax
        .text:0x1400010c5  e8650d0000       call 0x140001e2f    ;memmove_140001e2f()
        .text:0x1400010ca  488d0d7f110000   lea rcx,qword [rip + 4479]
        .text:0x1400010d1  c744242020000000 mov dword [rsp + 32],32
        .text:0x1400010d9  c744242401000000 mov dword [rsp + 36],1
        .text:0x1400010e1  48c7442428000000 mov qword [rsp + 40],0
        .text:0x1400010ea  48895c2430       mov qword [rsp + 48],rbx
        .text:0x1400010ef  48c7442438000000 mov qword [rsp + 56],0
        .text:0x1400010f8  ff150a0f0000     call qword [rip + 3850]    ;kernel32.DeleteFileW(0x140002250)
        .text:0x1400010fe  4c8d442420       lea r8,qword [rsp + 32]
        .text:0x140001103  488d1546110000   lea rdx,qword [rip + 4422]
        .text:0x14000110a  488d0d77110000   lea rcx,qword [rip + 4471]
        .text:0x140001111  ff15f90e0000     call qword [rip + 3833]    ;UnknownApi()
        .text:0x140001117  33c0             xor eax,eax
        .text:0x140001119  488b4c2440       mov rcx,qword [rsp + 64]
        .text:0x14000111e  4833cc           xor rcx,rsp
        .text:0x140001121  e82a000000       call 0x140001150    ;__security_check_cookie(0x2b992ddfa232)
        .text:0x140001126  488b5c2460       mov rbx,qword [rsp + 96]
        .text:0x14000112b  4883c450         add rsp,80
        .text:0x14000112f  5f               pop rdi
        .text:0x140001130  c3               ret 
        */
        $c3 = { 48 89 5C 24 ?? 57 48 83 EC 50 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 44 24 ?? 66 0F 6F 15 ?? ?? 00 00 48 8D 3D ?? ?? ?? ?? 33 C9 B8 00 03 00 00 90 F3 0F 6F 04 39 66 0F EF C2 F3 0F 7F 04 39 F3 0F 6F 4C 39 ?? 66 0F EF CA F3 0F 7F 4C 39 ?? F3 0F 6F 44 39 ?? 66 0F EF C2 F3 0F 7F 44 39 ?? F3 0F 6F 44 39 ?? 66 0F EF C2 F3 0F 7F 44 39 ?? 48 83 C1 40 48 3B C8 7C ?? 66 0F 1F 84 00 ?? ?? 00 00 80 34 38 62 48 FF C0 48 3D 1F 03 00 00 7C ?? 33 C9 BA 1F 03 00 00 41 B8 00 10 00 00 44 8D 49 ?? FF 15 ?? ?? ?? ?? 41 B8 1F 03 00 00 48 8B D7 48 8B C8 48 8B D8 E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? C7 44 24 ?? 20 00 00 00 C7 44 24 ?? 01 00 00 00 48 C7 44 24 ?? 00 00 00 00 48 89 5C 24 ?? 48 C7 44 24 ?? 00 00 00 00 FF 15 ?? ?? ?? ?? 4C 8D 44 24 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C0 48 8B 4C 24 ?? 48 33 CC E8 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 C4 50 5F C3 }
        /*
function at 0x140001a24@50580ef0b882905316c4569162ea07d9 with 1 features:
          - parse PE header
        .text:0x140001a24  
        .text:0x140001a24  FUNC: int msx64call sub_140001a24( ) [2 XREFS] 
        .text:0x140001a24  
        .text:0x140001a24  Stack Variables: (offset from initial top of stack)
        .text:0x140001a24            32: void * shadow3
        .text:0x140001a24            24: void * shadow2
        .text:0x140001a24            16: void * shadow1
        .text:0x140001a24             8: void * shadow0
        .text:0x140001a24  
        .text:0x140001a24  4883ec28         sub rsp,40
        .text:0x140001a28  33c9             xor ecx,ecx
        .text:0x140001a2a  ff1518060000     call qword [rip + 1560]    ;kernel32.GetModuleHandleW(0)
        .text:0x140001a30  4885c0           test rax,rax
        .text:0x140001a33  7439             jz 0x140001a6e
        .text:0x140001a35  b94d5a0000       mov ecx,0x00005a4d
        .text:0x140001a3a  663908           cmp word [rax],cx
        .text:0x140001a3d  752f             jnz 0x140001a6e
        .text:0x140001a3f  4863483c         movsxd rcx,dword [rax + 60]
        .text:0x140001a43  4803c8           add rcx,rax
        .text:0x140001a46  813950450000     cmp dword [rcx],0x00004550
        .text:0x140001a4c  7520             jnz 0x140001a6e
        .text:0x140001a4e  b80b020000       mov eax,523
        .text:0x140001a53  66394118         cmp word [rcx + 24],ax
        .text:0x140001a57  7515             jnz 0x140001a6e
        .text:0x140001a59  83b9840000000e   cmp dword [rcx + 132],14
        .text:0x140001a60  760c             jbe 0x140001a6e
        .text:0x140001a62  83b9f800000000   cmp dword [rcx + 248],0
        .text:0x140001a69  0f95c0           setnz al
        .text:0x140001a6c  eb02             jmp 0x140001a70
        .text:0x140001a6e  loc_140001a6e: [5 XREFS]
        .text:0x140001a6e  32c0             xor al,al
        .text:0x140001a70  loc_140001a70: [1 XREFS]
        .text:0x140001a70  4883c428         add rsp,40
        .text:0x140001a74  c3               ret 
        */
        $c4 = { 48 83 EC 28 33 C9 FF 15 ?? ?? ?? ?? 48 85 C0 74 ?? B9 4D 5A 00 00 66 39 08 75 ?? 48 63 48 ?? 48 03 C8 81 39 50 45 00 00 75 ?? B8 0B 02 00 00 66 39 41 ?? 75 ?? 83 B9 ?? ?? ?? ?? 0E 76 ?? 83 B9 ?? ?? ?? ?? 00 0F 95 C0 EB ?? 32 C0 48 83 C4 28 C3 }
    condition:
        all of them
}

