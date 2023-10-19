rule super_rule_18ec5
{
    meta:
        author = "CAPA Matches"
        date_created = "EXPECTED_DATE"
        date_modified = "EXPECTED_DATE"
        description = ""
        md5 = "18ec5becfa3991fb654e105bafbd5a4b"
    strings:
        /*
function at 0x004012d0@18ec5becfa3991fb654e105bafbd5a4b with 1 features:
          - copy file
        .text:0x004012d0  
        .text:0x004012d0  FUNC: int msfastcall sub_004012d0( int ecx, int edx, ) [2 XREFS] 
        .text:0x004012d0  
        .text:0x004012d0  Stack Variables: (offset from initial top of stack)
        .text:0x004012d0          -264: int local264
        .text:0x004012d0  
        .text:0x004012d0  55               push ebp
        .text:0x004012d1  8bec             mov ebp,esp
        .text:0x004012d3  81ec04010000     sub esp,260
        .text:0x004012d9  6a00             push 0
        .text:0x004012db  68b8914000       push 0x004091b8
        .text:0x004012e0  68a8914000       push 0x004091a8
        .text:0x004012e5  ff151c804000     call dword [0x0040801c]    ;kernel32.CopyFileA(0x004091a8,0x004091b8,0)
        .text:0x004012eb  689c914000       push 0x0040919c
        .text:0x004012f0  6884914000       push 0x00409184
        .text:0x004012f5  8d85fcfeffff     lea eax,dword [ebp - 260]
        .text:0x004012fb  50               push eax
        .text:0x004012fc  e851010000       call 0x00401452    ;_sprintf(ecx,edx,local264,0x00409184,0x0040919c)
        .text:0x00401301  83c40c           add esp,12
        .text:0x00401304  8d8dfcfeffff     lea ecx,dword [ebp - 260]
        .text:0x0040130a  51               push ecx
        .text:0x0040130b  e860fdffff       call 0x00401070    ;sub_00401070(local264)
        .text:0x00401310  83c404           add esp,4
        .text:0x00401313  6874914000       push 0x00409174
        .text:0x00401318  e89f000000       call 0x004013bc    ;sub_004013bc(sub_00401070(local264),edx,local264,0x00409174)
        .text:0x0040131d  83c404           add esp,4
        .text:0x00401320  33c0             xor eax,eax
        .text:0x00401322  8be5             mov esp,ebp
        .text:0x00401324  5d               pop ebp
        .text:0x00401325  c3               ret 
        */
        $c0 = { 55 8B EC 81 EC 04 01 00 00 6A 00 68 B8 91 40 00 68 A8 91 40 00 FF 15 ?? ?? ?? ?? 68 9C 91 40 00 68 84 91 40 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 04 68 74 91 40 00 E8 ?? ?? ?? ?? 83 C4 04 33 C0 8B E5 5D C3 }
        /*
function at 0x00401070@18ec5becfa3991fb654e105bafbd5a4b with 3 features:
          - enumerate PE sections
          - get file size
          - read file via mapping
        .text:0x00401070  
        .text:0x00401070  FUNC: int cdecl sub_00401070( int arg0, ) [2 XREFS] 
        .text:0x00401070  
        .text:0x00401070  Stack Variables: (offset from initial top of stack)
        .text:0x00401070             4: int arg0
        .text:0x00401070            -8: int local8
        .text:0x00401070           -12: int local12
        .text:0x00401070           -16: int local16
        .text:0x00401070           -20: int local20
        .text:0x00401070           -24: int local24
        .text:0x00401070           -28: int local28
        .text:0x00401070           -32: int local32
        .text:0x00401070           -36: int local36
        .text:0x00401070           -40: int local40
        .text:0x00401070           -44: int local44
        .text:0x00401070           -48: int local48
        .text:0x00401070           -52: int local52
        .text:0x00401070  
        .text:0x00401070  55               push ebp
        .text:0x00401071  8bec             mov ebp,esp
        .text:0x00401073  83ec30           sub esp,48
        .text:0x00401076  56               push esi
        .text:0x00401077  57               push edi
        .text:0x00401078  c745fc00000000   mov dword [ebp - 4],0
        .text:0x0040107f  6a00             push 0
        .text:0x00401081  6880000000       push 128
        .text:0x00401086  6a04             push 4
        .text:0x00401088  6a00             push 0
        .text:0x0040108a  6a01             push 1
        .text:0x0040108c  68000000c0       push 0xc0000000
        .text:0x00401091  8b4508           mov eax,dword [ebp + 8]
        .text:0x00401094  50               push eax
        .text:0x00401095  ff1518804000     call dword [0x00408018]    ;kernel32.CreateFileA(arg0,0xc0000000,1,0,4,128,0)
        .text:0x0040109b  8945d4           mov dword [ebp - 44],eax
        .text:0x0040109e  837dd4ff         cmp dword [ebp - 44],0xffffffff
        .text:0x004010a2  7508             jnz 0x004010ac
        .text:0x004010a4  83c8ff           or eax,0xffffffff
        .text:0x004010a7  e919020000       jmp 0x004012c5
        .text:0x004010ac  loc_004010ac: [1 XREFS]
        .text:0x004010ac  6a00             push 0
        .text:0x004010ae  8b4dd4           mov ecx,dword [ebp - 44]
        .text:0x004010b1  51               push ecx
        .text:0x004010b2  ff1514804000     call dword [0x00408014]    ;kernel32.GetFileSize(kernel32.CreateFileA(arg0,0xc0000000,1,0,4,128,0),0)
        .text:0x004010b8  8945f0           mov dword [ebp - 16],eax
        .text:0x004010bb  6a00             push 0
        .text:0x004010bd  8b55f0           mov edx,dword [ebp - 16]
        .text:0x004010c0  52               push edx
        .text:0x004010c1  6a00             push 0
        .text:0x004010c3  6a04             push 4
        .text:0x004010c5  6a00             push 0
        .text:0x004010c7  8b45d4           mov eax,dword [ebp - 44]
        .text:0x004010ca  50               push eax
        .text:0x004010cb  ff1510804000     call dword [0x00408010]    ;kernel32.CreateFileMappingA(<0x00401095>,0,4,0,kernel32.GetFileSize(<0x00401095>,0),0)
        .text:0x004010d1  8945f4           mov dword [ebp - 12],eax
        .text:0x004010d4  837df4ff         cmp dword [ebp - 12],0xffffffff
        .text:0x004010d8  7512             jnz 0x004010ec
        .text:0x004010da  8b4dd4           mov ecx,dword [ebp - 44]
        .text:0x004010dd  51               push ecx
        .text:0x004010de  ff150c804000     call dword [0x0040800c]    ;kernel32.CloseHandle(<0x00401095>)
        .text:0x004010e4  83c8ff           or eax,0xffffffff
        .text:0x004010e7  e9d9010000       jmp 0x004012c5
        .text:0x004010ec  loc_004010ec: [1 XREFS]
        .text:0x004010ec  8b55f0           mov edx,dword [ebp - 16]
        .text:0x004010ef  52               push edx
        .text:0x004010f0  6a00             push 0
        .text:0x004010f2  6a00             push 0
        .text:0x004010f4  6a06             push 6
        .text:0x004010f6  8b45f4           mov eax,dword [ebp - 12]
        .text:0x004010f9  50               push eax
        .text:0x004010fa  ff1508804000     call dword [0x00408008]    ;kernel32.MapViewOfFile(kernel32.CreateFileMappingA(<0x00401095>,0,4,0,<0x004010b2>,0),6,0,0,<0x004010b2>)
        .text:0x00401100  8945fc           mov dword [ebp - 4],eax
        .text:0x00401103  837dfc00         cmp dword [ebp - 4],0
        .text:0x00401107  7526             jnz 0x0040112f
        .text:0x00401109  8b4dd4           mov ecx,dword [ebp - 44]
        .text:0x0040110c  51               push ecx
        .text:0x0040110d  ff150c804000     call dword [0x0040800c]    ;kernel32.CloseHandle(<0x00401095>)
        .text:0x00401113  8b55f4           mov edx,dword [ebp - 12]
        .text:0x00401116  52               push edx
        .text:0x00401117  ff150c804000     call dword [0x0040800c]    ;kernel32.CloseHandle(<0x004010cb>)
        .text:0x0040111d  8b45fc           mov eax,dword [ebp - 4]
        .text:0x00401120  50               push eax
        .text:0x00401121  ff1504804000     call dword [0x00408004]    ;kernel32.UnmapViewOfFile(<0x004010fa>)
        .text:0x00401127  83c8ff           or eax,0xffffffff
        .text:0x0040112a  e996010000       jmp 0x004012c5
        .text:0x0040112f  loc_0040112f: [1 XREFS]
        .text:0x0040112f  8b4dfc           mov ecx,dword [ebp - 4]
        .text:0x00401132  894de8           mov dword [ebp - 24],ecx
        .text:0x00401135  8b55e8           mov edx,dword [ebp - 24]
        .text:0x00401138  8b45fc           mov eax,dword [ebp - 4]
        .text:0x0040113b  03423c           add eax,dword [edx + 60]
        .text:0x0040113e  8945dc           mov dword [ebp - 36],eax
        .text:0x00401141  8b4ddc           mov ecx,dword [ebp - 36]
        .text:0x00401144  33d2             xor edx,edx
        .text:0x00401146  668b5114         mov dx,word [ecx + 20]
        .text:0x0040114a  8b45dc           mov eax,dword [ebp - 36]
        .text:0x0040114d  8d4c1018         lea ecx,dword [eax + edx + 24]
        .text:0x00401151  894df8           mov dword [ebp - 8],ecx
        .text:0x00401154  8b55dc           mov edx,dword [ebp - 36]
        .text:0x00401157  33c0             xor eax,eax
        .text:0x00401159  668b4206         mov ax,word [edx + 6]
        .text:0x0040115d  50               push eax
        .text:0x0040115e  8b4df8           mov ecx,dword [ebp - 8]
        .text:0x00401161  51               push ecx
        .text:0x00401162  e899feffff       call 0x00401000    ;sub_00401000(0xa2bc12e9,0x00006161)
        .text:0x00401167  83c408           add esp,8
        .text:0x0040116a  8945ec           mov dword [ebp - 20],eax
        .text:0x0040116d  837dec00         cmp dword [ebp - 20],0
        .text:0x00401171  7526             jnz 0x00401199
        .text:0x00401173  8b55d4           mov edx,dword [ebp - 44]
        .text:0x00401176  52               push edx
        .text:0x00401177  ff150c804000     call dword [0x0040800c]    ;kernel32.CloseHandle(<0x00401095>)
        .text:0x0040117d  8b45f4           mov eax,dword [ebp - 12]
        .text:0x00401180  50               push eax
        .text:0x00401181  ff150c804000     call dword [0x0040800c]    ;kernel32.CloseHandle(<0x004010cb>)
        .text:0x00401187  8b4dfc           mov ecx,dword [ebp - 4]
        .text:0x0040118a  51               push ecx
        .text:0x0040118b  ff1504804000     call dword [0x00408004]    ;kernel32.UnmapViewOfFile(<0x004010fa>)
        .text:0x00401191  83c8ff           or eax,0xffffffff
        .text:0x00401194  e92c010000       jmp 0x004012c5
        .text:0x00401199  loc_00401199: [1 XREFS]
        .text:0x00401199  8b55dc           mov edx,dword [ebp - 36]
        .text:0x0040119c  837a2800         cmp dword [edx + 40],0
        .text:0x004011a0  7508             jnz 0x004011aa
        .text:0x004011a2  83c8ff           or eax,0xffffffff
        .text:0x004011a5  e91b010000       jmp 0x004012c5
        .text:0x004011aa  loc_004011aa: [1 XREFS]
        .text:0x004011aa  8b45ec           mov eax,dword [ebp - 20]
        .text:0x004011ad  8178103a010000   cmp dword [eax + 16],314
        .text:0x004011b4  7708             ja 0x004011be
        .text:0x004011b6  83c8ff           or eax,0xffffffff
        .text:0x004011b9  e907010000       jmp 0x004012c5
        .text:0x004011be  loc_004011be: [1 XREFS]
        .text:0x004011be  8b4dec           mov ecx,dword [ebp - 20]
        .text:0x004011c1  8b55ec           mov edx,dword [ebp - 20]
        .text:0x004011c4  8b4110           mov eax,dword [ecx + 16]
        .text:0x004011c7  2b4208           sub eax,dword [edx + 8]
        .text:0x004011ca  8945e4           mov dword [ebp - 28],eax
        .text:0x004011cd  817de43a010000   cmp dword [ebp - 28],314
        .text:0x004011d4  7308             jnc 0x004011de
        .text:0x004011d6  83c8ff           or eax,0xffffffff
        .text:0x004011d9  e9e7000000       jmp 0x004012c5
        .text:0x004011de  loc_004011de: [1 XREFS]
        .text:0x004011de  8b4dec           mov ecx,dword [ebp - 20]
        .text:0x004011e1  8b5114           mov edx,dword [ecx + 20]
        .text:0x004011e4  8b45ec           mov eax,dword [ebp - 20]
        .text:0x004011e7  035008           add edx,dword [eax + 8]
        .text:0x004011ea  8955d8           mov dword [ebp - 40],edx
        .text:0x004011ed  c745e000000000   mov dword [ebp - 32],0
        .text:0x004011f4  eb09             jmp 0x004011ff
        .text:0x004011f6  loc_004011f6: [1 XREFS]
        .text:0x004011f6  8b4de0           mov ecx,dword [ebp - 32]
        .text:0x004011f9  83c101           add ecx,1
        .text:0x004011fc  894de0           mov dword [ebp - 32],ecx
        .text:0x004011ff  loc_004011ff: [1 XREFS]
        .text:0x004011ff  817de03a010000   cmp dword [ebp - 32],314
        .text:0x00401206  7374             jnc 0x0040127c
        .text:0x00401208  8b55e0           mov edx,dword [ebp - 32]
        .text:0x0040120b  33c0             xor eax,eax
        .text:0x0040120d  8a8230904000     mov al,byte [edx + 0x00409030]
        .text:0x00401213  83f878           cmp eax,120
        .text:0x00401216  755f             jnz 0x00401277
        .text:0x00401218  8b4de0           mov ecx,dword [ebp - 32]
        .text:0x0040121b  33d2             xor edx,edx
        .text:0x0040121d  8a9131904000     mov dl,byte [ecx + 0x00409031]
        .text:0x00401223  83fa56           cmp edx,86
        .text:0x00401226  754f             jnz 0x00401277
        .text:0x00401228  8b45e0           mov eax,dword [ebp - 32]
        .text:0x0040122b  33c9             xor ecx,ecx
        .text:0x0040122d  8a8832904000     mov cl,byte [eax + 0x00409032]
        .text:0x00401233  83f934           cmp ecx,52
        .text:0x00401236  753f             jnz 0x00401277
        .text:0x00401238  8b55e0           mov edx,dword [ebp - 32]
        .text:0x0040123b  33c0             xor eax,eax
        .text:0x0040123d  8a8233904000     mov al,byte [edx + 0x00409033]
        .text:0x00401243  83f812           cmp eax,18
        .text:0x00401246  752f             jnz 0x00401277
        .text:0x00401248  8b4ddc           mov ecx,dword [ebp - 36]
        .text:0x0040124b  8b5128           mov edx,dword [ecx + 40]
        .text:0x0040124e  8b45ec           mov eax,dword [ebp - 20]
        .text:0x00401251  035014           add edx,dword [eax + 20]
        .text:0x00401254  8b4ddc           mov ecx,dword [ebp - 36]
        .text:0x00401257  2b512c           sub edx,dword [ecx + 44]
        .text:0x0040125a  8b45e0           mov eax,dword [ebp - 32]
        .text:0x0040125d  8b4dd8           mov ecx,dword [ebp - 40]
        .text:0x00401260  8d440104         lea eax,dword [ecx + eax + 4]
        .text:0x00401264  2bd0             sub edx,eax
        .text:0x00401266  8955d0           mov dword [ebp - 48],edx
        .text:0x00401269  8b4de0           mov ecx,dword [ebp - 32]
        .text:0x0040126c  8b55d0           mov edx,dword [ebp - 48]
        .text:0x0040126f  899130904000     mov dword [ecx + 0x00409030],edx
        .text:0x00401275  eb05             jmp 0x0040127c
        .text:0x00401277  loc_00401277: [4 XREFS]
        .text:0x00401277  e97affffff       jmp 0x004011f6
        .text:0x0040127c  loc_0040127c: [2 XREFS]
        .text:0x0040127c  8b7dfc           mov edi,dword [ebp - 4]
        .text:0x0040127f  037dd8           add edi,dword [ebp - 40]
        .text:0x00401282  b94e000000       mov ecx,78
        .text:0x00401287  be30904000       mov esi,0x00409030
        .text:0x0040128c  f3a5             rep: movsd 
        .text:0x0040128e  66a5             movsd 
        .text:0x00401290  8b45ec           mov eax,dword [ebp - 20]
        .text:0x00401293  8b4dd8           mov ecx,dword [ebp - 40]
        .text:0x00401296  2b4814           sub ecx,dword [eax + 20]
        .text:0x00401299  8b55dc           mov edx,dword [ebp - 36]
        .text:0x0040129c  034a2c           add ecx,dword [edx + 44]
        .text:0x0040129f  8b45dc           mov eax,dword [ebp - 36]
        .text:0x004012a2  894828           mov dword [eax + 40],ecx
        .text:0x004012a5  8b4dd4           mov ecx,dword [ebp - 44]
        .text:0x004012a8  51               push ecx
        .text:0x004012a9  ff150c804000     call dword [0x0040800c]    ;kernel32.CloseHandle(<0x00401095>)
        .text:0x004012af  8b55f4           mov edx,dword [ebp - 12]
        .text:0x004012b2  52               push edx
        .text:0x004012b3  ff150c804000     call dword [0x0040800c]    ;kernel32.CloseHandle(<0x004010cb>)
        .text:0x004012b9  8b45fc           mov eax,dword [ebp - 4]
        .text:0x004012bc  50               push eax
        .text:0x004012bd  ff1504804000     call dword [0x00408004]    ;kernel32.UnmapViewOfFile(kernel32.MapViewOfFile(<0x004010cb>,6,0,0,<0x004010b2>))
        .text:0x004012c3  33c0             xor eax,eax
        .text:0x004012c5  loc_004012c5: [7 XREFS]
        .text:0x004012c5  5f               pop edi
        .text:0x004012c6  5e               pop esi
        .text:0x004012c7  8be5             mov esp,ebp
        .text:0x004012c9  5d               pop ebp
        .text:0x004012ca  c3               ret 
        */
        $c1 = { 55 8B EC 83 EC 30 56 57 C7 45 ?? 00 00 00 00 6A 00 68 80 00 00 00 6A 04 6A 00 6A 01 68 00 00 00 C0 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? FF 75 ?? 83 C8 FF E9 ?? ?? ?? ?? 6A 00 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 45 ?? 6A 00 8B 55 ?? 52 6A 00 6A 04 6A 00 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? FF 75 ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 83 C8 FF E9 ?? ?? ?? ?? 8B 55 ?? 52 6A 00 6A 00 6A 06 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 00 75 ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 83 C8 FF E9 ?? ?? ?? ?? 8B 4D ?? 89 4D ?? 8B 55 ?? 8B 45 ?? 03 42 ?? 89 45 ?? 8B 4D ?? 33 D2 66 8B 51 ?? 8B 45 ?? 8D 4C 10 ?? 89 4D ?? 8B 55 ?? 33 C0 66 8B 42 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 08 89 45 ?? 83 7D ?? 00 75 ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 83 C8 FF E9 ?? ?? ?? ?? 8B 55 ?? 83 7A ?? 00 75 ?? 83 C8 FF E9 ?? ?? ?? ?? 8B 45 ?? 81 78 ?? 3A 01 00 00 77 ?? 83 C8 FF E9 ?? ?? ?? ?? 8B 4D ?? 8B 55 ?? 8B 41 ?? 2B 42 ?? 89 45 ?? 81 7D ?? 3A 01 00 00 73 ?? 83 C8 FF E9 ?? ?? ?? ?? 8B 4D ?? 8B 51 ?? 8B 45 ?? 03 50 ?? 89 55 ?? C7 45 ?? 00 00 00 00 EB ?? 8B 4D ?? 83 C1 01 89 4D ?? 81 7D ?? 3A 01 00 00 73 ?? 8B 55 ?? 33 C0 8A 82 ?? ?? ?? ?? 83 F8 78 75 ?? 8B 4D ?? 33 D2 8A 91 ?? ?? ?? ?? 83 FA 56 75 ?? 8B 45 ?? 33 C9 8A 88 ?? ?? ?? ?? 83 F9 34 75 ?? 8B 55 ?? 33 C0 8A 82 ?? ?? ?? ?? 83 F8 12 75 ?? 8B 4D ?? 8B 51 ?? 8B 45 ?? 03 50 ?? 8B 4D ?? 2B 51 ?? 8B 45 ?? 8B 4D ?? 8D 44 01 ?? 2B D0 89 55 ?? 8B 4D ?? 8B 55 ?? 89 91 ?? ?? ?? ?? EB ?? E9 ?? ?? ?? ?? 8B 7D ?? 03 7D ?? B9 4E 00 00 00 BE 30 90 40 00 F3 A5 66 A5 8B 45 ?? 8B 4D ?? 2B 48 ?? 8B 55 ?? 03 4A ?? 8B 45 ?? 89 48 ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 33 C0 5F 5E 8B E5 5D C3 }
    condition:
        all of them
}

rule super_rule_7faaf
{
    meta:
        author = "CAPA Matches"
        date_created = "EXPECTED_DATE"
        date_modified = "EXPECTED_DATE"
        description = ""
        md5 = "7faafc7e4a5c736ebfee6abbbc812d80"
    strings:
        /*
Basic Block at 0x00401100@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x00401100  
        .text:0x00401100  FUNC: int cdecl sub_00401100( ) [2 XREFS] 
        .text:0x00401100  
        .text:0x00401100  Stack Variables: (offset from initial top of stack)
        .text:0x00401100            -8: int local8
        .text:0x00401100           -12: int local12
        .text:0x00401100           -16: int local16
        .text:0x00401100           -20: int local20
        .text:0x00401100           -24: int local24
        .text:0x00401100  
        .text:0x00401100  55               push ebp
        .text:0x00401101  8bec             mov ebp,esp
        .text:0x00401103  83ec14           sub esp,20
        .text:0x00401106  53               push ebx
        .text:0x00401107  56               push esi
        .text:0x00401108  57               push edi
        .text:0x00401109  c745f000000000   mov dword [ebp - 16],0
        .text:0x00401110  c745ec00000000   mov dword [ebp - 20],0
        .text:0x00401117  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040111d  8a5802           mov bl,byte [eax + 2]
        .text:0x00401120  885df4           mov byte [ebp - 12],bl
        .text:0x00401123  0fbe45f4         movsx eax,byte [ebp - 12]
        .text:0x00401127  85c0             test eax,eax
        .text:0x00401129  7405             jz 0x00401130
        */
        $c2 = { 55 8B EC 83 EC 14 53 56 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 5D ?? 0F BE 45 ?? 85 C0 74 ?? }
        /*
Basic Block at 0x004011d0@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x004011d0  
        .text:0x004011d0  FUNC: int cdecl sub_004011d0( int arg0, int arg1, int arg2, int arg3, ) [6 XREFS] 
        .text:0x004011d0  
        .text:0x004011d0  Stack Variables: (offset from initial top of stack)
        .text:0x004011d0            16: int arg3
        .text:0x004011d0            12: int arg2
        .text:0x004011d0             8: int arg1
        .text:0x004011d0             4: int arg0
        .text:0x004011d0            -8: int local8
        .text:0x004011d0          -4108: int local4108
        .text:0x004011d0          -4112: int local4112
        .text:0x004011d0          -4116: int local4116
        .text:0x004011d0          -4120: int local4120
        .text:0x004011d0          -4124: int local4124
        .text:0x004011d0  
        .text:0x004011d0  55               push ebp
        .text:0x004011d1  8bec             mov ebp,esp
        .text:0x004011d3  b818100000       mov eax,0x00001018
        .text:0x004011d8  e893270000       call 0x00403970    ;__alloca_probe()
        .text:0x004011dd  53               push ebx
        .text:0x004011de  56               push esi
        .text:0x004011df  57               push edi
        .text:0x004011e0  c785ecefffff0000 mov dword [ebp - 4116],0
        .text:0x004011ea  c785e8efffff0000 mov dword [ebp - 4120],0
        .text:0x004011f4  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004011fa  8a5802           mov bl,byte [eax + 2]
        .text:0x004011fd  889df0efffff     mov byte [ebp - 4112],bl
        .text:0x00401203  0fbe85f0efffff   movsx eax,byte [ebp - 4112]
        .text:0x0040120a  85c0             test eax,eax
        .text:0x0040120c  7405             jz 0x00401213
        */
        $c3 = { 55 8B EC B8 18 10 00 00 E8 ?? ?? ?? ?? 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x004014b0@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x004014b0  
        .text:0x004014b0  FUNC: int cdecl sub_004014b0( int arg0, int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, ) [8 XREFS] 
        .text:0x004014b0  
        .text:0x004014b0  Stack Variables: (offset from initial top of stack)
        .text:0x004014b0            28: int arg6
        .text:0x004014b0            24: int arg5
        .text:0x004014b0            20: int arg4
        .text:0x004014b0            16: int arg3
        .text:0x004014b0            12: int arg2
        .text:0x004014b0             8: int arg1
        .text:0x004014b0             4: int arg0
        .text:0x004014b0            -8: int local8
        .text:0x004014b0           -12: int local12
        .text:0x004014b0          -4108: int local4108
        .text:0x004014b0          -4112: int local4112
        .text:0x004014b0          -4116: int local4116
        .text:0x004014b0          -4120: int local4120
        .text:0x004014b0          -4124: int local4124
        .text:0x004014b0          -4128: int local4128
        .text:0x004014b0  
        .text:0x004014b0  55               push ebp
        .text:0x004014b1  8bec             mov ebp,esp
        .text:0x004014b3  b81c100000       mov eax,0x0000101c
        .text:0x004014b8  e8b3240000       call 0x00403970    ;__alloca_probe()
        .text:0x004014bd  53               push ebx
        .text:0x004014be  56               push esi
        .text:0x004014bf  57               push edi
        .text:0x004014c0  c785e8efffff0000 mov dword [ebp - 4120],0
        .text:0x004014ca  c785e4efffff0000 mov dword [ebp - 4124],0
        .text:0x004014d4  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004014da  8a5802           mov bl,byte [eax + 2]
        .text:0x004014dd  889decefffff     mov byte [ebp - 4116],bl
        .text:0x004014e3  0fbe85ecefffff   movsx eax,byte [ebp - 4116]
        .text:0x004014ea  85c0             test eax,eax
        .text:0x004014ec  7405             jz 0x004014f3
        */
        $c4 = { 55 8B EC B8 1C 10 00 00 E8 ?? ?? ?? ?? 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x004016c0@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x004016c0  
        .text:0x004016c0  FUNC: int cdecl sub_004016c0( int arg0, int arg1, ) [2 XREFS] 
        .text:0x004016c0  
        .text:0x004016c0  Stack Variables: (offset from initial top of stack)
        .text:0x004016c0             8: int arg1
        .text:0x004016c0             4: int arg0
        .text:0x004016c0          -1028: int local1028
        .text:0x004016c0          -2052: int local2052
        .text:0x004016c0          -3076: int local3076
        .text:0x004016c0          -3080: int local3080
        .text:0x004016c0          -3084: int local3084
        .text:0x004016c0          -3088: int local3088
        .text:0x004016c0  
        .text:0x004016c0  55               push ebp
        .text:0x004016c1  8bec             mov ebp,esp
        .text:0x004016c3  81ec0c0c0000     sub esp,3084
        .text:0x004016c9  53               push ebx
        .text:0x004016ca  56               push esi
        .text:0x004016cb  57               push edi
        .text:0x004016cc  c785f8f3ffff0000 mov dword [ebp - 3080],0
        .text:0x004016d6  c785f4f3ffff0000 mov dword [ebp - 3084],0
        .text:0x004016e0  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004016e6  8a5802           mov bl,byte [eax + 2]
        .text:0x004016e9  889dfcf3ffff     mov byte [ebp - 3076],bl
        .text:0x004016ef  0fbe85fcf3ffff   movsx eax,byte [ebp - 3076]
        .text:0x004016f6  85c0             test eax,eax
        .text:0x004016f8  7405             jz 0x004016ff
        */
        $c5 = { 55 8B EC 81 EC 0C 0C 00 00 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x00401790@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x00401790  
        .text:0x00401790  FUNC: int cdecl sub_00401790( int arg0, ) [2 XREFS] 
        .text:0x00401790  
        .text:0x00401790  Stack Variables: (offset from initial top of stack)
        .text:0x00401790             4: int arg0
        .text:0x00401790          -1028: int local1028
        .text:0x00401790          -2052: int local2052
        .text:0x00401790          -3076: int local3076
        .text:0x00401790          -4100: int local4100
        .text:0x00401790          -4104: int local4104
        .text:0x00401790          -4108: int local4108
        .text:0x00401790          -4112: int local4112
        .text:0x00401790  
        .text:0x00401790  55               push ebp
        .text:0x00401791  8bec             mov ebp,esp
        .text:0x00401793  b80c100000       mov eax,0x0000100c
        .text:0x00401798  e8d3210000       call 0x00403970    ;__alloca_probe()
        .text:0x0040179d  53               push ebx
        .text:0x0040179e  56               push esi
        .text:0x0040179f  57               push edi
        .text:0x004017a0  c785f8efffff0000 mov dword [ebp - 4104],0
        .text:0x004017aa  c785f4efffff0000 mov dword [ebp - 4108],0
        .text:0x004017b4  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004017ba  8a5802           mov bl,byte [eax + 2]
        .text:0x004017bd  889dfcefffff     mov byte [ebp - 4100],bl
        .text:0x004017c3  0fbe85fcefffff   movsx eax,byte [ebp - 4100]
        .text:0x004017ca  85c0             test eax,eax
        .text:0x004017cc  7405             jz 0x004017d3
        */
        $c6 = { 55 8B EC B8 0C 10 00 00 E8 ?? ?? ?? ?? 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x00401880@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x00401880  
        .text:0x00401880  FUNC: int cdecl sub_00401880( int arg0, int arg1, ) [2 XREFS] 
        .text:0x00401880  
        .text:0x00401880  Stack Variables: (offset from initial top of stack)
        .text:0x00401880             8: int arg1
        .text:0x00401880             4: int arg0
        .text:0x00401880           -12: int local12
        .text:0x00401880           -20: int local20
        .text:0x00401880           -28: int local28
        .text:0x00401880           -32: int local32
        .text:0x00401880           -36: int local36
        .text:0x00401880           -40: int local40
        .text:0x00401880           -44: int local44
        .text:0x00401880  
        .text:0x00401880  55               push ebp
        .text:0x00401881  8bec             mov ebp,esp
        .text:0x00401883  83ec28           sub esp,40
        .text:0x00401886  53               push ebx
        .text:0x00401887  56               push esi
        .text:0x00401888  57               push edi
        .text:0x00401889  c745dc00000000   mov dword [ebp - 36],0
        .text:0x00401890  c745d800000000   mov dword [ebp - 40],0
        .text:0x00401897  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040189d  8a5802           mov bl,byte [eax + 2]
        .text:0x004018a0  885de0           mov byte [ebp - 32],bl
        .text:0x004018a3  0fbe45e0         movsx eax,byte [ebp - 32]
        .text:0x004018a7  85c0             test eax,eax
        .text:0x004018a9  7405             jz 0x004018b0
        */
        $c7 = { 55 8B EC 83 EC 28 53 56 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 5D ?? 0F BE 45 ?? 85 C0 74 ?? }
        /*
Basic Block at 0x004019b0@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x004019b0  
        .text:0x004019b0  FUNC: int cdecl sub_004019b0( int arg0, ) [4 XREFS] 
        .text:0x004019b0  
        .text:0x004019b0  Stack Variables: (offset from initial top of stack)
        .text:0x004019b0             4: int arg0
        .text:0x004019b0          -1028: int local1028
        .text:0x004019b0          -1032: int local1032
        .text:0x004019b0          -1036: int local1036
        .text:0x004019b0          -1040: int local1040
        .text:0x004019b0  
        .text:0x004019b0  55               push ebp
        .text:0x004019b1  8bec             mov ebp,esp
        .text:0x004019b3  81ec0c040000     sub esp,1036
        .text:0x004019b9  53               push ebx
        .text:0x004019ba  56               push esi
        .text:0x004019bb  57               push edi
        .text:0x004019bc  c785f8fbffff0000 mov dword [ebp - 1032],0
        .text:0x004019c6  c785f4fbffff0000 mov dword [ebp - 1036],0
        .text:0x004019d0  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004019d6  8a5802           mov bl,byte [eax + 2]
        .text:0x004019d9  889dfcfbffff     mov byte [ebp - 1028],bl
        .text:0x004019df  0fbe85fcfbffff   movsx eax,byte [ebp - 1028]
        .text:0x004019e6  85c0             test eax,eax
        .text:0x004019e8  7405             jz 0x004019ef
        */
        $c8 = { 55 8B EC 81 EC 0C 04 00 00 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x00401ab0@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x00401ab0  
        .text:0x00401ab0  FUNC: int cdecl sub_00401ab0( int arg0, int arg1, int arg2, ) [8 XREFS] 
        .text:0x00401ab0  
        .text:0x00401ab0  Stack Variables: (offset from initial top of stack)
        .text:0x00401ab0            12: int arg2
        .text:0x00401ab0             8: int arg1
        .text:0x00401ab0             4: int arg0
        .text:0x00401ab0          -404: int local404
        .text:0x00401ab0          -408: int local408
        .text:0x00401ab0          -420: int local420
        .text:0x00401ab0          -422: int local422
        .text:0x00401ab0          -424: int local424
        .text:0x00401ab0          -428: int local428
        .text:0x00401ab0          -432: int local432
        .text:0x00401ab0          -436: int local436
        .text:0x00401ab0  
        .text:0x00401ab0  55               push ebp
        .text:0x00401ab1  8bec             mov ebp,esp
        .text:0x00401ab3  81ecb0010000     sub esp,432
        .text:0x00401ab9  53               push ebx
        .text:0x00401aba  56               push esi
        .text:0x00401abb  57               push edi
        .text:0x00401abc  c78554feffff0000 mov dword [ebp - 428],0
        .text:0x00401ac6  c78550feffff0000 mov dword [ebp - 432],0
        .text:0x00401ad0  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401ad6  8a5802           mov bl,byte [eax + 2]
        .text:0x00401ad9  889d58feffff     mov byte [ebp - 424],bl
        .text:0x00401adf  0fbe8558feffff   movsx eax,byte [ebp - 424]
        .text:0x00401ae6  85c0             test eax,eax
        .text:0x00401ae8  7405             jz 0x00401aef
        */
        $c9 = { 55 8B EC 81 EC B0 01 00 00 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x00401c20@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x00401c20  
        .text:0x00401c20  FUNC: int cdecl sub_00401c20( int arg0, ) [24 XREFS] 
        .text:0x00401c20  
        .text:0x00401c20  Stack Variables: (offset from initial top of stack)
        .text:0x00401c20             4: int arg0
        .text:0x00401c20            -8: int local8
        .text:0x00401c20           -12: int local12
        .text:0x00401c20           -16: int local16
        .text:0x00401c20  
        .text:0x00401c20  55               push ebp
        .text:0x00401c21  8bec             mov ebp,esp
        .text:0x00401c23  83ec0c           sub esp,12
        .text:0x00401c26  53               push ebx
        .text:0x00401c27  56               push esi
        .text:0x00401c28  57               push edi
        .text:0x00401c29  c745f800000000   mov dword [ebp - 8],0
        .text:0x00401c30  c745f400000000   mov dword [ebp - 12],0
        .text:0x00401c37  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401c3d  8a5802           mov bl,byte [eax + 2]
        .text:0x00401c40  885dfc           mov byte [ebp - 4],bl
        .text:0x00401c43  0fbe45fc         movsx eax,byte [ebp - 4]
        .text:0x00401c47  85c0             test eax,eax
        .text:0x00401c49  7405             jz 0x00401c50
        */
        $c10 = { 55 8B EC 83 EC 0C 53 56 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 5D ?? 0F BE 45 ?? 85 C0 74 ?? }
        /*
Basic Block at 0x00401cd0@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x00401cd0  
        .text:0x00401cd0  FUNC: int cdecl sub_00401cd0( int arg0, int arg1, int arg2, ) [2 XREFS] 
        .text:0x00401cd0  
        .text:0x00401cd0  Stack Variables: (offset from initial top of stack)
        .text:0x00401cd0            12: int arg2
        .text:0x00401cd0             8: int arg1
        .text:0x00401cd0             4: int arg0
        .text:0x00401cd0            -8: int local8
        .text:0x00401cd0           -12: int local12
        .text:0x00401cd0          -524: int local524
        .text:0x00401cd0          -528: int local528
        .text:0x00401cd0          -532: int local532
        .text:0x00401cd0          -536: int local536
        .text:0x00401cd0          -540: int local540
        .text:0x00401cd0          -544: int local544
        .text:0x00401cd0  
        .text:0x00401cd0  55               push ebp
        .text:0x00401cd1  8bec             mov ebp,esp
        .text:0x00401cd3  81ec1c020000     sub esp,540
        .text:0x00401cd9  53               push ebx
        .text:0x00401cda  56               push esi
        .text:0x00401cdb  57               push edi
        .text:0x00401cdc  c745fc00000000   mov dword [ebp - 4],0
        .text:0x00401ce3  c785e8fdffff0000 mov dword [ebp - 536],0
        .text:0x00401ced  c785e4fdffff0000 mov dword [ebp - 540],0
        .text:0x00401cf7  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401cfd  8a5802           mov bl,byte [eax + 2]
        .text:0x00401d00  889decfdffff     mov byte [ebp - 532],bl
        .text:0x00401d06  0fbe85ecfdffff   movsx eax,byte [ebp - 532]
        .text:0x00401d0d  85c0             test eax,eax
        .text:0x00401d0f  7405             jz 0x00401d16
        */
        $c11 = { 55 8B EC 81 EC 1C 02 00 00 53 56 57 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x00401e30@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x00401e30  
        .text:0x00401e30  FUNC: int cdecl sub_00401e30( int arg0, int arg1, int arg2, ) [2 XREFS] 
        .text:0x00401e30  
        .text:0x00401e30  Stack Variables: (offset from initial top of stack)
        .text:0x00401e30            12: int arg2
        .text:0x00401e30             8: int arg1
        .text:0x00401e30             4: int arg0
        .text:0x00401e30            -8: int local8
        .text:0x00401e30           -12: int local12
        .text:0x00401e30          -524: int local524
        .text:0x00401e30          -528: int local528
        .text:0x00401e30          -532: int local532
        .text:0x00401e30          -536: int local536
        .text:0x00401e30          -540: int local540
        .text:0x00401e30          -544: int local544
        .text:0x00401e30          -548: int local548
        .text:0x00401e30  
        .text:0x00401e30  55               push ebp
        .text:0x00401e31  8bec             mov ebp,esp
        .text:0x00401e33  81ec20020000     sub esp,544
        .text:0x00401e39  53               push ebx
        .text:0x00401e3a  56               push esi
        .text:0x00401e3b  57               push edi
        .text:0x00401e3c  c745fc00000000   mov dword [ebp - 4],0
        .text:0x00401e43  c785e4fdffff0000 mov dword [ebp - 540],0
        .text:0x00401e4d  c785e0fdffff0000 mov dword [ebp - 544],0
        .text:0x00401e57  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401e5d  8a5802           mov bl,byte [eax + 2]
        .text:0x00401e60  889de8fdffff     mov byte [ebp - 536],bl
        .text:0x00401e66  0fbe85e8fdffff   movsx eax,byte [ebp - 536]
        .text:0x00401e6d  85c0             test eax,eax
        .text:0x00401e6f  7405             jz 0x00401e76
        */
        $c12 = { 55 8B EC 81 EC 20 02 00 00 53 56 57 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x00402020@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x00402020  
        .text:0x00402020  FUNC: int cdecl sub_00402020( int arg0, int arg1, int arg2, ) [2 XREFS] 
        .text:0x00402020  
        .text:0x00402020  Stack Variables: (offset from initial top of stack)
        .text:0x00402020            12: int arg2
        .text:0x00402020             8: int arg1
        .text:0x00402020             4: int arg0
        .text:0x00402020            -8: int local8
        .text:0x00402020           -12: int local12
        .text:0x00402020          -524: int local524
        .text:0x00402020          -528: int local528
        .text:0x00402020          -532: int local532
        .text:0x00402020          -536: int local536
        .text:0x00402020          -540: int local540
        .text:0x00402020  
        .text:0x00402020  55               push ebp
        .text:0x00402021  8bec             mov ebp,esp
        .text:0x00402023  81ec18020000     sub esp,536
        .text:0x00402029  53               push ebx
        .text:0x0040202a  56               push esi
        .text:0x0040202b  57               push edi
        .text:0x0040202c  c745f800000000   mov dword [ebp - 8],0
        .text:0x00402033  c785ecfdffff0000 mov dword [ebp - 532],0
        .text:0x0040203d  c785e8fdffff0000 mov dword [ebp - 536],0
        .text:0x00402047  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040204d  8a5802           mov bl,byte [eax + 2]
        .text:0x00402050  889df0fdffff     mov byte [ebp - 528],bl
        .text:0x00402056  0fbe85f0fdffff   movsx eax,byte [ebp - 528]
        .text:0x0040205d  85c0             test eax,eax
        .text:0x0040205f  7405             jz 0x00402066
        */
        $c13 = { 55 8B EC 81 EC 18 02 00 00 53 56 57 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x004021b0@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x004021b0  
        .text:0x004021b0  FUNC: int cdecl sub_004021b0( int arg0, int arg1, int arg2, int arg3, int arg4, ) [2 XREFS] 
        .text:0x004021b0  
        .text:0x004021b0  Stack Variables: (offset from initial top of stack)
        .text:0x004021b0            20: int arg4
        .text:0x004021b0            16: int arg3
        .text:0x004021b0            12: int arg2
        .text:0x004021b0             8: int arg1
        .text:0x004021b0             4: int arg0
        .text:0x004021b0            -8: int local8
        .text:0x004021b0          -1032: int local1032
        .text:0x004021b0          -1036: int local1036
        .text:0x004021b0          -1040: int local1040
        .text:0x004021b0          -1552: int local1552
        .text:0x004021b0          -1556: int local1556
        .text:0x004021b0          -1560: int local1560
        .text:0x004021b0          -1564: int local1564
        .text:0x004021b0          -1568: int local1568
        .text:0x004021b0  
        .text:0x004021b0  55               push ebp
        .text:0x004021b1  8bec             mov ebp,esp
        .text:0x004021b3  81ec1c060000     sub esp,1564
        .text:0x004021b9  53               push ebx
        .text:0x004021ba  56               push esi
        .text:0x004021bb  57               push edi
        .text:0x004021bc  c785f4fbffff0000 mov dword [ebp - 1036],0
        .text:0x004021c6  c785f8fbffff0000 mov dword [ebp - 1032],0
        .text:0x004021d0  c785e8f9ffff0000 mov dword [ebp - 1560],0
        .text:0x004021da  c785e4f9ffff0000 mov dword [ebp - 1564],0
        .text:0x004021e4  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004021ea  8a5802           mov bl,byte [eax + 2]
        .text:0x004021ed  889decf9ffff     mov byte [ebp - 1556],bl
        .text:0x004021f3  0fbe85ecf9ffff   movsx eax,byte [ebp - 1556]
        .text:0x004021fa  85c0             test eax,eax
        .text:0x004021fc  7405             jz 0x00402203
        */
        $c14 = { 55 8B EC 81 EC 1C 06 00 00 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x00402440@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x00402440  
        .text:0x00402440  FUNC: int cdecl sub_00402440( ) [6 XREFS] 
        .text:0x00402440  
        .text:0x00402440  Stack Variables: (offset from initial top of stack)
        .text:0x00402440            -8: int local8
        .text:0x00402440           -12: int local12
        .text:0x00402440           -16: int local16
        .text:0x00402440           -20: int local20
        .text:0x00402440  
        .text:0x00402440  55               push ebp
        .text:0x00402441  8bec             mov ebp,esp
        .text:0x00402443  83ec10           sub esp,16
        .text:0x00402446  53               push ebx
        .text:0x00402447  56               push esi
        .text:0x00402448  57               push edi
        .text:0x00402449  c745f400000000   mov dword [ebp - 12],0
        .text:0x00402450  c745f000000000   mov dword [ebp - 16],0
        .text:0x00402457  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040245d  8a5802           mov bl,byte [eax + 2]
        .text:0x00402460  885df8           mov byte [ebp - 8],bl
        .text:0x00402463  0fbe45f8         movsx eax,byte [ebp - 8]
        .text:0x00402467  85c0             test eax,eax
        .text:0x00402469  7405             jz 0x00402470
        */
        $c15 = { 55 8B EC 83 EC 10 53 56 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 5D ?? 0F BE 45 ?? 85 C0 74 ?? }
        /*
Basic Block at 0x00402650@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x00402650  
        .text:0x00402650  FUNC: int cdecl sub_00402650( int arg0, int arg1, ) [2 XREFS] 
        .text:0x00402650  
        .text:0x00402650  Stack Variables: (offset from initial top of stack)
        .text:0x00402650             8: int arg1
        .text:0x00402650             4: int arg0
        .text:0x00402650          -4100: int local4100
        .text:0x00402650          -4104: int local4104
        .text:0x00402650          -4120: int local4120
        .text:0x00402650          -4124: int local4124
        .text:0x00402650          -4128: int local4128
        .text:0x00402650          -4132: int local4132
        .text:0x00402650          -5156: int local5156
        .text:0x00402650          -5160: int local5160
        .text:0x00402650          -5164: int local5164
        .text:0x00402650          -5168: int local5168
        .text:0x00402650          -5172: int local5172
        .text:0x00402650  
        .text:0x00402650  55               push ebp
        .text:0x00402651  8bec             mov ebp,esp
        .text:0x00402653  b830140000       mov eax,0x00001430
        .text:0x00402658  e813130000       call 0x00403970    ;__alloca_probe()
        .text:0x0040265d  53               push ebx
        .text:0x0040265e  56               push esi
        .text:0x0040265f  57               push edi
        .text:0x00402660  c785e4efffff0010 mov dword [ebp - 4124],0x00001000
        .text:0x0040266a  c785d4ebffff0000 mov dword [ebp - 5164],0
        .text:0x00402674  c785d0ebffff0000 mov dword [ebp - 5168],0
        .text:0x0040267e  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402684  8a5802           mov bl,byte [eax + 2]
        .text:0x00402687  889dd8ebffff     mov byte [ebp - 5160],bl
        .text:0x0040268d  0fbe85d8ebffff   movsx eax,byte [ebp - 5160]
        .text:0x00402694  85c0             test eax,eax
        .text:0x00402696  7405             jz 0x0040269d
        */
        $c16 = { 55 8B EC B8 30 14 00 00 E8 ?? ?? ?? ?? 53 56 57 C7 85 ?? ?? ?? ?? 00 10 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x00402880@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x00402880  
        .text:0x00402880  FUNC: int cdecl sub_00402880( int arg0, ) [2 XREFS] 
        .text:0x00402880  
        .text:0x00402880  Stack Variables: (offset from initial top of stack)
        .text:0x00402880             4: int arg0
        .text:0x00402880          -1028: int local1028
        .text:0x00402880          -1032: int local1032
        .text:0x00402880          -1036: int local1036
        .text:0x00402880          -1040: int local1040
        .text:0x00402880          -1044: int local1044
        .text:0x00402880          -1048: int local1048
        .text:0x00402880          -1052: int local1052
        .text:0x00402880          -1056: int local1056
        .text:0x00402880          -1060: int local1060
        .text:0x00402880          -1064: int local1064
        .text:0x00402880          -1068: int local1068
        .text:0x00402880          -1072: int local1072
        .text:0x00402880          -1076: int local1076
        .text:0x00402880  
        .text:0x00402880  55               push ebp
        .text:0x00402881  8bec             mov ebp,esp
        .text:0x00402883  81ec30040000     sub esp,1072
        .text:0x00402889  53               push ebx
        .text:0x0040288a  56               push esi
        .text:0x0040288b  57               push edi
        .text:0x0040288c  c785d4fbffff0000 mov dword [ebp - 1068],0
        .text:0x00402896  c785d0fbffff0000 mov dword [ebp - 1072],0
        .text:0x004028a0  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004028a6  8a5802           mov bl,byte [eax + 2]
        .text:0x004028a9  889dd8fbffff     mov byte [ebp - 1064],bl
        .text:0x004028af  0fbe85d8fbffff   movsx eax,byte [ebp - 1064]
        .text:0x004028b6  85c0             test eax,eax
        .text:0x004028b8  7405             jz 0x004028bf
        */
        $c17 = { 55 8B EC 81 EC 30 04 00 00 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x00402f40@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x00402f40  
        .text:0x00402f40  FUNC: int cdecl sub_00402f40( int arg0, ) [4 XREFS] 
        .text:0x00402f40  
        .text:0x00402f40  Stack Variables: (offset from initial top of stack)
        .text:0x00402f40             4: int arg0
        .text:0x00402f40          -1028: int local1028
        .text:0x00402f40          -1032: int local1032
        .text:0x00402f40          -2056: int local2056
        .text:0x00402f40          -3080: int local3080
        .text:0x00402f40          -4104: int local4104
        .text:0x00402f40          -5128: int local5128
        .text:0x00402f40          -5132: int local5132
        .text:0x00402f40          -5136: int local5136
        .text:0x00402f40          -5140: int local5140
        .text:0x00402f40          -5144: int local5144
        .text:0x00402f40  
        .text:0x00402f40  55               push ebp
        .text:0x00402f41  8bec             mov ebp,esp
        .text:0x00402f43  b814140000       mov eax,0x00001414
        .text:0x00402f48  e8230a0000       call 0x00403970    ;__alloca_probe()
        .text:0x00402f4d  53               push ebx
        .text:0x00402f4e  56               push esi
        .text:0x00402f4f  57               push edi
        .text:0x00402f50  c785f0ebffff0000 mov dword [ebp - 5136],0
        .text:0x00402f5a  c785ecebffff0000 mov dword [ebp - 5140],0
        .text:0x00402f64  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402f6a  8a5802           mov bl,byte [eax + 2]
        .text:0x00402f6d  889df4ebffff     mov byte [ebp - 5132],bl
        .text:0x00402f73  0fbe85f4ebffff   movsx eax,byte [ebp - 5132]
        .text:0x00402f7a  85c0             test eax,eax
        .text:0x00402f7c  7405             jz 0x00402f83
        */
        $c18 = { 55 8B EC B8 14 14 00 00 E8 ?? ?? ?? ?? 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x004032c0@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x004032c0  
        .text:0x004032c0  FUNC: int cdecl sub_004032c0( int arg0, ) [4 XREFS] 
        .text:0x004032c0  
        .text:0x004032c0  Stack Variables: (offset from initial top of stack)
        .text:0x004032c0             4: int arg0
        .text:0x004032c0          -1028: int local1028
        .text:0x004032c0          -1032: int local1032
        .text:0x004032c0          -2056: int local2056
        .text:0x004032c0          -3080: int local3080
        .text:0x004032c0          -3084: int local3084
        .text:0x004032c0          -3088: int local3088
        .text:0x004032c0          -3092: int local3092
        .text:0x004032c0          -3096: int local3096
        .text:0x004032c0  
        .text:0x004032c0  55               push ebp
        .text:0x004032c1  8bec             mov ebp,esp
        .text:0x004032c3  81ec140c0000     sub esp,3092
        .text:0x004032c9  53               push ebx
        .text:0x004032ca  56               push esi
        .text:0x004032cb  57               push edi
        .text:0x004032cc  c785f0f3ffff0000 mov dword [ebp - 3088],0
        .text:0x004032d6  c785ecf3ffff0000 mov dword [ebp - 3092],0
        .text:0x004032e0  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004032e6  8a5802           mov bl,byte [eax + 2]
        .text:0x004032e9  889df4f3ffff     mov byte [ebp - 3084],bl
        .text:0x004032ef  0fbe85f4f3ffff   movsx eax,byte [ebp - 3084]
        .text:0x004032f6  85c0             test eax,eax
        .text:0x004032f8  7405             jz 0x004032ff
        */
        $c19 = { 55 8B EC 81 EC 14 0C 00 00 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x00403530@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB BeingDebugged flag
        .text:0x00403530  
        .text:0x00403530  FUNC: int cdecl sub_00403530( int arg0, int arg1, ) [2 XREFS] 
        .text:0x00403530  
        .text:0x00403530  Stack Variables: (offset from initial top of stack)
        .text:0x00403530             8: int arg1
        .text:0x00403530             4: int arg0
        .text:0x00403530            -8: int local8
        .text:0x00403530          -1032: int local1032
        .text:0x00403530          -1036: int local1036
        .text:0x00403530          -2060: int local2060
        .text:0x00403530          -2064: int local2064
        .text:0x00403530          -2068: int local2068
        .text:0x00403530          -2072: int local2072
        .text:0x00403530          -2076: int local2076
        .text:0x00403530          -2080: int local2080
        .text:0x00403530          -3104: int local3104
        .text:0x00403530          -4128: int local4128
        .text:0x00403530          -5152: int local5152
        .text:0x00403530          -6176: int local6176
        .text:0x00403530          -6180: int local6180
        .text:0x00403530          -6184: int local6184
        .text:0x00403530          -6188: int local6188
        .text:0x00403530          -6192: int local6192
        .text:0x00403530          -6196: int local6196
        .text:0x00403530          -6200: int local6200
        .text:0x00403530          -6204: int local6204
        .text:0x00403530  
        .text:0x00403530  55               push ebp
        .text:0x00403531  8bec             mov ebp,esp
        .text:0x00403533  b838180000       mov eax,0x00001838
        .text:0x00403538  e833040000       call 0x00403970    ;__alloca_probe()
        .text:0x0040353d  53               push ebx
        .text:0x0040353e  56               push esi
        .text:0x0040353f  57               push edi
        .text:0x00403540  c785dce7ffff0000 mov dword [ebp - 6180],0
        .text:0x0040354a  c785d8e7ffff0000 mov dword [ebp - 6184],0
        .text:0x00403554  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040355a  8a5802           mov bl,byte [eax + 2]
        .text:0x0040355d  889de0e7ffff     mov byte [ebp - 6176],bl
        .text:0x00403563  0fbe85e0e7ffff   movsx eax,byte [ebp - 6176]
        .text:0x0040356a  85c0             test eax,eax
        .text:0x0040356c  7405             jz 0x00403573
        */
        $c20 = { 55 8B EC B8 38 18 00 00 E8 ?? ?? ?? ?? 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? }
        /*
Basic Block at 0x00401000@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - create process on Windows
        .text:0x00401000  Segment: .text (40960 bytes)
        .text:0x00401000  
        .text:0x00401000  FUNC: int cdecl sub_00401000( ) [158 XREFS] 
        .text:0x00401000  
        .text:0x00401000  Stack Variables: (offset from initial top of stack)
        .text:0x00401000          -264: int local264
        .text:0x00401000          -524: int local524
        .text:0x00401000  
        .text:0x00401000  55               push ebp
        .text:0x00401001  8bec             mov ebp,esp
        .text:0x00401003  81ec08020000     sub esp,520
        .text:0x00401009  53               push ebx
        .text:0x0040100a  56               push esi
        .text:0x0040100b  57               push edi
        .text:0x0040100c  6804010000       push 260
        .text:0x00401011  8d85f8fdffff     lea eax,dword [ebp - 520]
        .text:0x00401017  50               push eax
        .text:0x00401018  6a00             push 0
        .text:0x0040101a  ff155cb04000     call dword [0x0040b05c]    ;kernel32.GetModuleFileNameA(0,local524,260)
        .text:0x00401020  6804010000       push 260
        .text:0x00401025  8d8df8fdffff     lea ecx,dword [ebp - 520]
        .text:0x0040102b  51               push ecx
        .text:0x0040102c  8d95f8fdffff     lea edx,dword [ebp - 520]
        .text:0x00401032  52               push edx
        .text:0x00401033  ff1564b04000     call dword [0x0040b064]    ;kernel32.GetShortPathNameA(local524,local524,260)
        .text:0x00401039  bf40c04000       mov edi,0x0040c040
        .text:0x0040103e  8d95fcfeffff     lea edx,dword [ebp - 260]
        .text:0x00401044  83c9ff           or ecx,0xffffffff
        .text:0x00401047  33c0             xor eax,eax
        .text:0x00401049  f2ae             repnz: scasb 
        .text:0x0040104b  f7d1             not ecx
        .text:0x0040104d  2bf9             sub edi,ecx
        .text:0x0040104f  8bf7             mov esi,edi
        .text:0x00401051  8bc1             mov eax,ecx
        .text:0x00401053  8bfa             mov edi,edx
        .text:0x00401055  c1e902           shr ecx,2
        .text:0x00401058  f3a5             rep: movsd 
        .text:0x0040105a  8bc8             mov ecx,eax
        .text:0x0040105c  83e103           and ecx,3
        .text:0x0040105f  f3a4             rep: movsb 
        .text:0x00401061  8dbdf8fdffff     lea edi,dword [ebp - 520]
        .text:0x00401067  8d95fcfeffff     lea edx,dword [ebp - 260]
        .text:0x0040106d  83c9ff           or ecx,0xffffffff
        .text:0x00401070  33c0             xor eax,eax
        .text:0x00401072  f2ae             repnz: scasb 
        .text:0x00401074  f7d1             not ecx
        .text:0x00401076  2bf9             sub edi,ecx
        .text:0x00401078  8bf7             mov esi,edi
        .text:0x0040107a  8bd9             mov ebx,ecx
        .text:0x0040107c  8bfa             mov edi,edx
        .text:0x0040107e  83c9ff           or ecx,0xffffffff
        .text:0x00401081  33c0             xor eax,eax
        .text:0x00401083  f2ae             repnz: scasb 
        .text:0x00401085  83c7ff           add edi,0xffffffff
        .text:0x00401088  8bcb             mov ecx,ebx
        .text:0x0040108a  c1e902           shr ecx,2
        .text:0x0040108d  f3a5             rep: movsd 
        .text:0x0040108f  8bcb             mov ecx,ebx
        .text:0x00401091  83e103           and ecx,3
        .text:0x00401094  f3a4             rep: movsb 
        .text:0x00401096  bf38c04000       mov edi,0x0040c038
        .text:0x0040109b  8d95fcfeffff     lea edx,dword [ebp - 260]
        .text:0x004010a1  83c9ff           or ecx,0xffffffff
        .text:0x004010a4  33c0             xor eax,eax
        .text:0x004010a6  f2ae             repnz: scasb 
        .text:0x004010a8  f7d1             not ecx
        .text:0x004010aa  2bf9             sub edi,ecx
        .text:0x004010ac  8bf7             mov esi,edi
        .text:0x004010ae  8bd9             mov ebx,ecx
        .text:0x004010b0  8bfa             mov edi,edx
        .text:0x004010b2  83c9ff           or ecx,0xffffffff
        .text:0x004010b5  33c0             xor eax,eax
        .text:0x004010b7  f2ae             repnz: scasb 
        .text:0x004010b9  83c7ff           add edi,0xffffffff
        .text:0x004010bc  8bcb             mov ecx,ebx
        .text:0x004010be  c1e902           shr ecx,2
        .text:0x004010c1  f3a5             rep: movsd 
        .text:0x004010c3  8bcb             mov ecx,ebx
        .text:0x004010c5  83e103           and ecx,3
        .text:0x004010c8  f3a4             rep: movsb 
        .text:0x004010ca  6a00             push 0
        .text:0x004010cc  6a00             push 0
        .text:0x004010ce  8d85fcfeffff     lea eax,dword [ebp - 260]
        .text:0x004010d4  50               push eax
        .text:0x004010d5  6830c04000       push 0x0040c030
        .text:0x004010da  6a00             push 0
        .text:0x004010dc  6a00             push 0
        .text:0x004010de  ff1538b14000     call dword [0x0040b138]    ;shell32.ShellExecuteA(0,0,0x0040c030,local264,0,0)
        .text:0x004010e4  6a00             push 0
        .text:0x004010e6  e879270000       call 0x00403864    ;_exit(0)
        .text:0x004010eb  5f               pop edi
        .text:0x004010ec  5e               pop esi
        .text:0x004010ed  5b               pop ebx
        .text:0x004010ee  8be5             mov esp,ebp
        .text:0x004010f0  5d               pop ebp
        .text:0x004010f1  c3               ret 
        */
        $c21 = { 55 8B EC 81 EC 08 02 00 00 53 56 57 68 04 01 00 00 8D 85 ?? ?? ?? ?? 50 6A 00 FF 15 ?? ?? ?? ?? 68 04 01 00 00 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? BF 40 C0 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8D BD ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 BF 38 C0 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 6A 00 6A 00 8D 85 ?? ?? ?? ?? 50 68 30 C0 40 00 6A 00 6A 00 FF 15 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00401100@7faafc7e4a5c736ebfee6abbbc812d80 with 2 features:
          - check for PEB NtGlobalFlag flag
          - query or enumerate registry value
        .text:0x00401100  
        .text:0x00401100  FUNC: int cdecl sub_00401100( ) [2 XREFS] 
        .text:0x00401100  
        .text:0x00401100  Stack Variables: (offset from initial top of stack)
        .text:0x00401100            -8: int local8
        .text:0x00401100           -12: int local12
        .text:0x00401100           -16: int local16
        .text:0x00401100           -20: int local20
        .text:0x00401100           -24: int local24
        .text:0x00401100  
        .text:0x00401100  55               push ebp
        .text:0x00401101  8bec             mov ebp,esp
        .text:0x00401103  83ec14           sub esp,20
        .text:0x00401106  53               push ebx
        .text:0x00401107  56               push esi
        .text:0x00401108  57               push edi
        .text:0x00401109  c745f000000000   mov dword [ebp - 16],0
        .text:0x00401110  c745ec00000000   mov dword [ebp - 20],0
        .text:0x00401117  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040111d  8a5802           mov bl,byte [eax + 2]
        .text:0x00401120  885df4           mov byte [ebp - 12],bl
        .text:0x00401123  0fbe45f4         movsx eax,byte [ebp - 12]
        .text:0x00401127  85c0             test eax,eax
        .text:0x00401129  7405             jz 0x00401130
        .text:0x0040112b  e8d0feffff       call 0x00401000    ;sub_00401000()
        .text:0x00401130  loc_00401130: [1 XREFS]
        .text:0x00401130  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401136  8b4018           mov eax,dword [eax + 24]
        .text:0x00401139  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x0040113d  8945f0           mov dword [ebp - 16],eax
        .text:0x00401140  837df000         cmp dword [ebp - 16],0
        .text:0x00401144  7405             jz 0x0040114b
        .text:0x00401146  e8b5feffff       call 0x00401000    ;sub_00401000()
        .text:0x0040114b  loc_0040114b: [1 XREFS]
        .text:0x0040114b  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401151  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x00401155  83e870           sub eax,112
        .text:0x00401158  8945ec           mov dword [ebp - 20],eax
        .text:0x0040115b  837dec00         cmp dword [ebp - 20],0
        .text:0x0040115f  7505             jnz 0x00401166
        .text:0x00401161  e89afeffff       call 0x00401000    ;sub_00401000()
        .text:0x00401166  loc_00401166: [1 XREFS]
        .text:0x00401166  8d4df8           lea ecx,dword [ebp - 8]
        .text:0x00401169  51               push ecx
        .text:0x0040116a  683f000f00       push 0x000f003f
        .text:0x0040116f  6a00             push 0
        .text:0x00401171  6858c04000       push 0x0040c058
        .text:0x00401176  6802000080       push 0x80000002
        .text:0x0040117b  ff1520b04000     call dword [0x0040b020]    ;advapi32.RegOpenKeyExA(0x80000002,0x0040c058,0,0x000f003f,local12)
        .text:0x00401181  85c0             test eax,eax
        .text:0x00401183  7404             jz 0x00401189
        .text:0x00401185  33c0             xor eax,eax
        .text:0x00401187  eb3d             jmp 0x004011c6
        .text:0x00401189  loc_00401189: [1 XREFS]
        .text:0x00401189  6a00             push 0
        .text:0x0040118b  6a00             push 0
        .text:0x0040118d  6a00             push 0
        .text:0x0040118f  6a00             push 0
        .text:0x00401191  6848c04000       push 0x0040c048
        .text:0x00401196  8b55f8           mov edx,dword [ebp - 8]
        .text:0x00401199  52               push edx
        .text:0x0040119a  ff1524b04000     call dword [0x0040b024]    ;advapi32.RegQueryValueExA(0xfefefefe,0x0040c048,0,0,0,0)
        .text:0x004011a0  8945fc           mov dword [ebp - 4],eax
        .text:0x004011a3  837dfc00         cmp dword [ebp - 4],0
        .text:0x004011a7  740e             jz 0x004011b7
        .text:0x004011a9  8b45f8           mov eax,dword [ebp - 8]
        .text:0x004011ac  50               push eax
        .text:0x004011ad  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x004011b3  33c0             xor eax,eax
        .text:0x004011b5  eb0f             jmp 0x004011c6
        .text:0x004011b7  loc_004011b7: [1 XREFS]
        .text:0x004011b7  8b4df8           mov ecx,dword [ebp - 8]
        .text:0x004011ba  51               push ecx
        .text:0x004011bb  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x004011c1  b801000000       mov eax,1
        .text:0x004011c6  loc_004011c6: [2 XREFS]
        .text:0x004011c6  5f               pop edi
        .text:0x004011c7  5e               pop esi
        .text:0x004011c8  5b               pop ebx
        .text:0x004011c9  8be5             mov esp,ebp
        .text:0x004011cb  5d               pop ebp
        .text:0x004011cc  c3               ret 
        */
        $c22 = { 55 8B EC 83 EC 14 53 56 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 5D ?? 0F BE 45 ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 45 ?? 83 7D ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 45 ?? 83 7D ?? 00 75 ?? E8 ?? ?? ?? ?? 8D 4D ?? 51 68 3F 00 0F 00 6A 00 68 58 C0 40 00 68 02 00 00 80 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 33 C0 EB ?? 6A 00 6A 00 6A 00 6A 00 68 48 C0 40 00 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 00 74 ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 33 C0 EB ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? B8 01 00 00 00 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x004011d0@7faafc7e4a5c736ebfee6abbbc812d80 with 2 features:
          - check for PEB NtGlobalFlag flag
          - set registry value
        .text:0x004011d0  
        .text:0x004011d0  FUNC: int cdecl sub_004011d0( int arg0, int arg1, int arg2, int arg3, ) [6 XREFS] 
        .text:0x004011d0  
        .text:0x004011d0  Stack Variables: (offset from initial top of stack)
        .text:0x004011d0            16: int arg3
        .text:0x004011d0            12: int arg2
        .text:0x004011d0             8: int arg1
        .text:0x004011d0             4: int arg0
        .text:0x004011d0            -8: int local8
        .text:0x004011d0          -4108: int local4108
        .text:0x004011d0          -4112: int local4112
        .text:0x004011d0          -4116: int local4116
        .text:0x004011d0          -4120: int local4120
        .text:0x004011d0          -4124: int local4124
        .text:0x004011d0  
        .text:0x004011d0  55               push ebp
        .text:0x004011d1  8bec             mov ebp,esp
        .text:0x004011d3  b818100000       mov eax,0x00001018
        .text:0x004011d8  e893270000       call 0x00403970    ;__alloca_probe()
        .text:0x004011dd  53               push ebx
        .text:0x004011de  56               push esi
        .text:0x004011df  57               push edi
        .text:0x004011e0  c785ecefffff0000 mov dword [ebp - 4116],0
        .text:0x004011ea  c785e8efffff0000 mov dword [ebp - 4120],0
        .text:0x004011f4  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004011fa  8a5802           mov bl,byte [eax + 2]
        .text:0x004011fd  889df0efffff     mov byte [ebp - 4112],bl
        .text:0x00401203  0fbe85f0efffff   movsx eax,byte [ebp - 4112]
        .text:0x0040120a  85c0             test eax,eax
        .text:0x0040120c  7405             jz 0x00401213
        .text:0x0040120e  e8edfdffff       call 0x00401000    ;sub_00401000()
        .text:0x00401213  loc_00401213: [1 XREFS]
        .text:0x00401213  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401219  8b4018           mov eax,dword [eax + 24]
        .text:0x0040121c  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x00401220  8985ecefffff     mov dword [ebp - 4116],eax
        .text:0x00401226  83bdecefffff00   cmp dword [ebp - 4116],0
        .text:0x0040122d  7405             jz 0x00401234
        .text:0x0040122f  e8ccfdffff       call 0x00401000    ;sub_00401000()
        .text:0x00401234  loc_00401234: [1 XREFS]
        .text:0x00401234  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040123a  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x0040123e  83e870           sub eax,112
        .text:0x00401241  8985e8efffff     mov dword [ebp - 4120],eax
        .text:0x00401247  83bde8efffff00   cmp dword [ebp - 4120],0
        .text:0x0040124e  7505             jnz 0x00401255
        .text:0x00401250  e8abfdffff       call 0x00401000    ;sub_00401000()
        .text:0x00401255  loc_00401255: [1 XREFS]
        .text:0x00401255  b900040000       mov ecx,1024
        .text:0x0040125a  33c0             xor eax,eax
        .text:0x0040125c  8dbdf8efffff     lea edi,dword [ebp - 4104]
        .text:0x00401262  f3ab             rep: stosd 
        .text:0x00401264  aa               stosb 
        .text:0x00401265  8d8df8efffff     lea ecx,dword [ebp - 4104]
        .text:0x0040126b  894dfc           mov dword [ebp - 4],ecx
        .text:0x0040126e  8b7d08           mov edi,dword [ebp + 8]
        .text:0x00401271  8b55fc           mov edx,dword [ebp - 4]
        .text:0x00401274  83c9ff           or ecx,0xffffffff
        .text:0x00401277  33c0             xor eax,eax
        .text:0x00401279  f2ae             repnz: scasb 
        .text:0x0040127b  f7d1             not ecx
        .text:0x0040127d  2bf9             sub edi,ecx
        .text:0x0040127f  8bf7             mov esi,edi
        .text:0x00401281  8bc1             mov eax,ecx
        .text:0x00401283  8bfa             mov edi,edx
        .text:0x00401285  c1e902           shr ecx,2
        .text:0x00401288  f3a5             rep: movsd 
        .text:0x0040128a  8bc8             mov ecx,eax
        .text:0x0040128c  83e103           and ecx,3
        .text:0x0040128f  f3a4             rep: movsb 
        .text:0x00401291  8b7d08           mov edi,dword [ebp + 8]
        .text:0x00401294  83c9ff           or ecx,0xffffffff
        .text:0x00401297  33c0             xor eax,eax
        .text:0x00401299  f2ae             repnz: scasb 
        .text:0x0040129b  f7d1             not ecx
        .text:0x0040129d  83c1ff           add ecx,0xffffffff
        .text:0x004012a0  8b55fc           mov edx,dword [ebp - 4]
        .text:0x004012a3  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x004012a7  8945fc           mov dword [ebp - 4],eax
        .text:0x004012aa  8b7d0c           mov edi,dword [ebp + 12]
        .text:0x004012ad  8b55fc           mov edx,dword [ebp - 4]
        .text:0x004012b0  83c9ff           or ecx,0xffffffff
        .text:0x004012b3  33c0             xor eax,eax
        .text:0x004012b5  f2ae             repnz: scasb 
        .text:0x004012b7  f7d1             not ecx
        .text:0x004012b9  2bf9             sub edi,ecx
        .text:0x004012bb  8bf7             mov esi,edi
        .text:0x004012bd  8bc1             mov eax,ecx
        .text:0x004012bf  8bfa             mov edi,edx
        .text:0x004012c1  c1e902           shr ecx,2
        .text:0x004012c4  f3a5             rep: movsd 
        .text:0x004012c6  8bc8             mov ecx,eax
        .text:0x004012c8  83e103           and ecx,3
        .text:0x004012cb  f3a4             rep: movsb 
        .text:0x004012cd  8b7d0c           mov edi,dword [ebp + 12]
        .text:0x004012d0  83c9ff           or ecx,0xffffffff
        .text:0x004012d3  33c0             xor eax,eax
        .text:0x004012d5  f2ae             repnz: scasb 
        .text:0x004012d7  f7d1             not ecx
        .text:0x004012d9  83c1ff           add ecx,0xffffffff
        .text:0x004012dc  8b55fc           mov edx,dword [ebp - 4]
        .text:0x004012df  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x004012e3  8945fc           mov dword [ebp - 4],eax
        .text:0x004012e6  8b7d10           mov edi,dword [ebp + 16]
        .text:0x004012e9  8b55fc           mov edx,dword [ebp - 4]
        .text:0x004012ec  83c9ff           or ecx,0xffffffff
        .text:0x004012ef  33c0             xor eax,eax
        .text:0x004012f1  f2ae             repnz: scasb 
        .text:0x004012f3  f7d1             not ecx
        .text:0x004012f5  2bf9             sub edi,ecx
        .text:0x004012f7  8bf7             mov esi,edi
        .text:0x004012f9  8bc1             mov eax,ecx
        .text:0x004012fb  8bfa             mov edi,edx
        .text:0x004012fd  c1e902           shr ecx,2
        .text:0x00401300  f3a5             rep: movsd 
        .text:0x00401302  8bc8             mov ecx,eax
        .text:0x00401304  83e103           and ecx,3
        .text:0x00401307  f3a4             rep: movsb 
        .text:0x00401309  8b7d10           mov edi,dword [ebp + 16]
        .text:0x0040130c  83c9ff           or ecx,0xffffffff
        .text:0x0040130f  33c0             xor eax,eax
        .text:0x00401311  f2ae             repnz: scasb 
        .text:0x00401313  f7d1             not ecx
        .text:0x00401315  83c1ff           add ecx,0xffffffff
        .text:0x00401318  8b55fc           mov edx,dword [ebp - 4]
        .text:0x0040131b  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x0040131f  8945fc           mov dword [ebp - 4],eax
        .text:0x00401322  8b7d14           mov edi,dword [ebp + 20]
        .text:0x00401325  8b55fc           mov edx,dword [ebp - 4]
        .text:0x00401328  83c9ff           or ecx,0xffffffff
        .text:0x0040132b  33c0             xor eax,eax
        .text:0x0040132d  f2ae             repnz: scasb 
        .text:0x0040132f  f7d1             not ecx
        .text:0x00401331  2bf9             sub edi,ecx
        .text:0x00401333  8bf7             mov esi,edi
        .text:0x00401335  8bc1             mov eax,ecx
        .text:0x00401337  8bfa             mov edi,edx
        .text:0x00401339  c1e902           shr ecx,2
        .text:0x0040133c  f3a5             rep: movsd 
        .text:0x0040133e  8bc8             mov ecx,eax
        .text:0x00401340  83e103           and ecx,3
        .text:0x00401343  f3a4             rep: movsb 
        .text:0x00401345  8b7d14           mov edi,dword [ebp + 20]
        .text:0x00401348  83c9ff           or ecx,0xffffffff
        .text:0x0040134b  33c0             xor eax,eax
        .text:0x0040134d  f2ae             repnz: scasb 
        .text:0x0040134f  f7d1             not ecx
        .text:0x00401351  83c1ff           add ecx,0xffffffff
        .text:0x00401354  8b55fc           mov edx,dword [ebp - 4]
        .text:0x00401357  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x0040135b  8945fc           mov dword [ebp - 4],eax
        .text:0x0040135e  6a00             push 0
        .text:0x00401360  8d8df4efffff     lea ecx,dword [ebp - 4108]
        .text:0x00401366  51               push ecx
        .text:0x00401367  6a00             push 0
        .text:0x00401369  683f000f00       push 0x000f003f
        .text:0x0040136e  6a00             push 0
        .text:0x00401370  6a00             push 0
        .text:0x00401372  6a00             push 0
        .text:0x00401374  6858c04000       push 0x0040c058
        .text:0x00401379  6802000080       push 0x80000002
        .text:0x0040137e  ff1518b04000     call dword [0x0040b018]    ;advapi32.RegCreateKeyExA(0x80000002,0x0040c058,0,0,0,0x000f003f,0,local4112,0)
        .text:0x00401384  85c0             test eax,eax
        .text:0x00401386  7407             jz 0x0040138f
        .text:0x00401388  b801000000       mov eax,1
        .text:0x0040138d  eb49             jmp 0x004013d8
        .text:0x0040138f  loc_0040138f: [1 XREFS]
        .text:0x0040138f  6800100000       push 0x00001000
        .text:0x00401394  8d95f8efffff     lea edx,dword [ebp - 4104]
        .text:0x0040139a  52               push edx
        .text:0x0040139b  6a03             push 3
        .text:0x0040139d  6a00             push 0
        .text:0x0040139f  6848c04000       push 0x0040c048
        .text:0x004013a4  8b85f4efffff     mov eax,dword [ebp - 4108]
        .text:0x004013aa  50               push eax
        .text:0x004013ab  ff151cb04000     call dword [0x0040b01c]    ;advapi32.RegSetValueExA(0xfefefefe,0x0040c048,0,3,local4108,0x00001000)
        .text:0x004013b1  85c0             test eax,eax
        .text:0x004013b3  7414             jz 0x004013c9
        .text:0x004013b5  8b8df4efffff     mov ecx,dword [ebp - 4108]
        .text:0x004013bb  51               push ecx
        .text:0x004013bc  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x004013c2  b801000000       mov eax,1
        .text:0x004013c7  eb0f             jmp 0x004013d8
        .text:0x004013c9  loc_004013c9: [1 XREFS]
        .text:0x004013c9  8b95f4efffff     mov edx,dword [ebp - 4108]
        .text:0x004013cf  52               push edx
        .text:0x004013d0  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x004013d6  33c0             xor eax,eax
        .text:0x004013d8  loc_004013d8: [2 XREFS]
        .text:0x004013d8  5f               pop edi
        .text:0x004013d9  5e               pop esi
        .text:0x004013da  5b               pop ebx
        .text:0x004013db  8be5             mov esp,ebp
        .text:0x004013dd  5d               pop ebp
        .text:0x004013de  c3               ret 
        */
        $c23 = { 55 8B EC B8 18 10 00 00 E8 ?? ?? ?? ?? 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? B9 00 04 00 00 33 C0 8D BD ?? ?? ?? ?? F3 AB AA 8D 8D ?? ?? ?? ?? 89 4D ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 6A 00 8D 8D ?? ?? ?? ?? 51 6A 00 68 3F 00 0F 00 6A 00 6A 00 6A 00 68 58 C0 40 00 68 02 00 00 80 FF 15 ?? ?? ?? ?? 85 C0 74 ?? B8 01 00 00 00 EB ?? 68 00 10 00 00 8D 95 ?? ?? ?? ?? 52 6A 03 6A 00 68 48 C0 40 00 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x004013e0@7faafc7e4a5c736ebfee6abbbc812d80 with 2 features:
          - check for PEB NtGlobalFlag flag
          - delete registry value
        .text:0x004013e0  
        .text:0x004013e0  FUNC: int cdecl sub_004013e0( ) [2 XREFS] 
        .text:0x004013e0  
        .text:0x004013e0  Stack Variables: (offset from initial top of stack)
        .text:0x004013e0            -8: int local8
        .text:0x004013e0           -12: int local12
        .text:0x004013e0           -16: int local16
        .text:0x004013e0           -20: int local20
        .text:0x004013e0           -24: int local24
        .text:0x004013e0  
        .text:0x004013e0  55               push ebp
        .text:0x004013e1  8bec             mov ebp,esp
        .text:0x004013e3  83ec14           sub esp,20
        .text:0x004013e6  53               push ebx
        .text:0x004013e7  56               push esi
        .text:0x004013e8  57               push edi
        .text:0x004013e9  c745f000000000   mov dword [ebp - 16],0
        .text:0x004013f0  c745ec00000000   mov dword [ebp - 20],0
        .text:0x004013f7  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004013fd  8a5802           mov bl,byte [eax + 2]
        .text:0x00401400  885df4           mov byte [ebp - 12],bl
        .text:0x00401403  0fbe45f4         movsx eax,byte [ebp - 12]
        .text:0x00401407  85c0             test eax,eax
        .text:0x00401409  7405             jz 0x00401410
        .text:0x0040140b  e8f0fbffff       call 0x00401000    ;sub_00401000()
        .text:0x00401410  loc_00401410: [1 XREFS]
        .text:0x00401410  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401416  8b4018           mov eax,dword [eax + 24]
        .text:0x00401419  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x0040141d  8945f0           mov dword [ebp - 16],eax
        .text:0x00401420  837df000         cmp dword [ebp - 16],0
        .text:0x00401424  7405             jz 0x0040142b
        .text:0x00401426  e8d5fbffff       call 0x00401000    ;sub_00401000()
        .text:0x0040142b  loc_0040142b: [1 XREFS]
        .text:0x0040142b  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401431  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x00401435  83e870           sub eax,112
        .text:0x00401438  8945ec           mov dword [ebp - 20],eax
        .text:0x0040143b  837dec00         cmp dword [ebp - 20],0
        .text:0x0040143f  7505             jnz 0x00401446
        .text:0x00401441  e8bafbffff       call 0x00401000    ;sub_00401000()
        .text:0x00401446  loc_00401446: [1 XREFS]
        .text:0x00401446  6a00             push 0
        .text:0x00401448  8d4df8           lea ecx,dword [ebp - 8]
        .text:0x0040144b  51               push ecx
        .text:0x0040144c  6a00             push 0
        .text:0x0040144e  683f000f00       push 0x000f003f
        .text:0x00401453  6a00             push 0
        .text:0x00401455  6a00             push 0
        .text:0x00401457  6a00             push 0
        .text:0x00401459  6858c04000       push 0x0040c058
        .text:0x0040145e  6802000080       push 0x80000002
        .text:0x00401463  ff1518b04000     call dword [0x0040b018]    ;advapi32.RegCreateKeyExA(0x80000002,0x0040c058,0,0,0,0x000f003f,0,local12,0)
        .text:0x00401469  85c0             test eax,eax
        .text:0x0040146b  7407             jz 0x00401474
        .text:0x0040146d  b801000000       mov eax,1
        .text:0x00401472  eb35             jmp 0x004014a9
        .text:0x00401474  loc_00401474: [1 XREFS]
        .text:0x00401474  6848c04000       push 0x0040c048
        .text:0x00401479  8b55f8           mov edx,dword [ebp - 8]
        .text:0x0040147c  52               push edx
        .text:0x0040147d  ff1514b04000     call dword [0x0040b014]    ;advapi32.RegDeleteValueA(0xfefefefe,0x0040c048)
        .text:0x00401483  8945fc           mov dword [ebp - 4],eax
        .text:0x00401486  837dfc00         cmp dword [ebp - 4],0
        .text:0x0040148a  7411             jz 0x0040149d
        .text:0x0040148c  8b45f8           mov eax,dword [ebp - 8]
        .text:0x0040148f  50               push eax
        .text:0x00401490  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x00401496  b801000000       mov eax,1
        .text:0x0040149b  eb0c             jmp 0x004014a9
        .text:0x0040149d  loc_0040149d: [1 XREFS]
        .text:0x0040149d  8b4df8           mov ecx,dword [ebp - 8]
        .text:0x004014a0  51               push ecx
        .text:0x004014a1  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x004014a7  33c0             xor eax,eax
        .text:0x004014a9  loc_004014a9: [2 XREFS]
        .text:0x004014a9  5f               pop edi
        .text:0x004014aa  5e               pop esi
        .text:0x004014ab  5b               pop ebx
        .text:0x004014ac  8be5             mov esp,ebp
        .text:0x004014ae  5d               pop ebp
        .text:0x004014af  c3               ret 
        */
        $c24 = { 55 8B EC 83 EC 14 53 56 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 5D ?? 0F BE 45 ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 45 ?? 83 7D ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 45 ?? 83 7D ?? 00 75 ?? E8 ?? ?? ?? ?? 6A 00 8D 4D ?? 51 6A 00 68 3F 00 0F 00 6A 00 6A 00 6A 00 68 58 C0 40 00 68 02 00 00 80 FF 15 ?? ?? ?? ?? 85 C0 74 ?? B8 01 00 00 00 EB ?? 68 48 C0 40 00 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 00 74 ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x004014b0@7faafc7e4a5c736ebfee6abbbc812d80 with 2 features:
          - check for PEB NtGlobalFlag flag
          - query or enumerate registry value
        .text:0x004014b0  
        .text:0x004014b0  FUNC: int cdecl sub_004014b0( int arg0, int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, ) [8 XREFS] 
        .text:0x004014b0  
        .text:0x004014b0  Stack Variables: (offset from initial top of stack)
        .text:0x004014b0            28: int arg6
        .text:0x004014b0            24: int arg5
        .text:0x004014b0            20: int arg4
        .text:0x004014b0            16: int arg3
        .text:0x004014b0            12: int arg2
        .text:0x004014b0             8: int arg1
        .text:0x004014b0             4: int arg0
        .text:0x004014b0            -8: int local8
        .text:0x004014b0           -12: int local12
        .text:0x004014b0          -4108: int local4108
        .text:0x004014b0          -4112: int local4112
        .text:0x004014b0          -4116: int local4116
        .text:0x004014b0          -4120: int local4120
        .text:0x004014b0          -4124: int local4124
        .text:0x004014b0          -4128: int local4128
        .text:0x004014b0  
        .text:0x004014b0  55               push ebp
        .text:0x004014b1  8bec             mov ebp,esp
        .text:0x004014b3  b81c100000       mov eax,0x0000101c
        .text:0x004014b8  e8b3240000       call 0x00403970    ;__alloca_probe()
        .text:0x004014bd  53               push ebx
        .text:0x004014be  56               push esi
        .text:0x004014bf  57               push edi
        .text:0x004014c0  c785e8efffff0000 mov dword [ebp - 4120],0
        .text:0x004014ca  c785e4efffff0000 mov dword [ebp - 4124],0
        .text:0x004014d4  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004014da  8a5802           mov bl,byte [eax + 2]
        .text:0x004014dd  889decefffff     mov byte [ebp - 4116],bl
        .text:0x004014e3  0fbe85ecefffff   movsx eax,byte [ebp - 4116]
        .text:0x004014ea  85c0             test eax,eax
        .text:0x004014ec  7405             jz 0x004014f3
        .text:0x004014ee  e80dfbffff       call 0x00401000    ;sub_00401000()
        .text:0x004014f3  loc_004014f3: [1 XREFS]
        .text:0x004014f3  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004014f9  8b4018           mov eax,dword [eax + 24]
        .text:0x004014fc  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x00401500  8985e8efffff     mov dword [ebp - 4120],eax
        .text:0x00401506  83bde8efffff00   cmp dword [ebp - 4120],0
        .text:0x0040150d  7405             jz 0x00401514
        .text:0x0040150f  e8ecfaffff       call 0x00401000    ;sub_00401000()
        .text:0x00401514  loc_00401514: [1 XREFS]
        .text:0x00401514  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040151a  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x0040151e  83e870           sub eax,112
        .text:0x00401521  8985e4efffff     mov dword [ebp - 4124],eax
        .text:0x00401527  83bde4efffff00   cmp dword [ebp - 4124],0
        .text:0x0040152e  7505             jnz 0x00401535
        .text:0x00401530  e8cbfaffff       call 0x00401000    ;sub_00401000()
        .text:0x00401535  loc_00401535: [1 XREFS]
        .text:0x00401535  c745f801100000   mov dword [ebp - 8],0x00001001
        .text:0x0040153c  8d8df0efffff     lea ecx,dword [ebp - 4112]
        .text:0x00401542  51               push ecx
        .text:0x00401543  683f000f00       push 0x000f003f
        .text:0x00401548  6a00             push 0
        .text:0x0040154a  6858c04000       push 0x0040c058
        .text:0x0040154f  6802000080       push 0x80000002
        .text:0x00401554  ff1520b04000     call dword [0x0040b020]    ;advapi32.RegOpenKeyExA(0x80000002,0x0040c058,0,0x000f003f,local4116)
        .text:0x0040155a  85c0             test eax,eax
        .text:0x0040155c  740a             jz 0x00401568
        .text:0x0040155e  b801000000       mov eax,1
        .text:0x00401563  e94f010000       jmp 0x004016b7
        .text:0x00401568  loc_00401568: [1 XREFS]
        .text:0x00401568  8d55f8           lea edx,dword [ebp - 8]
        .text:0x0040156b  52               push edx
        .text:0x0040156c  8d85f8efffff     lea eax,dword [ebp - 4104]
        .text:0x00401572  50               push eax
        .text:0x00401573  6a00             push 0
        .text:0x00401575  6a00             push 0
        .text:0x00401577  6848c04000       push 0x0040c048
        .text:0x0040157c  8b8df0efffff     mov ecx,dword [ebp - 4112]
        .text:0x00401582  51               push ecx
        .text:0x00401583  ff1524b04000     call dword [0x0040b024]    ;advapi32.RegQueryValueExA(0xfefefefe,0x0040c048,0,0,local4108,local12)
        .text:0x00401589  8985f4efffff     mov dword [ebp - 4108],eax
        .text:0x0040158f  83bdf4efffff00   cmp dword [ebp - 4108],0
        .text:0x00401596  7417             jz 0x004015af
        .text:0x00401598  8b95f0efffff     mov edx,dword [ebp - 4112]
        .text:0x0040159e  52               push edx
        .text:0x0040159f  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x004015a5  b801000000       mov eax,1
        .text:0x004015aa  e908010000       jmp 0x004016b7
        .text:0x004015af  loc_004015af: [1 XREFS]
        .text:0x004015af  8d85f8efffff     lea eax,dword [ebp - 4104]
        .text:0x004015b5  8945fc           mov dword [ebp - 4],eax
        .text:0x004015b8  8b7dfc           mov edi,dword [ebp - 4]
        .text:0x004015bb  8b5508           mov edx,dword [ebp + 8]
        .text:0x004015be  83c9ff           or ecx,0xffffffff
        .text:0x004015c1  33c0             xor eax,eax
        .text:0x004015c3  f2ae             repnz: scasb 
        .text:0x004015c5  f7d1             not ecx
        .text:0x004015c7  2bf9             sub edi,ecx
        .text:0x004015c9  8bf7             mov esi,edi
        .text:0x004015cb  8bc1             mov eax,ecx
        .text:0x004015cd  8bfa             mov edi,edx
        .text:0x004015cf  c1e902           shr ecx,2
        .text:0x004015d2  f3a5             rep: movsd 
        .text:0x004015d4  8bc8             mov ecx,eax
        .text:0x004015d6  83e103           and ecx,3
        .text:0x004015d9  f3a4             rep: movsb 
        .text:0x004015db  8b7d08           mov edi,dword [ebp + 8]
        .text:0x004015de  83c9ff           or ecx,0xffffffff
        .text:0x004015e1  33c0             xor eax,eax
        .text:0x004015e3  f2ae             repnz: scasb 
        .text:0x004015e5  f7d1             not ecx
        .text:0x004015e7  83c1ff           add ecx,0xffffffff
        .text:0x004015ea  8b55fc           mov edx,dword [ebp - 4]
        .text:0x004015ed  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x004015f1  8945fc           mov dword [ebp - 4],eax
        .text:0x004015f4  8b7dfc           mov edi,dword [ebp - 4]
        .text:0x004015f7  8b5510           mov edx,dword [ebp + 16]
        .text:0x004015fa  83c9ff           or ecx,0xffffffff
        .text:0x004015fd  33c0             xor eax,eax
        .text:0x004015ff  f2ae             repnz: scasb 
        .text:0x00401601  f7d1             not ecx
        .text:0x00401603  2bf9             sub edi,ecx
        .text:0x00401605  8bf7             mov esi,edi
        .text:0x00401607  8bc1             mov eax,ecx
        .text:0x00401609  8bfa             mov edi,edx
        .text:0x0040160b  c1e902           shr ecx,2
        .text:0x0040160e  f3a5             rep: movsd 
        .text:0x00401610  8bc8             mov ecx,eax
        .text:0x00401612  83e103           and ecx,3
        .text:0x00401615  f3a4             rep: movsb 
        .text:0x00401617  8b7d10           mov edi,dword [ebp + 16]
        .text:0x0040161a  83c9ff           or ecx,0xffffffff
        .text:0x0040161d  33c0             xor eax,eax
        .text:0x0040161f  f2ae             repnz: scasb 
        .text:0x00401621  f7d1             not ecx
        .text:0x00401623  83c1ff           add ecx,0xffffffff
        .text:0x00401626  8b55fc           mov edx,dword [ebp - 4]
        .text:0x00401629  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x0040162d  8945fc           mov dword [ebp - 4],eax
        .text:0x00401630  8b7dfc           mov edi,dword [ebp - 4]
        .text:0x00401633  8b5518           mov edx,dword [ebp + 24]
        .text:0x00401636  83c9ff           or ecx,0xffffffff
        .text:0x00401639  33c0             xor eax,eax
        .text:0x0040163b  f2ae             repnz: scasb 
        .text:0x0040163d  f7d1             not ecx
        .text:0x0040163f  2bf9             sub edi,ecx
        .text:0x00401641  8bf7             mov esi,edi
        .text:0x00401643  8bc1             mov eax,ecx
        .text:0x00401645  8bfa             mov edi,edx
        .text:0x00401647  c1e902           shr ecx,2
        .text:0x0040164a  f3a5             rep: movsd 
        .text:0x0040164c  8bc8             mov ecx,eax
        .text:0x0040164e  83e103           and ecx,3
        .text:0x00401651  f3a4             rep: movsb 
        .text:0x00401653  8b7d18           mov edi,dword [ebp + 24]
        .text:0x00401656  83c9ff           or ecx,0xffffffff
        .text:0x00401659  33c0             xor eax,eax
        .text:0x0040165b  f2ae             repnz: scasb 
        .text:0x0040165d  f7d1             not ecx
        .text:0x0040165f  83c1ff           add ecx,0xffffffff
        .text:0x00401662  8b55fc           mov edx,dword [ebp - 4]
        .text:0x00401665  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x00401669  8945fc           mov dword [ebp - 4],eax
        .text:0x0040166c  8b7dfc           mov edi,dword [ebp - 4]
        .text:0x0040166f  8b5520           mov edx,dword [ebp + 32]
        .text:0x00401672  83c9ff           or ecx,0xffffffff
        .text:0x00401675  33c0             xor eax,eax
        .text:0x00401677  f2ae             repnz: scasb 
        .text:0x00401679  f7d1             not ecx
        .text:0x0040167b  2bf9             sub edi,ecx
        .text:0x0040167d  8bf7             mov esi,edi
        .text:0x0040167f  8bc1             mov eax,ecx
        .text:0x00401681  8bfa             mov edi,edx
        .text:0x00401683  c1e902           shr ecx,2
        .text:0x00401686  f3a5             rep: movsd 
        .text:0x00401688  8bc8             mov ecx,eax
        .text:0x0040168a  83e103           and ecx,3
        .text:0x0040168d  f3a4             rep: movsb 
        .text:0x0040168f  8b7d20           mov edi,dword [ebp + 32]
        .text:0x00401692  83c9ff           or ecx,0xffffffff
        .text:0x00401695  33c0             xor eax,eax
        .text:0x00401697  f2ae             repnz: scasb 
        .text:0x00401699  f7d1             not ecx
        .text:0x0040169b  83c1ff           add ecx,0xffffffff
        .text:0x0040169e  8b55fc           mov edx,dword [ebp - 4]
        .text:0x004016a1  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x004016a5  8945fc           mov dword [ebp - 4],eax
        .text:0x004016a8  8b8df0efffff     mov ecx,dword [ebp - 4112]
        .text:0x004016ae  51               push ecx
        .text:0x004016af  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x004016b5  33c0             xor eax,eax
        .text:0x004016b7  loc_004016b7: [2 XREFS]
        .text:0x004016b7  5f               pop edi
        .text:0x004016b8  5e               pop esi
        .text:0x004016b9  5b               pop ebx
        .text:0x004016ba  8be5             mov esp,ebp
        .text:0x004016bc  5d               pop ebp
        .text:0x004016bd  c3               ret 
        */
        $c25 = { 55 8B EC B8 1C 10 00 00 E8 ?? ?? ?? ?? 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? C7 45 ?? 01 10 00 00 8D 8D ?? ?? ?? ?? 51 68 3F 00 0F 00 6A 00 68 58 C0 40 00 68 02 00 00 80 FF 15 ?? ?? ?? ?? 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8D 55 ?? 52 8D 85 ?? ?? ?? ?? 50 6A 00 6A 00 68 48 C0 40 00 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 89 45 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x004016c0@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB NtGlobalFlag flag
        .text:0x004016c0  
        .text:0x004016c0  FUNC: int cdecl sub_004016c0( int arg0, int arg1, ) [2 XREFS] 
        .text:0x004016c0  
        .text:0x004016c0  Stack Variables: (offset from initial top of stack)
        .text:0x004016c0             8: int arg1
        .text:0x004016c0             4: int arg0
        .text:0x004016c0          -1028: int local1028
        .text:0x004016c0          -2052: int local2052
        .text:0x004016c0          -3076: int local3076
        .text:0x004016c0          -3080: int local3080
        .text:0x004016c0          -3084: int local3084
        .text:0x004016c0          -3088: int local3088
        .text:0x004016c0  
        .text:0x004016c0  55               push ebp
        .text:0x004016c1  8bec             mov ebp,esp
        .text:0x004016c3  81ec0c0c0000     sub esp,3084
        .text:0x004016c9  53               push ebx
        .text:0x004016ca  56               push esi
        .text:0x004016cb  57               push edi
        .text:0x004016cc  c785f8f3ffff0000 mov dword [ebp - 3080],0
        .text:0x004016d6  c785f4f3ffff0000 mov dword [ebp - 3084],0
        .text:0x004016e0  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004016e6  8a5802           mov bl,byte [eax + 2]
        .text:0x004016e9  889dfcf3ffff     mov byte [ebp - 3076],bl
        .text:0x004016ef  0fbe85fcf3ffff   movsx eax,byte [ebp - 3076]
        .text:0x004016f6  85c0             test eax,eax
        .text:0x004016f8  7405             jz 0x004016ff
        .text:0x004016fa  e801f9ffff       call 0x00401000    ;sub_00401000()
        .text:0x004016ff  loc_004016ff: [1 XREFS]
        .text:0x004016ff  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401705  8b4018           mov eax,dword [eax + 24]
        .text:0x00401708  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x0040170c  8985f8f3ffff     mov dword [ebp - 3080],eax
        .text:0x00401712  83bdf8f3ffff00   cmp dword [ebp - 3080],0
        .text:0x00401719  7405             jz 0x00401720
        .text:0x0040171b  e8e0f8ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401720  loc_00401720: [1 XREFS]
        .text:0x00401720  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401726  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x0040172a  83e870           sub eax,112
        .text:0x0040172d  8985f4f3ffff     mov dword [ebp - 3084],eax
        .text:0x00401733  83bdf4f3ffff00   cmp dword [ebp - 3084],0
        .text:0x0040173a  7505             jnz 0x00401741
        .text:0x0040173c  e8bff8ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401741  loc_00401741: [1 XREFS]
        .text:0x00401741  6800040000       push 1024
        .text:0x00401746  8d8d00fcffff     lea ecx,dword [ebp - 1024]
        .text:0x0040174c  51               push ecx
        .text:0x0040174d  6800040000       push 1024
        .text:0x00401752  8d9500f4ffff     lea edx,dword [ebp - 3072]
        .text:0x00401758  52               push edx
        .text:0x00401759  8b450c           mov eax,dword [ebp + 12]
        .text:0x0040175c  50               push eax
        .text:0x0040175d  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00401760  51               push ecx
        .text:0x00401761  6800040000       push 1024
        .text:0x00401766  8d9500f8ffff     lea edx,dword [ebp - 2048]
        .text:0x0040176c  52               push edx
        .text:0x0040176d  e83efdffff       call 0x004014b0    ;sub_004014b0(local2052,1024,arg0,arg1,local3076,1024,local1028)
        .text:0x00401772  83c420           add esp,32
        .text:0x00401775  85c0             test eax,eax
        .text:0x00401777  7407             jz 0x00401780
        .text:0x00401779  b801000000       mov eax,1
        .text:0x0040177e  eb02             jmp 0x00401782
        .text:0x00401780  loc_00401780: [1 XREFS]
        .text:0x00401780  33c0             xor eax,eax
        .text:0x00401782  loc_00401782: [1 XREFS]
        .text:0x00401782  5f               pop edi
        .text:0x00401783  5e               pop esi
        .text:0x00401784  5b               pop ebx
        .text:0x00401785  8be5             mov esp,ebp
        .text:0x00401787  5d               pop ebp
        .text:0x00401788  c3               ret 
        */
        $c26 = { 55 8B EC 81 EC 0C 0C 00 00 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? 68 00 04 00 00 8D 8D ?? ?? ?? ?? 51 68 00 04 00 00 8D 95 ?? ?? ?? ?? 52 8B 45 ?? 50 8B 4D ?? 51 68 00 04 00 00 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 20 85 C0 74 ?? B8 01 00 00 00 EB ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00401790@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB NtGlobalFlag flag
        .text:0x00401790  
        .text:0x00401790  FUNC: int cdecl sub_00401790( int arg0, ) [2 XREFS] 
        .text:0x00401790  
        .text:0x00401790  Stack Variables: (offset from initial top of stack)
        .text:0x00401790             4: int arg0
        .text:0x00401790          -1028: int local1028
        .text:0x00401790          -2052: int local2052
        .text:0x00401790          -3076: int local3076
        .text:0x00401790          -4100: int local4100
        .text:0x00401790          -4104: int local4104
        .text:0x00401790          -4108: int local4108
        .text:0x00401790          -4112: int local4112
        .text:0x00401790  
        .text:0x00401790  55               push ebp
        .text:0x00401791  8bec             mov ebp,esp
        .text:0x00401793  b80c100000       mov eax,0x0000100c
        .text:0x00401798  e8d3210000       call 0x00403970    ;__alloca_probe()
        .text:0x0040179d  53               push ebx
        .text:0x0040179e  56               push esi
        .text:0x0040179f  57               push edi
        .text:0x004017a0  c785f8efffff0000 mov dword [ebp - 4104],0
        .text:0x004017aa  c785f4efffff0000 mov dword [ebp - 4108],0
        .text:0x004017b4  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004017ba  8a5802           mov bl,byte [eax + 2]
        .text:0x004017bd  889dfcefffff     mov byte [ebp - 4100],bl
        .text:0x004017c3  0fbe85fcefffff   movsx eax,byte [ebp - 4100]
        .text:0x004017ca  85c0             test eax,eax
        .text:0x004017cc  7405             jz 0x004017d3
        .text:0x004017ce  e82df8ffff       call 0x00401000    ;sub_00401000()
        .text:0x004017d3  loc_004017d3: [1 XREFS]
        .text:0x004017d3  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004017d9  8b4018           mov eax,dword [eax + 24]
        .text:0x004017dc  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x004017e0  8985f8efffff     mov dword [ebp - 4104],eax
        .text:0x004017e6  83bdf8efffff00   cmp dword [ebp - 4104],0
        .text:0x004017ed  7405             jz 0x004017f4
        .text:0x004017ef  e80cf8ffff       call 0x00401000    ;sub_00401000()
        .text:0x004017f4  loc_004017f4: [1 XREFS]
        .text:0x004017f4  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004017fa  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x004017fe  83e870           sub eax,112
        .text:0x00401801  8985f4efffff     mov dword [ebp - 4108],eax
        .text:0x00401807  83bdf4efffff00   cmp dword [ebp - 4108],0
        .text:0x0040180e  7505             jnz 0x00401815
        .text:0x00401810  e8ebf7ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401815  loc_00401815: [1 XREFS]
        .text:0x00401815  6800040000       push 1024
        .text:0x0040181a  8d8d00fcffff     lea ecx,dword [ebp - 1024]
        .text:0x00401820  51               push ecx
        .text:0x00401821  6800040000       push 1024
        .text:0x00401826  8d9500f0ffff     lea edx,dword [ebp - 4096]
        .text:0x0040182c  52               push edx
        .text:0x0040182d  6800040000       push 1024
        .text:0x00401832  8d8500f8ffff     lea eax,dword [ebp - 2048]
        .text:0x00401838  50               push eax
        .text:0x00401839  6800040000       push 1024
        .text:0x0040183e  8d8d00f4ffff     lea ecx,dword [ebp - 3072]
        .text:0x00401844  51               push ecx
        .text:0x00401845  e866fcffff       call 0x004014b0    ;sub_004014b0(local3076,1024,local2052,1024,local4100,1024,local1028)
        .text:0x0040184a  83c420           add esp,32
        .text:0x0040184d  85c0             test eax,eax
        .text:0x0040184f  7407             jz 0x00401858
        .text:0x00401851  b801000000       mov eax,1
        .text:0x00401856  eb16             jmp 0x0040186e
        .text:0x00401858  loc_00401858: [1 XREFS]
        .text:0x00401858  8d9500f0ffff     lea edx,dword [ebp - 4096]
        .text:0x0040185e  52               push edx
        .text:0x0040185f  e8c6210000       call 0x00403a2a    ;_atoi(local4100)
        .text:0x00401864  83c404           add esp,4
        .text:0x00401867  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x0040186a  8901             mov dword [ecx],eax
        .text:0x0040186c  33c0             xor eax,eax
        .text:0x0040186e  loc_0040186e: [1 XREFS]
        .text:0x0040186e  5f               pop edi
        .text:0x0040186f  5e               pop esi
        .text:0x00401870  5b               pop ebx
        .text:0x00401871  8be5             mov esp,ebp
        .text:0x00401873  5d               pop ebp
        .text:0x00401874  c3               ret 
        */
        $c27 = { 55 8B EC B8 0C 10 00 00 E8 ?? ?? ?? ?? 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? 68 00 04 00 00 8D 8D ?? ?? ?? ?? 51 68 00 04 00 00 8D 95 ?? ?? ?? ?? 52 68 00 04 00 00 8D 85 ?? ?? ?? ?? 50 68 00 04 00 00 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 20 85 C0 74 ?? B8 01 00 00 00 EB ?? 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 04 8B 4D ?? 89 01 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00401880@7faafc7e4a5c736ebfee6abbbc812d80 with 2 features:
          - check for PEB NtGlobalFlag flag
          - timestomp file
        .text:0x00401880  
        .text:0x00401880  FUNC: int cdecl sub_00401880( int arg0, int arg1, ) [2 XREFS] 
        .text:0x00401880  
        .text:0x00401880  Stack Variables: (offset from initial top of stack)
        .text:0x00401880             8: int arg1
        .text:0x00401880             4: int arg0
        .text:0x00401880           -12: int local12
        .text:0x00401880           -20: int local20
        .text:0x00401880           -28: int local28
        .text:0x00401880           -32: int local32
        .text:0x00401880           -36: int local36
        .text:0x00401880           -40: int local40
        .text:0x00401880           -44: int local44
        .text:0x00401880  
        .text:0x00401880  55               push ebp
        .text:0x00401881  8bec             mov ebp,esp
        .text:0x00401883  83ec28           sub esp,40
        .text:0x00401886  53               push ebx
        .text:0x00401887  56               push esi
        .text:0x00401888  57               push edi
        .text:0x00401889  c745dc00000000   mov dword [ebp - 36],0
        .text:0x00401890  c745d800000000   mov dword [ebp - 40],0
        .text:0x00401897  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040189d  8a5802           mov bl,byte [eax + 2]
        .text:0x004018a0  885de0           mov byte [ebp - 32],bl
        .text:0x004018a3  0fbe45e0         movsx eax,byte [ebp - 32]
        .text:0x004018a7  85c0             test eax,eax
        .text:0x004018a9  7405             jz 0x004018b0
        .text:0x004018ab  e850f7ffff       call 0x00401000    ;sub_00401000()
        .text:0x004018b0  loc_004018b0: [1 XREFS]
        .text:0x004018b0  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004018b6  8b4018           mov eax,dword [eax + 24]
        .text:0x004018b9  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x004018bd  8945dc           mov dword [ebp - 36],eax
        .text:0x004018c0  837ddc00         cmp dword [ebp - 36],0
        .text:0x004018c4  7405             jz 0x004018cb
        .text:0x004018c6  e835f7ffff       call 0x00401000    ;sub_00401000()
        .text:0x004018cb  loc_004018cb: [1 XREFS]
        .text:0x004018cb  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004018d1  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x004018d5  83e870           sub eax,112
        .text:0x004018d8  8945d8           mov dword [ebp - 40],eax
        .text:0x004018db  837dd800         cmp dword [ebp - 40],0
        .text:0x004018df  7505             jnz 0x004018e6
        .text:0x004018e1  e81af7ffff       call 0x00401000    ;sub_00401000()
        .text:0x004018e6  loc_004018e6: [1 XREFS]
        .text:0x004018e6  6a00             push 0
        .text:0x004018e8  6880000000       push 128
        .text:0x004018ed  6a03             push 3
        .text:0x004018ef  6a00             push 0
        .text:0x004018f1  6a01             push 1
        .text:0x004018f3  6800000080       push 0x80000000
        .text:0x004018f8  8b4d0c           mov ecx,dword [ebp + 12]
        .text:0x004018fb  51               push ecx
        .text:0x004018fc  ff154cb04000     call dword [0x0040b04c]    ;kernel32.CreateFileA(arg1,0x80000000,1,0,3,128,0)
        .text:0x00401902  8945e4           mov dword [ebp - 28],eax
        .text:0x00401905  837de400         cmp dword [ebp - 28],0
        .text:0x00401909  750a             jnz 0x00401915
        .text:0x0040190b  b801000000       mov eax,1
        .text:0x00401910  e98b000000       jmp 0x004019a0
        .text:0x00401915  loc_00401915: [1 XREFS]
        .text:0x00401915  8d55f0           lea edx,dword [ebp - 16]
        .text:0x00401918  52               push edx
        .text:0x00401919  8d45e8           lea eax,dword [ebp - 24]
        .text:0x0040191c  50               push eax
        .text:0x0040191d  8d4df8           lea ecx,dword [ebp - 8]
        .text:0x00401920  51               push ecx
        .text:0x00401921  8b55e4           mov edx,dword [ebp - 28]
        .text:0x00401924  52               push edx
        .text:0x00401925  ff1550b04000     call dword [0x0040b050]    ;kernel32.GetFileTime(kernel32.CreateFileA(arg1,0x80000000,1,0,3,128,0),local12,local28,local20)
        .text:0x0040192b  85c0             test eax,eax
        .text:0x0040192d  7511             jnz 0x00401940
        .text:0x0040192f  8b45e4           mov eax,dword [ebp - 28]
        .text:0x00401932  50               push eax
        .text:0x00401933  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(<0x004018fc>)
        .text:0x00401939  b801000000       mov eax,1
        .text:0x0040193e  eb60             jmp 0x004019a0
        .text:0x00401940  loc_00401940: [1 XREFS]
        .text:0x00401940  8b4de4           mov ecx,dword [ebp - 28]
        .text:0x00401943  51               push ecx
        .text:0x00401944  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(<0x004018fc>)
        .text:0x0040194a  6a00             push 0
        .text:0x0040194c  6880000000       push 128
        .text:0x00401951  6a03             push 3
        .text:0x00401953  6a00             push 0
        .text:0x00401955  6a02             push 2
        .text:0x00401957  6800000040       push 0x40000000
        .text:0x0040195c  8b5508           mov edx,dword [ebp + 8]
        .text:0x0040195f  52               push edx
        .text:0x00401960  ff154cb04000     call dword [0x0040b04c]    ;kernel32.CreateFileA(arg0,0x40000000,2,0,3,128,0)
        .text:0x00401966  8945e4           mov dword [ebp - 28],eax
        .text:0x00401969  8d45f0           lea eax,dword [ebp - 16]
        .text:0x0040196c  50               push eax
        .text:0x0040196d  8d4de8           lea ecx,dword [ebp - 24]
        .text:0x00401970  51               push ecx
        .text:0x00401971  8d55f8           lea edx,dword [ebp - 8]
        .text:0x00401974  52               push edx
        .text:0x00401975  8b45e4           mov eax,dword [ebp - 28]
        .text:0x00401978  50               push eax
        .text:0x00401979  ff1554b04000     call dword [0x0040b054]    ;kernel32.SetFileTime(kernel32.CreateFileA(arg0,0x40000000,2,0,3,128,0),local12,local28,local20)
        .text:0x0040197f  85c0             test eax,eax
        .text:0x00401981  7511             jnz 0x00401994
        .text:0x00401983  8b4de4           mov ecx,dword [ebp - 28]
        .text:0x00401986  51               push ecx
        .text:0x00401987  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(<0x00401960>)
        .text:0x0040198d  b801000000       mov eax,1
        .text:0x00401992  eb0c             jmp 0x004019a0
        .text:0x00401994  loc_00401994: [1 XREFS]
        .text:0x00401994  8b55e4           mov edx,dword [ebp - 28]
        .text:0x00401997  52               push edx
        .text:0x00401998  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(<0x00401960>)
        .text:0x0040199e  33c0             xor eax,eax
        .text:0x004019a0  loc_004019a0: [3 XREFS]
        .text:0x004019a0  5f               pop edi
        .text:0x004019a1  5e               pop esi
        .text:0x004019a2  5b               pop ebx
        .text:0x004019a3  8be5             mov esp,ebp
        .text:0x004019a5  5d               pop ebp
        .text:0x004019a6  c3               ret 
        */
        $c28 = { 55 8B EC 83 EC 28 53 56 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 5D ?? 0F BE 45 ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 45 ?? 83 7D ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 45 ?? 83 7D ?? 00 75 ?? E8 ?? ?? ?? ?? 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 00 75 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8D 55 ?? 52 8D 45 ?? 50 8D 4D ?? 51 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 6A 00 68 80 00 00 00 6A 03 6A 00 6A 02 68 00 00 00 40 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 89 45 ?? 8D 45 ?? 50 8D 4D ?? 51 8D 55 ?? 52 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x004019b0@7faafc7e4a5c736ebfee6abbbc812d80 with 2 features:
          - check for PEB NtGlobalFlag flag
          - get common file path
        .text:0x004019b0  
        .text:0x004019b0  FUNC: int cdecl sub_004019b0( int arg0, ) [4 XREFS] 
        .text:0x004019b0  
        .text:0x004019b0  Stack Variables: (offset from initial top of stack)
        .text:0x004019b0             4: int arg0
        .text:0x004019b0          -1028: int local1028
        .text:0x004019b0          -1032: int local1032
        .text:0x004019b0          -1036: int local1036
        .text:0x004019b0          -1040: int local1040
        .text:0x004019b0  
        .text:0x004019b0  55               push ebp
        .text:0x004019b1  8bec             mov ebp,esp
        .text:0x004019b3  81ec0c040000     sub esp,1036
        .text:0x004019b9  53               push ebx
        .text:0x004019ba  56               push esi
        .text:0x004019bb  57               push edi
        .text:0x004019bc  c785f8fbffff0000 mov dword [ebp - 1032],0
        .text:0x004019c6  c785f4fbffff0000 mov dword [ebp - 1036],0
        .text:0x004019d0  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004019d6  8a5802           mov bl,byte [eax + 2]
        .text:0x004019d9  889dfcfbffff     mov byte [ebp - 1028],bl
        .text:0x004019df  0fbe85fcfbffff   movsx eax,byte [ebp - 1028]
        .text:0x004019e6  85c0             test eax,eax
        .text:0x004019e8  7405             jz 0x004019ef
        .text:0x004019ea  e811f6ffff       call 0x00401000    ;sub_00401000()
        .text:0x004019ef  loc_004019ef: [1 XREFS]
        .text:0x004019ef  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004019f5  8b4018           mov eax,dword [eax + 24]
        .text:0x004019f8  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x004019fc  8985f8fbffff     mov dword [ebp - 1032],eax
        .text:0x00401a02  83bdf8fbffff00   cmp dword [ebp - 1032],0
        .text:0x00401a09  7405             jz 0x00401a10
        .text:0x00401a0b  e8f0f5ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401a10  loc_00401a10: [1 XREFS]
        .text:0x00401a10  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401a16  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x00401a1a  83e870           sub eax,112
        .text:0x00401a1d  8985f4fbffff     mov dword [ebp - 1036],eax
        .text:0x00401a23  83bdf4fbffff00   cmp dword [ebp - 1036],0
        .text:0x00401a2a  7505             jnz 0x00401a31
        .text:0x00401a2c  e8cff5ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401a31  loc_00401a31: [1 XREFS]
        .text:0x00401a31  6800040000       push 1024
        .text:0x00401a36  8d8d00fcffff     lea ecx,dword [ebp - 1024]
        .text:0x00401a3c  51               push ecx
        .text:0x00401a3d  ff1548b04000     call dword [0x0040b048]    ;kernel32.GetSystemDirectoryA(local1028,1024)
        .text:0x00401a43  85c0             test eax,eax
        .text:0x00401a45  7507             jnz 0x00401a4e
        .text:0x00401a47  b801000000       mov eax,1
        .text:0x00401a4c  eb54             jmp 0x00401aa2
        .text:0x00401a4e  loc_00401a4e: [1 XREFS]
        .text:0x00401a4e  bf70c04000       mov edi,0x0040c070
        .text:0x00401a53  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x00401a59  83c9ff           or ecx,0xffffffff
        .text:0x00401a5c  33c0             xor eax,eax
        .text:0x00401a5e  f2ae             repnz: scasb 
        .text:0x00401a60  f7d1             not ecx
        .text:0x00401a62  2bf9             sub edi,ecx
        .text:0x00401a64  8bf7             mov esi,edi
        .text:0x00401a66  8bd9             mov ebx,ecx
        .text:0x00401a68  8bfa             mov edi,edx
        .text:0x00401a6a  83c9ff           or ecx,0xffffffff
        .text:0x00401a6d  33c0             xor eax,eax
        .text:0x00401a6f  f2ae             repnz: scasb 
        .text:0x00401a71  83c7ff           add edi,0xffffffff
        .text:0x00401a74  8bcb             mov ecx,ebx
        .text:0x00401a76  c1e902           shr ecx,2
        .text:0x00401a79  f3a5             rep: movsd 
        .text:0x00401a7b  8bcb             mov ecx,ebx
        .text:0x00401a7d  83e103           and ecx,3
        .text:0x00401a80  f3a4             rep: movsb 
        .text:0x00401a82  8d8500fcffff     lea eax,dword [ebp - 1024]
        .text:0x00401a88  50               push eax
        .text:0x00401a89  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00401a8c  51               push ecx
        .text:0x00401a8d  e8eefdffff       call 0x00401880    ;sub_00401880(arg0,local1028)
        .text:0x00401a92  83c408           add esp,8
        .text:0x00401a95  85c0             test eax,eax
        .text:0x00401a97  7407             jz 0x00401aa0
        .text:0x00401a99  b801000000       mov eax,1
        .text:0x00401a9e  eb02             jmp 0x00401aa2
        .text:0x00401aa0  loc_00401aa0: [1 XREFS]
        .text:0x00401aa0  33c0             xor eax,eax
        .text:0x00401aa2  loc_00401aa2: [2 XREFS]
        .text:0x00401aa2  5f               pop edi
        .text:0x00401aa3  5e               pop esi
        .text:0x00401aa4  5b               pop ebx
        .text:0x00401aa5  8be5             mov esp,ebp
        .text:0x00401aa7  5d               pop ebp
        .text:0x00401aa8  c3               ret 
        */
        $c29 = { 55 8B EC 81 EC 0C 04 00 00 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? 68 00 04 00 00 8D 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 85 C0 75 ?? B8 01 00 00 00 EB ?? BF 70 C0 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 8D 85 ?? ?? ?? ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? B8 01 00 00 00 EB ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00401ab0@7faafc7e4a5c736ebfee6abbbc812d80 with 5 features:
          - act as TCP client
          - check for PEB NtGlobalFlag flag
          - connect TCP socket
          - initialize Winsock library
          - resolve DNS
        .text:0x00401ab0  
        .text:0x00401ab0  FUNC: int cdecl sub_00401ab0( int arg0, int arg1, int arg2, ) [8 XREFS] 
        .text:0x00401ab0  
        .text:0x00401ab0  Stack Variables: (offset from initial top of stack)
        .text:0x00401ab0            12: int arg2
        .text:0x00401ab0             8: int arg1
        .text:0x00401ab0             4: int arg0
        .text:0x00401ab0          -404: int local404
        .text:0x00401ab0          -408: int local408
        .text:0x00401ab0          -420: int local420
        .text:0x00401ab0          -422: int local422
        .text:0x00401ab0          -424: int local424
        .text:0x00401ab0          -428: int local428
        .text:0x00401ab0          -432: int local432
        .text:0x00401ab0          -436: int local436
        .text:0x00401ab0  
        .text:0x00401ab0  55               push ebp
        .text:0x00401ab1  8bec             mov ebp,esp
        .text:0x00401ab3  81ecb0010000     sub esp,432
        .text:0x00401ab9  53               push ebx
        .text:0x00401aba  56               push esi
        .text:0x00401abb  57               push edi
        .text:0x00401abc  c78554feffff0000 mov dword [ebp - 428],0
        .text:0x00401ac6  c78550feffff0000 mov dword [ebp - 432],0
        .text:0x00401ad0  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401ad6  8a5802           mov bl,byte [eax + 2]
        .text:0x00401ad9  889d58feffff     mov byte [ebp - 424],bl
        .text:0x00401adf  0fbe8558feffff   movsx eax,byte [ebp - 424]
        .text:0x00401ae6  85c0             test eax,eax
        .text:0x00401ae8  7405             jz 0x00401aef
        .text:0x00401aea  e811f5ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401aef  loc_00401aef: [1 XREFS]
        .text:0x00401aef  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401af5  8b4018           mov eax,dword [eax + 24]
        .text:0x00401af8  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x00401afc  898554feffff     mov dword [ebp - 428],eax
        .text:0x00401b02  83bd54feffff00   cmp dword [ebp - 428],0
        .text:0x00401b09  7405             jz 0x00401b10
        .text:0x00401b0b  e8f0f4ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401b10  loc_00401b10: [1 XREFS]
        .text:0x00401b10  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401b16  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x00401b1a  83e870           sub eax,112
        .text:0x00401b1d  898550feffff     mov dword [ebp - 432],eax
        .text:0x00401b23  83bd50feffff00   cmp dword [ebp - 432],0
        .text:0x00401b2a  7505             jnz 0x00401b31
        .text:0x00401b2c  e8cff4ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401b31  loc_00401b31: [1 XREFS]
        .text:0x00401b31  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00401b34  c701ffffffff     mov dword [ecx],0xffffffff
        .text:0x00401b3a  8d9570feffff     lea edx,dword [ebp - 400]
        .text:0x00401b40  52               push edx
        .text:0x00401b41  6802020000       push 514
        .text:0x00401b46  ff1544b14000     call dword [0x0040b144]    ;ws2_32.WSAStartup(514,local404)
        .text:0x00401b4c  85c0             test eax,eax
        .text:0x00401b4e  740a             jz 0x00401b5a
        .text:0x00401b50  b801000000       mov eax,1
        .text:0x00401b55  e9bb000000       jmp 0x00401c15
        .text:0x00401b5a  loc_00401b5a: [1 XREFS]
        .text:0x00401b5a  8b450c           mov eax,dword [ebp + 12]
        .text:0x00401b5d  50               push eax
        .text:0x00401b5e  ff1548b14000     call dword [0x0040b148]    ;ws2_32.gethostbyname(arg1)
        .text:0x00401b64  89856cfeffff     mov dword [ebp - 404],eax
        .text:0x00401b6a  83bd6cfeffff00   cmp dword [ebp - 404],0
        .text:0x00401b71  7510             jnz 0x00401b83
        .text:0x00401b73  ff1564b14000     call dword [0x0040b164]    ;ws2_32.WSACleanup()
        .text:0x00401b79  b801000000       mov eax,1
        .text:0x00401b7e  e992000000       jmp 0x00401c15
        .text:0x00401b83  loc_00401b83: [1 XREFS]
        .text:0x00401b83  6a06             push 6
        .text:0x00401b85  6a01             push 1
        .text:0x00401b87  6a02             push 2
        .text:0x00401b89  ff1550b14000     call dword [0x0040b150]    ;ws2_32.socket(2,1,6)
        .text:0x00401b8f  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00401b92  8901             mov dword [ecx],eax
        .text:0x00401b94  8b5508           mov edx,dword [ebp + 8]
        .text:0x00401b97  833aff           cmp dword [edx],0xffffffff
        .text:0x00401b9a  750d             jnz 0x00401ba9
        .text:0x00401b9c  ff1564b14000     call dword [0x0040b164]    ;ws2_32.WSACleanup()
        .text:0x00401ba2  b801000000       mov eax,1
        .text:0x00401ba7  eb6c             jmp 0x00401c15
        .text:0x00401ba9  loc_00401ba9: [1 XREFS]
        .text:0x00401ba9  66c7855cfeffff02 mov word [ebp - 420],2
        .text:0x00401bb2  8b856cfeffff     mov eax,dword [ebp - 404]
        .text:0x00401bb8  8b480c           mov ecx,dword [eax + 12]
        .text:0x00401bbb  8b11             mov edx,dword [ecx]
        .text:0x00401bbd  8b02             mov eax,dword [edx]
        .text:0x00401bbf  898560feffff     mov dword [ebp - 416],eax
        .text:0x00401bc5  668b4d10         mov cx,word [ebp + 16]
        .text:0x00401bc9  51               push ecx
        .text:0x00401bca  ff1554b14000     call dword [0x0040b154]    ;ws2_32.htons(0x6161500f)
        .text:0x00401bd0  6689855efeffff   mov word [ebp - 418],ax
        .text:0x00401bd7  6a10             push 16
        .text:0x00401bd9  8d955cfeffff     lea edx,dword [ebp - 420]
        .text:0x00401bdf  52               push edx
        .text:0x00401be0  8b4508           mov eax,dword [ebp + 8]
        .text:0x00401be3  8b08             mov ecx,dword [eax]
        .text:0x00401be5  51               push ecx
        .text:0x00401be6  ff1558b14000     call dword [0x0040b158]    ;ws2_32.connect(0x61616161,local424,16)
        .text:0x00401bec  83f8ff           cmp eax,0xffffffff
        .text:0x00401bef  7522             jnz 0x00401c13
        .text:0x00401bf1  8b5508           mov edx,dword [ebp + 8]
        .text:0x00401bf4  8b02             mov eax,dword [edx]
        .text:0x00401bf6  50               push eax
        .text:0x00401bf7  ff155cb14000     call dword [0x0040b15c]    ;ws2_32.closesocket(0x61616161)
        .text:0x00401bfd  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00401c00  c701ffffffff     mov dword [ecx],0xffffffff
        .text:0x00401c06  ff1564b14000     call dword [0x0040b164]    ;ws2_32.WSACleanup()
        .text:0x00401c0c  b801000000       mov eax,1
        .text:0x00401c11  eb02             jmp 0x00401c15
        .text:0x00401c13  loc_00401c13: [1 XREFS]
        .text:0x00401c13  33c0             xor eax,eax
        .text:0x00401c15  loc_00401c15: [4 XREFS]
        .text:0x00401c15  5f               pop edi
        .text:0x00401c16  5e               pop esi
        .text:0x00401c17  5b               pop ebx
        .text:0x00401c18  8be5             mov esp,ebp
        .text:0x00401c1a  5d               pop ebp
        .text:0x00401c1b  c3               ret 
        */
        $c30 = { 55 8B EC 81 EC B0 01 00 00 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? 8B 4D ?? C7 01 FF FF FF FF 8D 95 ?? ?? ?? ?? 52 68 02 02 00 00 FF 15 ?? ?? ?? ?? 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 6A 06 6A 01 6A 02 FF 15 ?? ?? ?? ?? 8B 4D ?? 89 01 8B 55 ?? 83 3A FF 75 ?? FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 66 C7 85 ?? ?? ?? ?? 02 00 8B 85 ?? ?? ?? ?? 8B 48 ?? 8B 11 8B 02 89 85 ?? ?? ?? ?? 66 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? 6A 10 8D 95 ?? ?? ?? ?? 52 8B 45 ?? 8B 08 51 FF 15 ?? ?? ?? ?? 83 F8 FF 75 ?? 8B 55 ?? 8B 02 50 FF 15 ?? ?? ?? ?? 8B 4D ?? C7 01 FF FF FF FF FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00401c20@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB NtGlobalFlag flag
        .text:0x00401c20  
        .text:0x00401c20  FUNC: int cdecl sub_00401c20( int arg0, ) [24 XREFS] 
        .text:0x00401c20  
        .text:0x00401c20  Stack Variables: (offset from initial top of stack)
        .text:0x00401c20             4: int arg0
        .text:0x00401c20            -8: int local8
        .text:0x00401c20           -12: int local12
        .text:0x00401c20           -16: int local16
        .text:0x00401c20  
        .text:0x00401c20  55               push ebp
        .text:0x00401c21  8bec             mov ebp,esp
        .text:0x00401c23  83ec0c           sub esp,12
        .text:0x00401c26  53               push ebx
        .text:0x00401c27  56               push esi
        .text:0x00401c28  57               push edi
        .text:0x00401c29  c745f800000000   mov dword [ebp - 8],0
        .text:0x00401c30  c745f400000000   mov dword [ebp - 12],0
        .text:0x00401c37  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401c3d  8a5802           mov bl,byte [eax + 2]
        .text:0x00401c40  885dfc           mov byte [ebp - 4],bl
        .text:0x00401c43  0fbe45fc         movsx eax,byte [ebp - 4]
        .text:0x00401c47  85c0             test eax,eax
        .text:0x00401c49  7405             jz 0x00401c50
        .text:0x00401c4b  e8b0f3ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401c50  loc_00401c50: [1 XREFS]
        .text:0x00401c50  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401c56  8b4018           mov eax,dword [eax + 24]
        .text:0x00401c59  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x00401c5d  8945f8           mov dword [ebp - 8],eax
        .text:0x00401c60  837df800         cmp dword [ebp - 8],0
        .text:0x00401c64  7405             jz 0x00401c6b
        .text:0x00401c66  e895f3ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401c6b  loc_00401c6b: [1 XREFS]
        .text:0x00401c6b  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401c71  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x00401c75  83e870           sub eax,112
        .text:0x00401c78  8945f4           mov dword [ebp - 12],eax
        .text:0x00401c7b  837df400         cmp dword [ebp - 12],0
        .text:0x00401c7f  7505             jnz 0x00401c86
        .text:0x00401c81  e87af3ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401c86  loc_00401c86: [1 XREFS]
        .text:0x00401c86  6a01             push 1
        .text:0x00401c88  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00401c8b  8b11             mov edx,dword [ecx]
        .text:0x00401c8d  52               push edx
        .text:0x00401c8e  ff1540b14000     call dword [0x0040b140]    ;ws2_32.shutdown(0x61616161,1)
        .text:0x00401c94  83f8ff           cmp eax,0xffffffff
        .text:0x00401c97  7519             jnz 0x00401cb2
        .text:0x00401c99  8b4508           mov eax,dword [ebp + 8]
        .text:0x00401c9c  8b08             mov ecx,dword [eax]
        .text:0x00401c9e  51               push ecx
        .text:0x00401c9f  ff155cb14000     call dword [0x0040b15c]    ;ws2_32.closesocket(0x61616161)
        .text:0x00401ca5  ff1564b14000     call dword [0x0040b164]    ;ws2_32.WSACleanup()
        .text:0x00401cab  b801000000       mov eax,1
        .text:0x00401cb0  eb14             jmp 0x00401cc6
        .text:0x00401cb2  loc_00401cb2: [1 XREFS]
        .text:0x00401cb2  8b5508           mov edx,dword [ebp + 8]
        .text:0x00401cb5  8b02             mov eax,dword [edx]
        .text:0x00401cb7  50               push eax
        .text:0x00401cb8  ff155cb14000     call dword [0x0040b15c]    ;ws2_32.closesocket(0x61616161)
        .text:0x00401cbe  ff1564b14000     call dword [0x0040b164]    ;ws2_32.WSACleanup()
        .text:0x00401cc4  33c0             xor eax,eax
        .text:0x00401cc6  loc_00401cc6: [1 XREFS]
        .text:0x00401cc6  5f               pop edi
        .text:0x00401cc7  5e               pop esi
        .text:0x00401cc8  5b               pop ebx
        .text:0x00401cc9  8be5             mov esp,ebp
        .text:0x00401ccb  5d               pop ebp
        .text:0x00401ccc  c3               ret 
        */
        $c31 = { 55 8B EC 83 EC 0C 53 56 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 5D ?? 0F BE 45 ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 45 ?? 83 7D ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 45 ?? 83 7D ?? 00 75 ?? E8 ?? ?? ?? ?? 6A 01 8B 4D ?? 8B 11 52 FF 15 ?? ?? ?? ?? 83 F8 FF 75 ?? 8B 45 ?? 8B 08 51 FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 8B 55 ?? 8B 02 50 FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00401cd0@7faafc7e4a5c736ebfee6abbbc812d80 with 3 features:
          - check for PEB NtGlobalFlag flag
          - send data
          - send data on socket
        .text:0x00401cd0  
        .text:0x00401cd0  FUNC: int cdecl sub_00401cd0( int arg0, int arg1, int arg2, ) [2 XREFS] 
        .text:0x00401cd0  
        .text:0x00401cd0  Stack Variables: (offset from initial top of stack)
        .text:0x00401cd0            12: int arg2
        .text:0x00401cd0             8: int arg1
        .text:0x00401cd0             4: int arg0
        .text:0x00401cd0            -8: int local8
        .text:0x00401cd0           -12: int local12
        .text:0x00401cd0          -524: int local524
        .text:0x00401cd0          -528: int local528
        .text:0x00401cd0          -532: int local532
        .text:0x00401cd0          -536: int local536
        .text:0x00401cd0          -540: int local540
        .text:0x00401cd0          -544: int local544
        .text:0x00401cd0  
        .text:0x00401cd0  55               push ebp
        .text:0x00401cd1  8bec             mov ebp,esp
        .text:0x00401cd3  81ec1c020000     sub esp,540
        .text:0x00401cd9  53               push ebx
        .text:0x00401cda  56               push esi
        .text:0x00401cdb  57               push edi
        .text:0x00401cdc  c745fc00000000   mov dword [ebp - 4],0
        .text:0x00401ce3  c785e8fdffff0000 mov dword [ebp - 536],0
        .text:0x00401ced  c785e4fdffff0000 mov dword [ebp - 540],0
        .text:0x00401cf7  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401cfd  8a5802           mov bl,byte [eax + 2]
        .text:0x00401d00  889decfdffff     mov byte [ebp - 532],bl
        .text:0x00401d06  0fbe85ecfdffff   movsx eax,byte [ebp - 532]
        .text:0x00401d0d  85c0             test eax,eax
        .text:0x00401d0f  7405             jz 0x00401d16
        .text:0x00401d11  e8eaf2ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401d16  loc_00401d16: [1 XREFS]
        .text:0x00401d16  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401d1c  8b4018           mov eax,dword [eax + 24]
        .text:0x00401d1f  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x00401d23  8985e8fdffff     mov dword [ebp - 536],eax
        .text:0x00401d29  83bde8fdffff00   cmp dword [ebp - 536],0
        .text:0x00401d30  7405             jz 0x00401d37
        .text:0x00401d32  e8c9f2ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401d37  loc_00401d37: [1 XREFS]
        .text:0x00401d37  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401d3d  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x00401d41  83e870           sub eax,112
        .text:0x00401d44  8985e4fdffff     mov dword [ebp - 540],eax
        .text:0x00401d4a  83bde4fdffff00   cmp dword [ebp - 540],0
        .text:0x00401d51  7505             jnz 0x00401d58
        .text:0x00401d53  e8a8f2ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401d58  loc_00401d58: [1 XREFS]
        .text:0x00401d58  8b4d0c           mov ecx,dword [ebp + 12]
        .text:0x00401d5b  51               push ecx
        .text:0x00401d5c  8b5508           mov edx,dword [ebp + 8]
        .text:0x00401d5f  52               push edx
        .text:0x00401d60  8d45fc           lea eax,dword [ebp - 4]
        .text:0x00401d63  50               push eax
        .text:0x00401d64  e847fdffff       call 0x00401ab0    ;sub_00401ab0(local8,arg0,arg1)
        .text:0x00401d69  83c40c           add esp,12
        .text:0x00401d6c  85c0             test eax,eax
        .text:0x00401d6e  740a             jz 0x00401d7a
        .text:0x00401d70  b801000000       mov eax,1
        .text:0x00401d75  e9a0000000       jmp 0x00401e1a
        .text:0x00401d7a  loc_00401d7a: [2 XREFS]
        .text:0x00401d7a  c785f4fdffff0000 mov dword [ebp - 524],0
        .text:0x00401d84  8b4d10           mov ecx,dword [ebp + 16]
        .text:0x00401d87  51               push ecx
        .text:0x00401d88  6800020000       push 512
        .text:0x00401d8d  6a01             push 1
        .text:0x00401d8f  8d95f8fdffff     lea edx,dword [ebp - 520]
        .text:0x00401d95  52               push edx
        .text:0x00401d96  e89a1c0000       call 0x00403a35    ;?(local524,1,512,arg2)
        .text:0x00401d9b  83c410           add esp,16
        .text:0x00401d9e  8945f8           mov dword [ebp - 8],eax
        .text:0x00401da1  loc_00401da1: [1 XREFS]
        .text:0x00401da1  6a00             push 0
        .text:0x00401da3  8b45f8           mov eax,dword [ebp - 8]
        .text:0x00401da6  50               push eax
        .text:0x00401da7  8d8df8fdffff     lea ecx,dword [ebp - 520]
        .text:0x00401dad  51               push ecx
        .text:0x00401dae  8b55fc           mov edx,dword [ebp - 4]
        .text:0x00401db1  52               push edx
        .text:0x00401db2  ff154cb14000     call dword [0x0040b14c]    ;ws2_32.send(0,local524,sub_00403a35(local524,1,512,arg2),0)
        .text:0x00401db8  8985f0fdffff     mov dword [ebp - 528],eax
        .text:0x00401dbe  83bdf0fdffffff   cmp dword [ebp - 528],0xffffffff
        .text:0x00401dc5  7513             jnz 0x00401dda
        .text:0x00401dc7  8d45fc           lea eax,dword [ebp - 4]
        .text:0x00401dca  50               push eax
        .text:0x00401dcb  e850feffff       call 0x00401c20    ;sub_00401c20(local8)
        .text:0x00401dd0  83c404           add esp,4
        .text:0x00401dd3  b801000000       mov eax,1
        .text:0x00401dd8  eb40             jmp 0x00401e1a
        .text:0x00401dda  loc_00401dda: [1 XREFS]
        .text:0x00401dda  8b8df4fdffff     mov ecx,dword [ebp - 524]
        .text:0x00401de0  038df0fdffff     add ecx,dword [ebp - 528]
        .text:0x00401de6  898df4fdffff     mov dword [ebp - 524],ecx
        .text:0x00401dec  8b95f4fdffff     mov edx,dword [ebp - 524]
        .text:0x00401df2  3b55f8           cmp edx,dword [ebp - 8]
        .text:0x00401df5  72aa             jc 0x00401da1
        .text:0x00401df7  837df800         cmp dword [ebp - 8],0
        .text:0x00401dfb  0f8779ffffff     ja 0x00401d7a
        .text:0x00401e01  8d45fc           lea eax,dword [ebp - 4]
        .text:0x00401e04  50               push eax
        .text:0x00401e05  e816feffff       call 0x00401c20    ;sub_00401c20(local8)
        .text:0x00401e0a  83c404           add esp,4
        .text:0x00401e0d  85c0             test eax,eax
        .text:0x00401e0f  7407             jz 0x00401e18
        .text:0x00401e11  b801000000       mov eax,1
        .text:0x00401e16  eb02             jmp 0x00401e1a
        .text:0x00401e18  loc_00401e18: [1 XREFS]
        .text:0x00401e18  33c0             xor eax,eax
        .text:0x00401e1a  loc_00401e1a: [3 XREFS]
        .text:0x00401e1a  5f               pop edi
        .text:0x00401e1b  5e               pop esi
        .text:0x00401e1c  5b               pop ebx
        .text:0x00401e1d  8be5             mov esp,ebp
        .text:0x00401e1f  5d               pop ebp
        .text:0x00401e20  c3               ret 
        */
        $c32 = { 55 8B EC 81 EC 1C 02 00 00 53 56 57 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? 8B 4D ?? 51 8B 55 ?? 52 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 8B 4D ?? 51 68 00 02 00 00 6A 01 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 10 89 45 ?? 6A 00 8B 45 ?? 50 8D 8D ?? ?? ?? ?? 51 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? FF 75 ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 04 B8 01 00 00 00 EB ?? 8B 8D ?? ?? ?? ?? 03 8D ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 3B 55 ?? 72 ?? 83 7D ?? 00 0F 87 ?? ?? ?? ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 ?? B8 01 00 00 00 EB ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00401e30@7faafc7e4a5c736ebfee6abbbc812d80 with 5 features:
          - check for PEB NtGlobalFlag flag
          - read and send data from client to server
          - read file on Windows
          - send data
          - send data on socket
        .text:0x00401e30  
        .text:0x00401e30  FUNC: int cdecl sub_00401e30( int arg0, int arg1, int arg2, ) [2 XREFS] 
        .text:0x00401e30  
        .text:0x00401e30  Stack Variables: (offset from initial top of stack)
        .text:0x00401e30            12: int arg2
        .text:0x00401e30             8: int arg1
        .text:0x00401e30             4: int arg0
        .text:0x00401e30            -8: int local8
        .text:0x00401e30           -12: int local12
        .text:0x00401e30          -524: int local524
        .text:0x00401e30          -528: int local528
        .text:0x00401e30          -532: int local532
        .text:0x00401e30          -536: int local536
        .text:0x00401e30          -540: int local540
        .text:0x00401e30          -544: int local544
        .text:0x00401e30          -548: int local548
        .text:0x00401e30  
        .text:0x00401e30  55               push ebp
        .text:0x00401e31  8bec             mov ebp,esp
        .text:0x00401e33  81ec20020000     sub esp,544
        .text:0x00401e39  53               push ebx
        .text:0x00401e3a  56               push esi
        .text:0x00401e3b  57               push edi
        .text:0x00401e3c  c745fc00000000   mov dword [ebp - 4],0
        .text:0x00401e43  c785e4fdffff0000 mov dword [ebp - 540],0
        .text:0x00401e4d  c785e0fdffff0000 mov dword [ebp - 544],0
        .text:0x00401e57  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401e5d  8a5802           mov bl,byte [eax + 2]
        .text:0x00401e60  889de8fdffff     mov byte [ebp - 536],bl
        .text:0x00401e66  0fbe85e8fdffff   movsx eax,byte [ebp - 536]
        .text:0x00401e6d  85c0             test eax,eax
        .text:0x00401e6f  7405             jz 0x00401e76
        .text:0x00401e71  e88af1ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401e76  loc_00401e76: [1 XREFS]
        .text:0x00401e76  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401e7c  8b4018           mov eax,dword [eax + 24]
        .text:0x00401e7f  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x00401e83  8985e4fdffff     mov dword [ebp - 540],eax
        .text:0x00401e89  83bde4fdffff00   cmp dword [ebp - 540],0
        .text:0x00401e90  7405             jz 0x00401e97
        .text:0x00401e92  e869f1ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401e97  loc_00401e97: [1 XREFS]
        .text:0x00401e97  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00401e9d  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x00401ea1  83e870           sub eax,112
        .text:0x00401ea4  8985e0fdffff     mov dword [ebp - 544],eax
        .text:0x00401eaa  83bde0fdffff00   cmp dword [ebp - 544],0
        .text:0x00401eb1  7505             jnz 0x00401eb8
        .text:0x00401eb3  e848f1ffff       call 0x00401000    ;sub_00401000()
        .text:0x00401eb8  loc_00401eb8: [1 XREFS]
        .text:0x00401eb8  8b4d0c           mov ecx,dword [ebp + 12]
        .text:0x00401ebb  51               push ecx
        .text:0x00401ebc  8b5508           mov edx,dword [ebp + 8]
        .text:0x00401ebf  52               push edx
        .text:0x00401ec0  8d45fc           lea eax,dword [ebp - 4]
        .text:0x00401ec3  50               push eax
        .text:0x00401ec4  e8e7fbffff       call 0x00401ab0    ;sub_00401ab0(local8,arg0,arg1)
        .text:0x00401ec9  83c40c           add esp,12
        .text:0x00401ecc  85c0             test eax,eax
        .text:0x00401ece  740a             jz 0x00401eda
        .text:0x00401ed0  b801000000       mov eax,1
        .text:0x00401ed5  e936010000       jmp 0x00402010
        .text:0x00401eda  loc_00401eda: [1 XREFS]
        .text:0x00401eda  6a00             push 0
        .text:0x00401edc  6880000000       push 128
        .text:0x00401ee1  6a03             push 3
        .text:0x00401ee3  6a00             push 0
        .text:0x00401ee5  6a01             push 1
        .text:0x00401ee7  6800000080       push 0x80000000
        .text:0x00401eec  8b4d10           mov ecx,dword [ebp + 16]
        .text:0x00401eef  51               push ecx
        .text:0x00401ef0  ff154cb04000     call dword [0x0040b04c]    ;kernel32.CreateFileA(arg2,0x80000000,1,0,3,128,0)
        .text:0x00401ef6  8985f4fdffff     mov dword [ebp - 524],eax
        .text:0x00401efc  83bdf4fdffffff   cmp dword [ebp - 524],0xffffffff
        .text:0x00401f03  7516             jnz 0x00401f1b
        .text:0x00401f05  8d55fc           lea edx,dword [ebp - 4]
        .text:0x00401f08  52               push edx
        .text:0x00401f09  e812fdffff       call 0x00401c20    ;sub_00401c20(local8)
        .text:0x00401f0e  83c404           add esp,4
        .text:0x00401f11  b801000000       mov eax,1
        .text:0x00401f16  e9f5000000       jmp 0x00402010
        .text:0x00401f1b  loc_00401f1b: [2 XREFS]
        .text:0x00401f1b  c785f0fdffff0000 mov dword [ebp - 528],0
        .text:0x00401f25  6a00             push 0
        .text:0x00401f27  8d45f8           lea eax,dword [ebp - 8]
        .text:0x00401f2a  50               push eax
        .text:0x00401f2b  6800020000       push 512
        .text:0x00401f30  8d8df8fdffff     lea ecx,dword [ebp - 520]
        .text:0x00401f36  51               push ecx
        .text:0x00401f37  8b95f4fdffff     mov edx,dword [ebp - 524]
        .text:0x00401f3d  52               push edx
        .text:0x00401f3e  ff1540b04000     call dword [0x0040b040]    ;kernel32.ReadFile(kernel32.CreateFileA(arg2,0x80000000,1,0,3,128,0),local524,512,local12,0)
        .text:0x00401f44  85c0             test eax,eax
        .text:0x00401f46  7535             jnz 0x00401f7d
        .text:0x00401f48  ff1544b04000     call dword [0x0040b044]    ;ntdll.RtlGetLastWin32Error()
        .text:0x00401f4e  83f826           cmp eax,38
        .text:0x00401f51  7423             jz 0x00401f76
        .text:0x00401f53  8d45fc           lea eax,dword [ebp - 4]
        .text:0x00401f56  50               push eax
        .text:0x00401f57  e8c4fcffff       call 0x00401c20    ;sub_00401c20(local8)
        .text:0x00401f5c  83c404           add esp,4
        .text:0x00401f5f  8b8df4fdffff     mov ecx,dword [ebp - 524]
        .text:0x00401f65  51               push ecx
        .text:0x00401f66  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(<0x00401ef0>)
        .text:0x00401f6c  b801000000       mov eax,1
        .text:0x00401f71  e99a000000       jmp 0x00402010
        .text:0x00401f76  loc_00401f76: [1 XREFS]
        .text:0x00401f76  c745f800000000   mov dword [ebp - 8],0
        .text:0x00401f7d  loc_00401f7d: [2 XREFS]
        .text:0x00401f7d  6a00             push 0
        .text:0x00401f7f  8b55f8           mov edx,dword [ebp - 8]
        .text:0x00401f82  52               push edx
        .text:0x00401f83  8d85f8fdffff     lea eax,dword [ebp - 520]
        .text:0x00401f89  50               push eax
        .text:0x00401f8a  8b4dfc           mov ecx,dword [ebp - 4]
        .text:0x00401f8d  51               push ecx
        .text:0x00401f8e  ff154cb14000     call dword [0x0040b14c]    ;ws2_32.send(0,local524,0xfefefefe,0)
        .text:0x00401f94  8985ecfdffff     mov dword [ebp - 532],eax
        .text:0x00401f9a  83bdecfdffffff   cmp dword [ebp - 532],0xffffffff
        .text:0x00401fa1  7520             jnz 0x00401fc3
        .text:0x00401fa3  8d55fc           lea edx,dword [ebp - 4]
        .text:0x00401fa6  52               push edx
        .text:0x00401fa7  e874fcffff       call 0x00401c20    ;sub_00401c20(local8)
        .text:0x00401fac  83c404           add esp,4
        .text:0x00401faf  8b85f4fdffff     mov eax,dword [ebp - 524]
        .text:0x00401fb5  50               push eax
        .text:0x00401fb6  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(<0x00401ef0>)
        .text:0x00401fbc  b801000000       mov eax,1
        .text:0x00401fc1  eb4d             jmp 0x00402010
        .text:0x00401fc3  loc_00401fc3: [1 XREFS]
        .text:0x00401fc3  8b8df0fdffff     mov ecx,dword [ebp - 528]
        .text:0x00401fc9  038decfdffff     add ecx,dword [ebp - 532]
        .text:0x00401fcf  898df0fdffff     mov dword [ebp - 528],ecx
        .text:0x00401fd5  8b95f0fdffff     mov edx,dword [ebp - 528]
        .text:0x00401fdb  3b55f8           cmp edx,dword [ebp - 8]
        .text:0x00401fde  729d             jc 0x00401f7d
        .text:0x00401fe0  837df800         cmp dword [ebp - 8],0
        .text:0x00401fe4  0f8731ffffff     ja 0x00401f1b
        .text:0x00401fea  8b85f4fdffff     mov eax,dword [ebp - 524]
        .text:0x00401ff0  50               push eax
        .text:0x00401ff1  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(<0x00401ef0>)
        .text:0x00401ff7  8d4dfc           lea ecx,dword [ebp - 4]
        .text:0x00401ffa  51               push ecx
        .text:0x00401ffb  e820fcffff       call 0x00401c20    ;sub_00401c20(local8)
        .text:0x00402000  83c404           add esp,4
        .text:0x00402003  85c0             test eax,eax
        .text:0x00402005  7407             jz 0x0040200e
        .text:0x00402007  b801000000       mov eax,1
        .text:0x0040200c  eb02             jmp 0x00402010
        .text:0x0040200e  loc_0040200e: [1 XREFS]
        .text:0x0040200e  33c0             xor eax,eax
        .text:0x00402010  loc_00402010: [5 XREFS]
        .text:0x00402010  5f               pop edi
        .text:0x00402011  5e               pop esi
        .text:0x00402012  5b               pop ebx
        .text:0x00402013  8be5             mov esp,ebp
        .text:0x00402015  5d               pop ebp
        .text:0x00402016  c3               ret 
        */
        $c33 = { 55 8B EC 81 EC 20 02 00 00 53 56 57 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? 8B 4D ?? 51 8B 55 ?? 52 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? FF 75 ?? 8D 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 04 B8 01 00 00 00 E9 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 6A 00 8D 45 ?? 50 68 00 02 00 00 8D 8D ?? ?? ?? ?? 51 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? FF 15 ?? ?? ?? ?? 83 F8 26 74 ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 04 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 6A 00 8B 55 ?? 52 8D 85 ?? ?? ?? ?? 50 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? FF 75 ?? 8D 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 04 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 8B 8D ?? ?? ?? ?? 03 8D ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 3B 55 ?? 72 ?? 83 7D ?? 00 0F 87 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 ?? B8 01 00 00 00 EB ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00402020@7faafc7e4a5c736ebfee6abbbc812d80 with 5 features:
          - check for PEB NtGlobalFlag flag
          - receive and write data from server to client
          - receive data
          - receive data on socket
          - write file on Windows
        .text:0x00402020  
        .text:0x00402020  FUNC: int cdecl sub_00402020( int arg0, int arg1, int arg2, ) [2 XREFS] 
        .text:0x00402020  
        .text:0x00402020  Stack Variables: (offset from initial top of stack)
        .text:0x00402020            12: int arg2
        .text:0x00402020             8: int arg1
        .text:0x00402020             4: int arg0
        .text:0x00402020            -8: int local8
        .text:0x00402020           -12: int local12
        .text:0x00402020          -524: int local524
        .text:0x00402020          -528: int local528
        .text:0x00402020          -532: int local532
        .text:0x00402020          -536: int local536
        .text:0x00402020          -540: int local540
        .text:0x00402020  
        .text:0x00402020  55               push ebp
        .text:0x00402021  8bec             mov ebp,esp
        .text:0x00402023  81ec18020000     sub esp,536
        .text:0x00402029  53               push ebx
        .text:0x0040202a  56               push esi
        .text:0x0040202b  57               push edi
        .text:0x0040202c  c745f800000000   mov dword [ebp - 8],0
        .text:0x00402033  c785ecfdffff0000 mov dword [ebp - 532],0
        .text:0x0040203d  c785e8fdffff0000 mov dword [ebp - 536],0
        .text:0x00402047  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040204d  8a5802           mov bl,byte [eax + 2]
        .text:0x00402050  889df0fdffff     mov byte [ebp - 528],bl
        .text:0x00402056  0fbe85f0fdffff   movsx eax,byte [ebp - 528]
        .text:0x0040205d  85c0             test eax,eax
        .text:0x0040205f  7405             jz 0x00402066
        .text:0x00402061  e89aefffff       call 0x00401000    ;sub_00401000()
        .text:0x00402066  loc_00402066: [1 XREFS]
        .text:0x00402066  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040206c  8b4018           mov eax,dword [eax + 24]
        .text:0x0040206f  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x00402073  8985ecfdffff     mov dword [ebp - 532],eax
        .text:0x00402079  83bdecfdffff00   cmp dword [ebp - 532],0
        .text:0x00402080  7405             jz 0x00402087
        .text:0x00402082  e879efffff       call 0x00401000    ;sub_00401000()
        .text:0x00402087  loc_00402087: [1 XREFS]
        .text:0x00402087  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040208d  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x00402091  83e870           sub eax,112
        .text:0x00402094  8985e8fdffff     mov dword [ebp - 536],eax
        .text:0x0040209a  83bde8fdffff00   cmp dword [ebp - 536],0
        .text:0x004020a1  7505             jnz 0x004020a8
        .text:0x004020a3  e858efffff       call 0x00401000    ;sub_00401000()
        .text:0x004020a8  loc_004020a8: [1 XREFS]
        .text:0x004020a8  8b4d0c           mov ecx,dword [ebp + 12]
        .text:0x004020ab  51               push ecx
        .text:0x004020ac  8b5508           mov edx,dword [ebp + 8]
        .text:0x004020af  52               push edx
        .text:0x004020b0  8d45f8           lea eax,dword [ebp - 8]
        .text:0x004020b3  50               push eax
        .text:0x004020b4  e8f7f9ffff       call 0x00401ab0    ;sub_00401ab0(local12,arg0,arg1)
        .text:0x004020b9  83c40c           add esp,12
        .text:0x004020bc  85c0             test eax,eax
        .text:0x004020be  740a             jz 0x004020ca
        .text:0x004020c0  b801000000       mov eax,1
        .text:0x004020c5  e9d4000000       jmp 0x0040219e
        .text:0x004020ca  loc_004020ca: [1 XREFS]
        .text:0x004020ca  6a00             push 0
        .text:0x004020cc  6880000000       push 128
        .text:0x004020d1  6a02             push 2
        .text:0x004020d3  6a00             push 0
        .text:0x004020d5  6a02             push 2
        .text:0x004020d7  6800000040       push 0x40000000
        .text:0x004020dc  8b4d10           mov ecx,dword [ebp + 16]
        .text:0x004020df  51               push ecx
        .text:0x004020e0  ff154cb04000     call dword [0x0040b04c]    ;kernel32.CreateFileA(arg2,0x40000000,2,0,2,128,0)
        .text:0x004020e6  8985f4fdffff     mov dword [ebp - 524],eax
        .text:0x004020ec  83bdf4fdffffff   cmp dword [ebp - 524],0xffffffff
        .text:0x004020f3  7516             jnz 0x0040210b
        .text:0x004020f5  8d55f8           lea edx,dword [ebp - 8]
        .text:0x004020f8  52               push edx
        .text:0x004020f9  e822fbffff       call 0x00401c20    ;sub_00401c20(local12)
        .text:0x004020fe  83c404           add esp,4
        .text:0x00402101  b801000000       mov eax,1
        .text:0x00402106  e993000000       jmp 0x0040219e
        .text:0x0040210b  loc_0040210b: [2 XREFS]
        .text:0x0040210b  6a00             push 0
        .text:0x0040210d  6800020000       push 512
        .text:0x00402112  8d85f8fdffff     lea eax,dword [ebp - 520]
        .text:0x00402118  50               push eax
        .text:0x00402119  8b4df8           mov ecx,dword [ebp - 8]
        .text:0x0040211c  51               push ecx
        .text:0x0040211d  ff1560b14000     call dword [0x0040b160]    ;ws2_32.recv(0,local524,512)
        .text:0x00402123  8945fc           mov dword [ebp - 4],eax
        .text:0x00402126  6a00             push 0
        .text:0x00402128  6a00             push 0
        .text:0x0040212a  8b55fc           mov edx,dword [ebp - 4]
        .text:0x0040212d  52               push edx
        .text:0x0040212e  8d85f8fdffff     lea eax,dword [ebp - 520]
        .text:0x00402134  50               push eax
        .text:0x00402135  8b8df4fdffff     mov ecx,dword [ebp - 524]
        .text:0x0040213b  51               push ecx
        .text:0x0040213c  ff153cb04000     call dword [0x0040b03c]    ;kernel32.WriteFile(kernel32.CreateFileA(arg2,0x40000000,2,0,2,128,0),local524,ws2_32.recv(0,local524,512),0,0)
        .text:0x00402142  85c0             test eax,eax
        .text:0x00402144  7520             jnz 0x00402166
        .text:0x00402146  8d55f8           lea edx,dword [ebp - 8]
        .text:0x00402149  52               push edx
        .text:0x0040214a  e8d1faffff       call 0x00401c20    ;sub_00401c20(local12)
        .text:0x0040214f  83c404           add esp,4
        .text:0x00402152  8b85f4fdffff     mov eax,dword [ebp - 524]
        .text:0x00402158  50               push eax
        .text:0x00402159  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(<0x004020e0>)
        .text:0x0040215f  b801000000       mov eax,1
        .text:0x00402164  eb38             jmp 0x0040219e
        .text:0x00402166  loc_00402166: [1 XREFS]
        .text:0x00402166  837dfc00         cmp dword [ebp - 4],0
        .text:0x0040216a  7f9f             jg 0x0040210b
        .text:0x0040216c  8b8df4fdffff     mov ecx,dword [ebp - 524]
        .text:0x00402172  51               push ecx
        .text:0x00402173  ff1558b04000     call dword [0x0040b058]    ;kernel32.CloseHandle(<0x004020e0>)
        .text:0x00402179  8d55f8           lea edx,dword [ebp - 8]
        .text:0x0040217c  52               push edx
        .text:0x0040217d  e89efaffff       call 0x00401c20    ;sub_00401c20(local12)
        .text:0x00402182  83c404           add esp,4
        .text:0x00402185  85c0             test eax,eax
        .text:0x00402187  7407             jz 0x00402190
        .text:0x00402189  b801000000       mov eax,1
        .text:0x0040218e  eb0e             jmp 0x0040219e
        .text:0x00402190  loc_00402190: [1 XREFS]
        .text:0x00402190  8b4510           mov eax,dword [ebp + 16]
        .text:0x00402193  50               push eax
        .text:0x00402194  e817f8ffff       call 0x004019b0    ;sub_004019b0(arg2)
        .text:0x00402199  83c404           add esp,4
        .text:0x0040219c  33c0             xor eax,eax
        .text:0x0040219e  loc_0040219e: [4 XREFS]
        .text:0x0040219e  5f               pop edi
        .text:0x0040219f  5e               pop esi
        .text:0x004021a0  5b               pop ebx
        .text:0x004021a1  8be5             mov esp,ebp
        .text:0x004021a3  5d               pop ebp
        .text:0x004021a4  c3               ret 
        */
        $c34 = { 55 8B EC 81 EC 18 02 00 00 53 56 57 C7 45 ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? 8B 4D ?? 51 8B 55 ?? 52 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 6A 00 68 80 00 00 00 6A 02 6A 00 6A 02 68 00 00 00 40 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? FF 75 ?? 8D 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 04 B8 01 00 00 00 E9 ?? ?? ?? ?? 6A 00 68 00 02 00 00 8D 85 ?? ?? ?? ?? 50 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 45 ?? 6A 00 6A 00 8B 55 ?? 52 8D 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8D 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 04 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 83 7D ?? 00 7F ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 8D 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 ?? B8 01 00 00 00 EB ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 04 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x004021b0@7faafc7e4a5c736ebfee6abbbc812d80 with 6 features:
          - check for PEB NtGlobalFlag flag
          - receive data
          - receive data on socket
          - send HTTP request
          - send data
          - send data on socket
        .text:0x004021b0  
        .text:0x004021b0  FUNC: int cdecl sub_004021b0( int arg0, int arg1, int arg2, int arg3, int arg4, ) [2 XREFS] 
        .text:0x004021b0  
        .text:0x004021b0  Stack Variables: (offset from initial top of stack)
        .text:0x004021b0            20: int arg4
        .text:0x004021b0            16: int arg3
        .text:0x004021b0            12: int arg2
        .text:0x004021b0             8: int arg1
        .text:0x004021b0             4: int arg0
        .text:0x004021b0            -8: int local8
        .text:0x004021b0          -1032: int local1032
        .text:0x004021b0          -1036: int local1036
        .text:0x004021b0          -1040: int local1040
        .text:0x004021b0          -1552: int local1552
        .text:0x004021b0          -1556: int local1556
        .text:0x004021b0          -1560: int local1560
        .text:0x004021b0          -1564: int local1564
        .text:0x004021b0          -1568: int local1568
        .text:0x004021b0  
        .text:0x004021b0  55               push ebp
        .text:0x004021b1  8bec             mov ebp,esp
        .text:0x004021b3  81ec1c060000     sub esp,1564
        .text:0x004021b9  53               push ebx
        .text:0x004021ba  56               push esi
        .text:0x004021bb  57               push edi
        .text:0x004021bc  c785f4fbffff0000 mov dword [ebp - 1036],0
        .text:0x004021c6  c785f8fbffff0000 mov dword [ebp - 1032],0
        .text:0x004021d0  c785e8f9ffff0000 mov dword [ebp - 1560],0
        .text:0x004021da  c785e4f9ffff0000 mov dword [ebp - 1564],0
        .text:0x004021e4  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004021ea  8a5802           mov bl,byte [eax + 2]
        .text:0x004021ed  889decf9ffff     mov byte [ebp - 1556],bl
        .text:0x004021f3  0fbe85ecf9ffff   movsx eax,byte [ebp - 1556]
        .text:0x004021fa  85c0             test eax,eax
        .text:0x004021fc  7405             jz 0x00402203
        .text:0x004021fe  e8fdedffff       call 0x00401000    ;sub_00401000()
        .text:0x00402203  loc_00402203: [1 XREFS]
        .text:0x00402203  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402209  8b4018           mov eax,dword [eax + 24]
        .text:0x0040220c  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x00402210  8985e8f9ffff     mov dword [ebp - 1560],eax
        .text:0x00402216  83bde8f9ffff00   cmp dword [ebp - 1560],0
        .text:0x0040221d  7405             jz 0x00402224
        .text:0x0040221f  e8dcedffff       call 0x00401000    ;sub_00401000()
        .text:0x00402224  loc_00402224: [1 XREFS]
        .text:0x00402224  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040222a  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x0040222e  83e870           sub eax,112
        .text:0x00402231  8985e4f9ffff     mov dword [ebp - 1564],eax
        .text:0x00402237  83bde4f9ffff00   cmp dword [ebp - 1564],0
        .text:0x0040223e  7505             jnz 0x00402245
        .text:0x00402240  e8bbedffff       call 0x00401000    ;sub_00401000()
        .text:0x00402245  loc_00402245: [1 XREFS]
        .text:0x00402245  8b4d0c           mov ecx,dword [ebp + 12]
        .text:0x00402248  51               push ecx
        .text:0x00402249  8b5508           mov edx,dword [ebp + 8]
        .text:0x0040224c  52               push edx
        .text:0x0040224d  8d85f4fbffff     lea eax,dword [ebp - 1036]
        .text:0x00402253  50               push eax
        .text:0x00402254  e857f8ffff       call 0x00401ab0    ;sub_00401ab0(local1040,arg0,arg1)
        .text:0x00402259  83c40c           add esp,12
        .text:0x0040225c  85c0             test eax,eax
        .text:0x0040225e  740a             jz 0x0040226a
        .text:0x00402260  b801000000       mov eax,1
        .text:0x00402265  e9c7010000       jmp 0x00402431
        .text:0x0040226a  loc_0040226a: [1 XREFS]
        .text:0x0040226a  bf98c04000       mov edi,0x0040c098
        .text:0x0040226f  8d95fcfbffff     lea edx,dword [ebp - 1028]
        .text:0x00402275  83c9ff           or ecx,0xffffffff
        .text:0x00402278  33c0             xor eax,eax
        .text:0x0040227a  f2ae             repnz: scasb 
        .text:0x0040227c  f7d1             not ecx
        .text:0x0040227e  2bf9             sub edi,ecx
        .text:0x00402280  8bf7             mov esi,edi
        .text:0x00402282  8bc1             mov eax,ecx
        .text:0x00402284  8bfa             mov edi,edx
        .text:0x00402286  c1e902           shr ecx,2
        .text:0x00402289  f3a5             rep: movsd 
        .text:0x0040228b  8bc8             mov ecx,eax
        .text:0x0040228d  83e103           and ecx,3
        .text:0x00402290  f3a4             rep: movsb 
        .text:0x00402292  8b7d10           mov edi,dword [ebp + 16]
        .text:0x00402295  8d95fcfbffff     lea edx,dword [ebp - 1028]
        .text:0x0040229b  83c9ff           or ecx,0xffffffff
        .text:0x0040229e  33c0             xor eax,eax
        .text:0x004022a0  f2ae             repnz: scasb 
        .text:0x004022a2  f7d1             not ecx
        .text:0x004022a4  2bf9             sub edi,ecx
        .text:0x004022a6  8bf7             mov esi,edi
        .text:0x004022a8  8bd9             mov ebx,ecx
        .text:0x004022aa  8bfa             mov edi,edx
        .text:0x004022ac  83c9ff           or ecx,0xffffffff
        .text:0x004022af  33c0             xor eax,eax
        .text:0x004022b1  f2ae             repnz: scasb 
        .text:0x004022b3  83c7ff           add edi,0xffffffff
        .text:0x004022b6  8bcb             mov ecx,ebx
        .text:0x004022b8  c1e902           shr ecx,2
        .text:0x004022bb  f3a5             rep: movsd 
        .text:0x004022bd  8bcb             mov ecx,ebx
        .text:0x004022bf  83e103           and ecx,3
        .text:0x004022c2  f3a4             rep: movsb 
        .text:0x004022c4  bf88c04000       mov edi,0x0040c088
        .text:0x004022c9  8d95fcfbffff     lea edx,dword [ebp - 1028]
        .text:0x004022cf  83c9ff           or ecx,0xffffffff
        .text:0x004022d2  33c0             xor eax,eax
        .text:0x004022d4  f2ae             repnz: scasb 
        .text:0x004022d6  f7d1             not ecx
        .text:0x004022d8  2bf9             sub edi,ecx
        .text:0x004022da  8bf7             mov esi,edi
        .text:0x004022dc  8bd9             mov ebx,ecx
        .text:0x004022de  8bfa             mov edi,edx
        .text:0x004022e0  83c9ff           or ecx,0xffffffff
        .text:0x004022e3  33c0             xor eax,eax
        .text:0x004022e5  f2ae             repnz: scasb 
        .text:0x004022e7  83c7ff           add edi,0xffffffff
        .text:0x004022ea  8bcb             mov ecx,ebx
        .text:0x004022ec  c1e902           shr ecx,2
        .text:0x004022ef  f3a5             rep: movsd 
        .text:0x004022f1  8bcb             mov ecx,ebx
        .text:0x004022f3  83e103           and ecx,3
        .text:0x004022f6  f3a4             rep: movsb 
        .text:0x004022f8  6a00             push 0
        .text:0x004022fa  8dbdfcfbffff     lea edi,dword [ebp - 1028]
        .text:0x00402300  83c9ff           or ecx,0xffffffff
        .text:0x00402303  33c0             xor eax,eax
        .text:0x00402305  f2ae             repnz: scasb 
        .text:0x00402307  f7d1             not ecx
        .text:0x00402309  83c1ff           add ecx,0xffffffff
        .text:0x0040230c  51               push ecx
        .text:0x0040230d  8d85fcfbffff     lea eax,dword [ebp - 1028]
        .text:0x00402313  50               push eax
        .text:0x00402314  8b8df4fbffff     mov ecx,dword [ebp - 1036]
        .text:0x0040231a  51               push ecx
        .text:0x0040231b  ff154cb14000     call dword [0x0040b14c]    ;ws2_32.send(0,local1032,0xffffffff,0)
        .text:0x00402321  8985f0f9ffff     mov dword [ebp - 1552],eax
        .text:0x00402327  83bdf0f9ffffff   cmp dword [ebp - 1552],0xffffffff
        .text:0x0040232e  751d             jnz 0x0040234d
        .text:0x00402330  8b95f4fbffff     mov edx,dword [ebp - 1036]
        .text:0x00402336  52               push edx
        .text:0x00402337  ff155cb14000     call dword [0x0040b15c]    ;ws2_32.closesocket(0)
        .text:0x0040233d  ff1564b14000     call dword [0x0040b164]    ;ws2_32.WSACleanup()
        .text:0x00402343  b801000000       mov eax,1
        .text:0x00402348  e9e4000000       jmp 0x00402431
        .text:0x0040234d  loc_0040234d: [2 XREFS]
        .text:0x0040234d  6a00             push 0
        .text:0x0040234f  6800020000       push 512
        .text:0x00402354  8d85f4f9ffff     lea eax,dword [ebp - 1548]
        .text:0x0040235a  50               push eax
        .text:0x0040235b  8b8df4fbffff     mov ecx,dword [ebp - 1036]
        .text:0x00402361  51               push ecx
        .text:0x00402362  ff1560b14000     call dword [0x0040b160]    ;ws2_32.recv(0,local1552,512)
        .text:0x00402368  8945fc           mov dword [ebp - 4],eax
        .text:0x0040236b  837dfc00         cmp dword [ebp - 4],0
        .text:0x0040236f  7e71             jle 0x004023e2
        .text:0x00402371  8b95f8fbffff     mov edx,dword [ebp - 1032]
        .text:0x00402377  0355fc           add edx,dword [ebp - 4]
        .text:0x0040237a  8b4518           mov eax,dword [ebp + 24]
        .text:0x0040237d  3b10             cmp edx,dword [eax]
        .text:0x0040237f  7619             jbe 0x0040239a
        .text:0x00402381  8d8df4fbffff     lea ecx,dword [ebp - 1036]
        .text:0x00402387  51               push ecx
        .text:0x00402388  e893f8ffff       call 0x00401c20    ;sub_00401c20(local1040)
        .text:0x0040238d  83c404           add esp,4
        .text:0x00402390  b801000000       mov eax,1
        .text:0x00402395  e997000000       jmp 0x00402431
        .text:0x0040239a  loc_0040239a: [1 XREFS]
        .text:0x0040239a  8b4dfc           mov ecx,dword [ebp - 4]
        .text:0x0040239d  8db5f4f9ffff     lea esi,dword [ebp - 1548]
        .text:0x004023a3  8b7d14           mov edi,dword [ebp + 20]
        .text:0x004023a6  03bdf8fbffff     add edi,dword [ebp - 1032]
        .text:0x004023ac  8bd1             mov edx,ecx
        .text:0x004023ae  c1e902           shr ecx,2
        .text:0x004023b1  f3a5             rep: movsd 
        .text:0x004023b3  8bca             mov ecx,edx
        .text:0x004023b5  83e103           and ecx,3
        .text:0x004023b8  f3a4             rep: movsb 
        .text:0x004023ba  8b85f8fbffff     mov eax,dword [ebp - 1032]
        .text:0x004023c0  0345fc           add eax,dword [ebp - 4]
        .text:0x004023c3  8985f8fbffff     mov dword [ebp - 1032],eax
        .text:0x004023c9  6880c04000       push 0x0040c080
        .text:0x004023ce  8b4d14           mov ecx,dword [ebp + 20]
        .text:0x004023d1  51               push ecx
        .text:0x004023d2  e849170000       call 0x00403b20    ;_strstr(arg3,0x0040c080)
        .text:0x004023d7  83c408           add esp,8
        .text:0x004023da  85c0             test eax,eax
        .text:0x004023dc  7402             jz 0x004023e0
        .text:0x004023de  eb2a             jmp 0x0040240a
        .text:0x004023e0  loc_004023e0: [1 XREFS]
        .text:0x004023e0  eb1e             jmp 0x00402400
        .text:0x004023e2  loc_004023e2: [1 XREFS]
        .text:0x004023e2  837dfc00         cmp dword [ebp - 4],0
        .text:0x004023e6  7502             jnz 0x004023ea
        .text:0x004023e8  eb16             jmp 0x00402400
        .text:0x004023ea  loc_004023ea: [1 XREFS]
        .text:0x004023ea  8d95f4fbffff     lea edx,dword [ebp - 1036]
        .text:0x004023f0  52               push edx
        .text:0x004023f1  e82af8ffff       call 0x00401c20    ;sub_00401c20(local1040)
        .text:0x004023f6  83c404           add esp,4
        .text:0x004023f9  b801000000       mov eax,1
        .text:0x004023fe  eb31             jmp 0x00402431
        .text:0x00402400  loc_00402400: [2 XREFS]
        .text:0x00402400  837dfc00         cmp dword [ebp - 4],0
        .text:0x00402404  0f8f43ffffff     jg 0x0040234d
        .text:0x0040240a  loc_0040240a: [1 XREFS]
        .text:0x0040240a  8d85f4fbffff     lea eax,dword [ebp - 1036]
        .text:0x00402410  50               push eax
        .text:0x00402411  e80af8ffff       call 0x00401c20    ;sub_00401c20(local1040)
        .text:0x00402416  83c404           add esp,4
        .text:0x00402419  85c0             test eax,eax
        .text:0x0040241b  7407             jz 0x00402424
        .text:0x0040241d  b801000000       mov eax,1
        .text:0x00402422  eb0d             jmp 0x00402431
        .text:0x00402424  loc_00402424: [1 XREFS]
        .text:0x00402424  8b4d18           mov ecx,dword [ebp + 24]
        .text:0x00402427  8b95f8fbffff     mov edx,dword [ebp - 1032]
        .text:0x0040242d  8911             mov dword [ecx],edx
        .text:0x0040242f  33c0             xor eax,eax
        .text:0x00402431  loc_00402431: [5 XREFS]
        .text:0x00402431  5f               pop edi
        .text:0x00402432  5e               pop esi
        .text:0x00402433  5b               pop ebx
        .text:0x00402434  8be5             mov esp,ebp
        .text:0x00402436  5d               pop ebp
        .text:0x00402437  c3               ret 
        */
        $c35 = { 55 8B EC 81 EC 1C 06 00 00 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? 8B 4D ?? 51 8B 55 ?? 52 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? BF 98 C0 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 BF 88 C0 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 6A 00 8D BD ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 51 8D 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? FF 75 ?? 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 6A 00 68 00 02 00 00 8D 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 00 7E ?? 8B 95 ?? ?? ?? ?? 03 55 ?? 8B 45 ?? 3B 10 76 ?? 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 04 B8 01 00 00 00 E9 ?? ?? ?? ?? 8B 4D ?? 8D B5 ?? ?? ?? ?? 8B 7D ?? 03 BD ?? ?? ?? ?? 8B D1 C1 E9 02 F3 A5 8B CA 83 E1 03 F3 A4 8B 85 ?? ?? ?? ?? 03 45 ?? 89 85 ?? ?? ?? ?? 68 80 C0 40 00 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? EB ?? EB ?? 83 7D ?? 00 75 ?? EB ?? 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 04 B8 01 00 00 00 EB ?? 83 7D ?? 00 0F 8F ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 ?? B8 01 00 00 00 EB ?? 8B 4D ?? 8B 95 ?? ?? ?? ?? 89 11 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00402440@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB NtGlobalFlag flag
        .text:0x00402440  
        .text:0x00402440  FUNC: int cdecl sub_00402440( ) [6 XREFS] 
        .text:0x00402440  
        .text:0x00402440  Stack Variables: (offset from initial top of stack)
        .text:0x00402440            -8: int local8
        .text:0x00402440           -12: int local12
        .text:0x00402440           -16: int local16
        .text:0x00402440           -20: int local20
        .text:0x00402440  
        .text:0x00402440  55               push ebp
        .text:0x00402441  8bec             mov ebp,esp
        .text:0x00402443  83ec10           sub esp,16
        .text:0x00402446  53               push ebx
        .text:0x00402447  56               push esi
        .text:0x00402448  57               push edi
        .text:0x00402449  c745f400000000   mov dword [ebp - 12],0
        .text:0x00402450  c745f000000000   mov dword [ebp - 16],0
        .text:0x00402457  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040245d  8a5802           mov bl,byte [eax + 2]
        .text:0x00402460  885df8           mov byte [ebp - 8],bl
        .text:0x00402463  0fbe45f8         movsx eax,byte [ebp - 8]
        .text:0x00402467  85c0             test eax,eax
        .text:0x00402469  7405             jz 0x00402470
        .text:0x0040246b  e890ebffff       call 0x00401000    ;sub_00401000()
        .text:0x00402470  loc_00402470: [1 XREFS]
        .text:0x00402470  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402476  8b4018           mov eax,dword [eax + 24]
        .text:0x00402479  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x0040247d  8945f4           mov dword [ebp - 12],eax
        .text:0x00402480  837df400         cmp dword [ebp - 12],0
        .text:0x00402484  7405             jz 0x0040248b
        .text:0x00402486  e875ebffff       call 0x00401000    ;sub_00401000()
        .text:0x0040248b  loc_0040248b: [1 XREFS]
        .text:0x0040248b  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402491  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x00402495  83e870           sub eax,112
        .text:0x00402498  8945f0           mov dword [ebp - 16],eax
        .text:0x0040249b  837df000         cmp dword [ebp - 16],0
        .text:0x0040249f  7505             jnz 0x004024a6
        .text:0x004024a1  e85aebffff       call 0x00401000    ;sub_00401000()
        .text:0x004024a6  loc_004024a6: [2 XREFS]
        .text:0x004024a6  b901000000       mov ecx,1
        .text:0x004024ab  85c9             test ecx,ecx
        .text:0x004024ad  7456             jz 0x00402505
        .text:0x004024af  e8f6160000       call 0x00403baa    ;_rand()
        .text:0x004024b4  8845fc           mov byte [ebp - 4],al
        .text:0x004024b7  0fbe55fc         movsx edx,byte [ebp - 4]
        .text:0x004024bb  83fa7f           cmp edx,127
        .text:0x004024be  7e08             jle 0x004024c8
        .text:0x004024c0  8a45fc           mov al,byte [ebp - 4]
        .text:0x004024c3  2c7f             sub al,127
        .text:0x004024c5  8845fc           mov byte [ebp - 4],al
        .text:0x004024c8  loc_004024c8: [1 XREFS]
        .text:0x004024c8  0fbe4dfc         movsx ecx,byte [ebp - 4]
        .text:0x004024cc  83f930           cmp ecx,48
        .text:0x004024cf  7c09             jl 0x004024da
        .text:0x004024d1  0fbe55fc         movsx edx,byte [ebp - 4]
        .text:0x004024d5  83fa39           cmp edx,57
        .text:0x004024d8  7e24             jle 0x004024fe
        .text:0x004024da  loc_004024da: [1 XREFS]
        .text:0x004024da  0fbe45fc         movsx eax,byte [ebp - 4]
        .text:0x004024de  83f861           cmp eax,97
        .text:0x004024e1  7c09             jl 0x004024ec
        .text:0x004024e3  0fbe4dfc         movsx ecx,byte [ebp - 4]
        .text:0x004024e7  83f97a           cmp ecx,122
        .text:0x004024ea  7e12             jle 0x004024fe
        .text:0x004024ec  loc_004024ec: [1 XREFS]
        .text:0x004024ec  0fbe55fc         movsx edx,byte [ebp - 4]
        .text:0x004024f0  83fa41           cmp edx,65
        .text:0x004024f3  7c0e             jl 0x00402503
        .text:0x004024f5  0fbe45fc         movsx eax,byte [ebp - 4]
        .text:0x004024f9  83f85a           cmp eax,90
        .text:0x004024fc  7f05             jg 0x00402503
        .text:0x004024fe  loc_004024fe: [2 XREFS]
        .text:0x004024fe  8a45fc           mov al,byte [ebp - 4]
        .text:0x00402501  eb02             jmp 0x00402505
        .text:0x00402503  loc_00402503: [2 XREFS]
        .text:0x00402503  eba1             jmp 0x004024a6
        .text:0x00402505  loc_00402505: [2 XREFS]
        .text:0x00402505  5f               pop edi
        .text:0x00402506  5e               pop esi
        .text:0x00402507  5b               pop ebx
        .text:0x00402508  8be5             mov esp,ebp
        .text:0x0040250a  5d               pop ebp
        .text:0x0040250b  c3               ret 
        */
        $c36 = { 55 8B EC 83 EC 10 53 56 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 5D ?? 0F BE 45 ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 45 ?? 83 7D ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 45 ?? 83 7D ?? 00 75 ?? E8 ?? ?? ?? ?? B9 01 00 00 00 85 C9 74 ?? E8 ?? ?? ?? ?? 88 45 ?? 0F BE 55 ?? 83 FA 7F 7E ?? 8A 45 ?? 2C 7F 88 45 ?? 0F BE 4D ?? 83 F9 30 7C ?? 0F BE 55 ?? 83 FA 39 7E ?? 0F BE 45 ?? 83 F8 61 7C ?? 0F BE 4D ?? 83 F9 7A 7E ?? 0F BE 55 ?? 83 FA 41 7C ?? 0F BE 45 ?? 83 F8 5A 7F ?? 8A 45 ?? EB ?? EB ?? 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00402510@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB NtGlobalFlag flag
        .text:0x00402510  
        .text:0x00402510  FUNC: int cdecl sub_00402510( int arg0, ) [2 XREFS] 
        .text:0x00402510  
        .text:0x00402510  Stack Variables: (offset from initial top of stack)
        .text:0x00402510             4: int arg0
        .text:0x00402510            -8: int local8
        .text:0x00402510           -12: int local12
        .text:0x00402510           -16: int local16
        .text:0x00402510           -20: int local20
        .text:0x00402510           -24: int local24
        .text:0x00402510  
        .text:0x00402510  55               push ebp
        .text:0x00402511  8bec             mov ebp,esp
        .text:0x00402513  83ec14           sub esp,20
        .text:0x00402516  53               push ebx
        .text:0x00402517  56               push esi
        .text:0x00402518  57               push edi
        .text:0x00402519  c745f000000000   mov dword [ebp - 16],0
        .text:0x00402520  c745ec00000000   mov dword [ebp - 20],0
        .text:0x00402527  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040252d  8a5802           mov bl,byte [eax + 2]
        .text:0x00402530  885df4           mov byte [ebp - 12],bl
        .text:0x00402533  0fbe45f4         movsx eax,byte [ebp - 12]
        .text:0x00402537  85c0             test eax,eax
        .text:0x00402539  7405             jz 0x00402540
        .text:0x0040253b  e8c0eaffff       call 0x00401000    ;sub_00401000()
        .text:0x00402540  loc_00402540: [1 XREFS]
        .text:0x00402540  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402546  8b4018           mov eax,dword [eax + 24]
        .text:0x00402549  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x0040254d  8945f0           mov dword [ebp - 16],eax
        .text:0x00402550  837df000         cmp dword [ebp - 16],0
        .text:0x00402554  7405             jz 0x0040255b
        .text:0x00402556  e8a5eaffff       call 0x00401000    ;sub_00401000()
        .text:0x0040255b  loc_0040255b: [1 XREFS]
        .text:0x0040255b  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402561  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x00402565  83e870           sub eax,112
        .text:0x00402568  8945ec           mov dword [ebp - 20],eax
        .text:0x0040256b  837dec00         cmp dword [ebp - 20],0
        .text:0x0040256f  7505             jnz 0x00402576
        .text:0x00402571  e88aeaffff       call 0x00401000    ;sub_00401000()
        .text:0x00402576  loc_00402576: [1 XREFS]
        .text:0x00402576  6a00             push 0
        .text:0x00402578  e84b160000       call 0x00403bc8    ;_time(ecx,edx,0)
        .text:0x0040257d  83c404           add esp,4
        .text:0x00402580  50               push eax
        .text:0x00402581  e81a160000       call 0x00403ba0    ;sub_00403ba0(sub_00403bc8(ecx,edx,0))
        .text:0x00402586  83c404           add esp,4
        .text:0x00402589  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x0040258c  894dfc           mov dword [ebp - 4],ecx
        .text:0x0040258f  c745f800000000   mov dword [ebp - 8],0
        .text:0x00402596  eb09             jmp 0x004025a1
        .text:0x00402598  loc_00402598: [1 XREFS]
        .text:0x00402598  8b55f8           mov edx,dword [ebp - 8]
        .text:0x0040259b  83c201           add edx,1
        .text:0x0040259e  8955f8           mov dword [ebp - 8],edx
        .text:0x004025a1  loc_004025a1: [1 XREFS]
        .text:0x004025a1  837df804         cmp dword [ebp - 8],4
        .text:0x004025a5  7d15             jge 0x004025bc
        .text:0x004025a7  e894feffff       call 0x00402440    ;sub_00402440()
        .text:0x004025ac  8b4dfc           mov ecx,dword [ebp - 4]
        .text:0x004025af  8801             mov byte [ecx],al
        .text:0x004025b1  8b55fc           mov edx,dword [ebp - 4]
        .text:0x004025b4  83c201           add edx,1
        .text:0x004025b7  8955fc           mov dword [ebp - 4],edx
        .text:0x004025ba  ebdc             jmp 0x00402598
        .text:0x004025bc  loc_004025bc: [1 XREFS]
        .text:0x004025bc  8b45fc           mov eax,dword [ebp - 4]
        .text:0x004025bf  c6002f           mov byte [eax],47
        .text:0x004025c2  8b4dfc           mov ecx,dword [ebp - 4]
        .text:0x004025c5  83c101           add ecx,1
        .text:0x004025c8  894dfc           mov dword [ebp - 4],ecx
        .text:0x004025cb  c745f800000000   mov dword [ebp - 8],0
        .text:0x004025d2  eb09             jmp 0x004025dd
        .text:0x004025d4  loc_004025d4: [1 XREFS]
        .text:0x004025d4  8b55f8           mov edx,dword [ebp - 8]
        .text:0x004025d7  83c201           add edx,1
        .text:0x004025da  8955f8           mov dword [ebp - 8],edx
        .text:0x004025dd  loc_004025dd: [1 XREFS]
        .text:0x004025dd  837df804         cmp dword [ebp - 8],4
        .text:0x004025e1  7d15             jge 0x004025f8
        .text:0x004025e3  e858feffff       call 0x00402440    ;sub_00402440()
        .text:0x004025e8  8b4dfc           mov ecx,dword [ebp - 4]
        .text:0x004025eb  8801             mov byte [ecx],al
        .text:0x004025ed  8b55fc           mov edx,dword [ebp - 4]
        .text:0x004025f0  83c201           add edx,1
        .text:0x004025f3  8955fc           mov dword [ebp - 4],edx
        .text:0x004025f6  ebdc             jmp 0x004025d4
        .text:0x004025f8  loc_004025f8: [1 XREFS]
        .text:0x004025f8  8b45fc           mov eax,dword [ebp - 4]
        .text:0x004025fb  c6002e           mov byte [eax],46
        .text:0x004025fe  8b4dfc           mov ecx,dword [ebp - 4]
        .text:0x00402601  83c101           add ecx,1
        .text:0x00402604  894dfc           mov dword [ebp - 4],ecx
        .text:0x00402607  c745f800000000   mov dword [ebp - 8],0
        .text:0x0040260e  eb09             jmp 0x00402619
        .text:0x00402610  loc_00402610: [1 XREFS]
        .text:0x00402610  8b55f8           mov edx,dword [ebp - 8]
        .text:0x00402613  83c201           add edx,1
        .text:0x00402616  8955f8           mov dword [ebp - 8],edx
        .text:0x00402619  loc_00402619: [1 XREFS]
        .text:0x00402619  837df803         cmp dword [ebp - 8],3
        .text:0x0040261d  7d15             jge 0x00402634
        .text:0x0040261f  e81cfeffff       call 0x00402440    ;sub_00402440()
        .text:0x00402624  8b4dfc           mov ecx,dword [ebp - 4]
        .text:0x00402627  8801             mov byte [ecx],al
        .text:0x00402629  8b55fc           mov edx,dword [ebp - 4]
        .text:0x0040262c  83c201           add edx,1
        .text:0x0040262f  8955fc           mov dword [ebp - 4],edx
        .text:0x00402632  ebdc             jmp 0x00402610
        .text:0x00402634  loc_00402634: [1 XREFS]
        .text:0x00402634  8b45fc           mov eax,dword [ebp - 4]
        .text:0x00402637  c60000           mov byte [eax],0
        .text:0x0040263a  8b4dfc           mov ecx,dword [ebp - 4]
        .text:0x0040263d  83c101           add ecx,1
        .text:0x00402640  894dfc           mov dword [ebp - 4],ecx
        .text:0x00402643  33c0             xor eax,eax
        .text:0x00402645  5f               pop edi
        .text:0x00402646  5e               pop esi
        .text:0x00402647  5b               pop ebx
        .text:0x00402648  8be5             mov esp,ebp
        .text:0x0040264a  5d               pop ebp
        .text:0x0040264b  c3               ret 
        */
        $c37 = { 55 8B EC 83 EC 14 53 56 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 5D ?? 0F BE 45 ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 45 ?? 83 7D ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 45 ?? 83 7D ?? 00 75 ?? E8 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 83 C4 04 50 E8 ?? ?? ?? ?? 83 C4 04 8B 4D ?? 89 4D ?? C7 45 ?? 00 00 00 00 EB ?? 8B 55 ?? 83 C2 01 89 55 ?? 83 7D ?? 04 7D ?? E8 ?? ?? ?? ?? 8B 4D ?? 88 01 8B 55 ?? 83 C2 01 89 55 ?? EB ?? 8B 45 ?? C6 00 2F 8B 4D ?? 83 C1 01 89 4D ?? C7 45 ?? 00 00 00 00 EB ?? 8B 55 ?? 83 C2 01 89 55 ?? 83 7D ?? 04 7D ?? E8 ?? ?? ?? ?? 8B 4D ?? 88 01 8B 55 ?? 83 C2 01 89 55 ?? EB ?? 8B 45 ?? C6 00 2E 8B 4D ?? 83 C1 01 89 4D ?? C7 45 ?? 00 00 00 00 EB ?? 8B 55 ?? 83 C2 01 89 55 ?? 83 7D ?? 03 7D ?? E8 ?? ?? ?? ?? 8B 4D ?? 88 01 8B 55 ?? 83 C2 01 89 55 ?? EB ?? 8B 45 ?? C6 00 00 8B 4D ?? 83 C1 01 89 4D ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00402650@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB NtGlobalFlag flag
        .text:0x00402650  
        .text:0x00402650  FUNC: int cdecl sub_00402650( int arg0, int arg1, ) [2 XREFS] 
        .text:0x00402650  
        .text:0x00402650  Stack Variables: (offset from initial top of stack)
        .text:0x00402650             8: int arg1
        .text:0x00402650             4: int arg0
        .text:0x00402650          -4100: int local4100
        .text:0x00402650          -4104: int local4104
        .text:0x00402650          -4120: int local4120
        .text:0x00402650          -4124: int local4124
        .text:0x00402650          -4128: int local4128
        .text:0x00402650          -4132: int local4132
        .text:0x00402650          -5156: int local5156
        .text:0x00402650          -5160: int local5160
        .text:0x00402650          -5164: int local5164
        .text:0x00402650          -5168: int local5168
        .text:0x00402650          -5172: int local5172
        .text:0x00402650  
        .text:0x00402650  55               push ebp
        .text:0x00402651  8bec             mov ebp,esp
        .text:0x00402653  b830140000       mov eax,0x00001430
        .text:0x00402658  e813130000       call 0x00403970    ;__alloca_probe()
        .text:0x0040265d  53               push ebx
        .text:0x0040265e  56               push esi
        .text:0x0040265f  57               push edi
        .text:0x00402660  c785e4efffff0010 mov dword [ebp - 4124],0x00001000
        .text:0x0040266a  c785d4ebffff0000 mov dword [ebp - 5164],0
        .text:0x00402674  c785d0ebffff0000 mov dword [ebp - 5168],0
        .text:0x0040267e  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402684  8a5802           mov bl,byte [eax + 2]
        .text:0x00402687  889dd8ebffff     mov byte [ebp - 5160],bl
        .text:0x0040268d  0fbe85d8ebffff   movsx eax,byte [ebp - 5160]
        .text:0x00402694  85c0             test eax,eax
        .text:0x00402696  7405             jz 0x0040269d
        .text:0x00402698  e863e9ffff       call 0x00401000    ;sub_00401000()
        .text:0x0040269d  loc_0040269d: [1 XREFS]
        .text:0x0040269d  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004026a3  8b4018           mov eax,dword [eax + 24]
        .text:0x004026a6  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x004026aa  8985d4ebffff     mov dword [ebp - 5164],eax
        .text:0x004026b0  83bdd4ebffff00   cmp dword [ebp - 5164],0
        .text:0x004026b7  7405             jz 0x004026be
        .text:0x004026b9  e842e9ffff       call 0x00401000    ;sub_00401000()
        .text:0x004026be  loc_004026be: [1 XREFS]
        .text:0x004026be  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004026c4  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x004026c8  83e870           sub eax,112
        .text:0x004026cb  8985d0ebffff     mov dword [ebp - 5168],eax
        .text:0x004026d1  83bdd0ebffff00   cmp dword [ebp - 5168],0
        .text:0x004026d8  7505             jnz 0x004026df
        .text:0x004026da  e821e9ffff       call 0x00401000    ;sub_00401000()
        .text:0x004026df  loc_004026df: [1 XREFS]
        .text:0x004026df  6800040000       push 1024
        .text:0x004026e4  8d8de0ebffff     lea ecx,dword [ebp - 5152]
        .text:0x004026ea  51               push ecx
        .text:0x004026eb  e8d0efffff       call 0x004016c0    ;sub_004016c0(local5156,1024)
        .text:0x004026f0  83c408           add esp,8
        .text:0x004026f3  85c0             test eax,eax
        .text:0x004026f5  740a             jz 0x00402701
        .text:0x004026f7  b801000000       mov eax,1
        .text:0x004026fc  e975010000       jmp 0x00402876
        .text:0x00402701  loc_00402701: [1 XREFS]
        .text:0x00402701  8d95dcebffff     lea edx,dword [ebp - 5156]
        .text:0x00402707  52               push edx
        .text:0x00402708  e883f0ffff       call 0x00401790    ;sub_00401790(local5160)
        .text:0x0040270d  83c404           add esp,4
        .text:0x00402710  85c0             test eax,eax
        .text:0x00402712  740a             jz 0x0040271e
        .text:0x00402714  b801000000       mov eax,1
        .text:0x00402719  e958010000       jmp 0x00402876
        .text:0x0040271e  loc_0040271e: [1 XREFS]
        .text:0x0040271e  6a10             push 16
        .text:0x00402720  8d85ecefffff     lea eax,dword [ebp - 4116]
        .text:0x00402726  50               push eax
        .text:0x00402727  e8e4fdffff       call 0x00402510    ;sub_00402510(local4120)
        .text:0x0040272c  83c408           add esp,8
        .text:0x0040272f  85c0             test eax,eax
        .text:0x00402731  740a             jz 0x0040273d
        .text:0x00402733  b801000000       mov eax,1
        .text:0x00402738  e939010000       jmp 0x00402876
        .text:0x0040273d  loc_0040273d: [1 XREFS]
        .text:0x0040273d  8d8de4efffff     lea ecx,dword [ebp - 4124]
        .text:0x00402743  51               push ecx
        .text:0x00402744  8d9500f0ffff     lea edx,dword [ebp - 4096]
        .text:0x0040274a  52               push edx
        .text:0x0040274b  8d85ecefffff     lea eax,dword [ebp - 4116]
        .text:0x00402751  50               push eax
        .text:0x00402752  8b8ddcebffff     mov ecx,dword [ebp - 5156]
        .text:0x00402758  51               push ecx
        .text:0x00402759  8d95e0ebffff     lea edx,dword [ebp - 5152]
        .text:0x0040275f  52               push edx
        .text:0x00402760  e84bfaffff       call 0x004021b0    ;sub_004021b0(local5156,0xfefefefe,local4120,local4100,local4128)
        .text:0x00402765  83c414           add esp,20
        .text:0x00402768  85c0             test eax,eax
        .text:0x0040276a  740a             jz 0x00402776
        .text:0x0040276c  b801000000       mov eax,1
        .text:0x00402771  e900010000       jmp 0x00402876
        .text:0x00402776  loc_00402776: [1 XREFS]
        .text:0x00402776  68a8c04000       push 0x0040c0a8
        .text:0x0040277b  8d8500f0ffff     lea eax,dword [ebp - 4096]
        .text:0x00402781  50               push eax
        .text:0x00402782  e899130000       call 0x00403b20    ;_strstr(local4100,0x0040c0a8)
        .text:0x00402787  83c408           add esp,8
        .text:0x0040278a  8985fcefffff     mov dword [ebp - 4100],eax
        .text:0x00402790  83bdfcefffff00   cmp dword [ebp - 4100],0
        .text:0x00402797  750a             jnz 0x004027a3
        .text:0x00402799  b801000000       mov eax,1
        .text:0x0040279e  e9d3000000       jmp 0x00402876
        .text:0x004027a3  loc_004027a3: [1 XREFS]
        .text:0x004027a3  8b8dfcefffff     mov ecx,dword [ebp - 4100]
        .text:0x004027a9  898de0efffff     mov dword [ebp - 4128],ecx
        .text:0x004027af  68a0c04000       push 0x0040c0a0
        .text:0x004027b4  8b95fcefffff     mov edx,dword [ebp - 4100]
        .text:0x004027ba  52               push edx
        .text:0x004027bb  e860130000       call 0x00403b20    ;_strstr(sub_00403b20(local4100,0x0040c0a8),0x0040c0a0)
        .text:0x004027c0  83c408           add esp,8
        .text:0x004027c3  8985fcefffff     mov dword [ebp - 4100],eax
        .text:0x004027c9  83bdfcefffff00   cmp dword [ebp - 4100],0
        .text:0x004027d0  750a             jnz 0x004027dc
        .text:0x004027d2  b801000000       mov eax,1
        .text:0x004027d7  e99a000000       jmp 0x00402876
        .text:0x004027dc  loc_004027dc: [1 XREFS]
        .text:0x004027dc  8b85fcefffff     mov eax,dword [ebp - 4100]
        .text:0x004027e2  8985e8efffff     mov dword [ebp - 4120],eax
        .text:0x004027e8  8b8de8efffff     mov ecx,dword [ebp - 4120]
        .text:0x004027ee  2b8de0efffff     sub ecx,dword [ebp - 4128]
        .text:0x004027f4  83c101           add ecx,1
        .text:0x004027f7  3b4d0c           cmp ecx,dword [ebp + 12]
        .text:0x004027fa  7e07             jle 0x00402803
        .text:0x004027fc  b801000000       mov eax,1
        .text:0x00402801  eb73             jmp 0x00402876
        .text:0x00402803  loc_00402803: [1 XREFS]
        .text:0x00402803  8b95e8efffff     mov edx,dword [ebp - 4120]
        .text:0x00402809  2b95e0efffff     sub edx,dword [ebp - 4128]
        .text:0x0040280f  bfa8c04000       mov edi,0x0040c0a8
        .text:0x00402814  83c9ff           or ecx,0xffffffff
        .text:0x00402817  33c0             xor eax,eax
        .text:0x00402819  f2ae             repnz: scasb 
        .text:0x0040281b  f7d1             not ecx
        .text:0x0040281d  83c1ff           add ecx,0xffffffff
        .text:0x00402820  2bd1             sub edx,ecx
        .text:0x00402822  bfa8c04000       mov edi,0x0040c0a8
        .text:0x00402827  83c9ff           or ecx,0xffffffff
        .text:0x0040282a  33c0             xor eax,eax
        .text:0x0040282c  f2ae             repnz: scasb 
        .text:0x0040282e  f7d1             not ecx
        .text:0x00402830  83c1ff           add ecx,0xffffffff
        .text:0x00402833  8bb5e0efffff     mov esi,dword [ebp - 4128]
        .text:0x00402839  03f1             add esi,ecx
        .text:0x0040283b  8b7d08           mov edi,dword [ebp + 8]
        .text:0x0040283e  8bca             mov ecx,edx
        .text:0x00402840  8bc1             mov eax,ecx
        .text:0x00402842  c1e902           shr ecx,2
        .text:0x00402845  f3a5             rep: movsd 
        .text:0x00402847  8bc8             mov ecx,eax
        .text:0x00402849  83e103           and ecx,3
        .text:0x0040284c  f3a4             rep: movsb 
        .text:0x0040284e  8b95e8efffff     mov edx,dword [ebp - 4120]
        .text:0x00402854  2b95e0efffff     sub edx,dword [ebp - 4128]
        .text:0x0040285a  bfa8c04000       mov edi,0x0040c0a8
        .text:0x0040285f  83c9ff           or ecx,0xffffffff
        .text:0x00402862  33c0             xor eax,eax
        .text:0x00402864  f2ae             repnz: scasb 
        .text:0x00402866  f7d1             not ecx
        .text:0x00402868  83c1ff           add ecx,0xffffffff
        .text:0x0040286b  2bd1             sub edx,ecx
        .text:0x0040286d  8b4508           mov eax,dword [ebp + 8]
        .text:0x00402870  c6041000         mov byte [eax + edx],0
        .text:0x00402874  33c0             xor eax,eax
        .text:0x00402876  loc_00402876: [7 XREFS]
        .text:0x00402876  5f               pop edi
        .text:0x00402877  5e               pop esi
        .text:0x00402878  5b               pop ebx
        .text:0x00402879  8be5             mov esp,ebp
        .text:0x0040287b  5d               pop ebp
        .text:0x0040287c  c3               ret 
        */
        $c38 = { 55 8B EC B8 30 14 00 00 E8 ?? ?? ?? ?? 53 56 57 C7 85 ?? ?? ?? ?? 00 10 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? 68 00 04 00 00 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 6A 10 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 8D 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 14 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 68 A8 C0 40 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 08 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 89 8D ?? ?? ?? ?? 68 A0 C0 40 00 8B 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 08 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 2B 8D ?? ?? ?? ?? 83 C1 01 3B 4D ?? 7E ?? B8 01 00 00 00 EB ?? 8B 95 ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? BF A8 C0 40 00 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 2B D1 BF A8 C0 40 00 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B B5 ?? ?? ?? ?? 03 F1 8B 7D ?? 8B CA 8B C1 C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 95 ?? ?? ?? ?? 2B 95 ?? ?? ?? ?? BF A8 C0 40 00 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 2B D1 8B 45 ?? C6 04 10 00 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00402880@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB NtGlobalFlag flag
        .text:0x00402880  
        .text:0x00402880  FUNC: int cdecl sub_00402880( int arg0, ) [2 XREFS] 
        .text:0x00402880  
        .text:0x00402880  Stack Variables: (offset from initial top of stack)
        .text:0x00402880             4: int arg0
        .text:0x00402880          -1028: int local1028
        .text:0x00402880          -1032: int local1032
        .text:0x00402880          -1036: int local1036
        .text:0x00402880          -1040: int local1040
        .text:0x00402880          -1044: int local1044
        .text:0x00402880          -1048: int local1048
        .text:0x00402880          -1052: int local1052
        .text:0x00402880          -1056: int local1056
        .text:0x00402880          -1060: int local1060
        .text:0x00402880          -1064: int local1064
        .text:0x00402880          -1068: int local1068
        .text:0x00402880          -1072: int local1072
        .text:0x00402880          -1076: int local1076
        .text:0x00402880  
        .text:0x00402880  55               push ebp
        .text:0x00402881  8bec             mov ebp,esp
        .text:0x00402883  81ec30040000     sub esp,1072
        .text:0x00402889  53               push ebx
        .text:0x0040288a  56               push esi
        .text:0x0040288b  57               push edi
        .text:0x0040288c  c785d4fbffff0000 mov dword [ebp - 1068],0
        .text:0x00402896  c785d0fbffff0000 mov dword [ebp - 1072],0
        .text:0x004028a0  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004028a6  8a5802           mov bl,byte [eax + 2]
        .text:0x004028a9  889dd8fbffff     mov byte [ebp - 1064],bl
        .text:0x004028af  0fbe85d8fbffff   movsx eax,byte [ebp - 1064]
        .text:0x004028b6  85c0             test eax,eax
        .text:0x004028b8  7405             jz 0x004028bf
        .text:0x004028ba  e841e7ffff       call 0x00401000    ;sub_00401000()
        .text:0x004028bf  loc_004028bf: [1 XREFS]
        .text:0x004028bf  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004028c5  8b4018           mov eax,dword [eax + 24]
        .text:0x004028c8  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x004028cc  8985d4fbffff     mov dword [ebp - 1068],eax
        .text:0x004028d2  83bdd4fbffff00   cmp dword [ebp - 1068],0
        .text:0x004028d9  7405             jz 0x004028e0
        .text:0x004028db  e820e7ffff       call 0x00401000    ;sub_00401000()
        .text:0x004028e0  loc_004028e0: [1 XREFS]
        .text:0x004028e0  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004028e6  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x004028ea  83e870           sub eax,112
        .text:0x004028ed  8985d0fbffff     mov dword [ebp - 1072],eax
        .text:0x004028f3  83bdd0fbffff00   cmp dword [ebp - 1072],0
        .text:0x004028fa  7505             jnz 0x00402901
        .text:0x004028fc  e8ffe6ffff       call 0x00401000    ;sub_00401000()
        .text:0x00402901  loc_00402901: [1 XREFS]
        .text:0x00402901  6800040000       push 1024
        .text:0x00402906  8d8d00fcffff     lea ecx,dword [ebp - 1024]
        .text:0x0040290c  51               push ecx
        .text:0x0040290d  e83efdffff       call 0x00402650    ;sub_00402650(local1028,1024)
        .text:0x00402912  83c408           add esp,8
        .text:0x00402915  85c0             test eax,eax
        .text:0x00402917  740a             jz 0x00402923
        .text:0x00402919  b801000000       mov eax,1
        .text:0x0040291e  e90c030000       jmp 0x00402c2f
        .text:0x00402923  loc_00402923: [1 XREFS]
        .text:0x00402923  bfdcc04000       mov edi,0x0040c0dc
        .text:0x00402928  83c9ff           or ecx,0xffffffff
        .text:0x0040292b  33c0             xor eax,eax
        .text:0x0040292d  f2ae             repnz: scasb 
        .text:0x0040292f  f7d1             not ecx
        .text:0x00402931  83c1ff           add ecx,0xffffffff
        .text:0x00402934  51               push ecx
        .text:0x00402935  68dcc04000       push 0x0040c0dc
        .text:0x0040293a  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x00402940  52               push edx
        .text:0x00402941  e80a180000       call 0x00404150    ;_strncmp(local1028,0x0040c0dc,0xffffffff)
        .text:0x00402946  83c40c           add esp,12
        .text:0x00402949  85c0             test eax,eax
        .text:0x0040294b  755c             jnz 0x004029a9
        .text:0x0040294d  68d8c04000       push 0x0040c0d8
        .text:0x00402952  8d8500fcffff     lea eax,dword [ebp - 1024]
        .text:0x00402958  50               push eax
        .text:0x00402959  e856170000       call 0x004040b4    ;_strtok(local1028,0x0040c0d8)
        .text:0x0040295e  83c408           add esp,8
        .text:0x00402961  8985f8fbffff     mov dword [ebp - 1032],eax
        .text:0x00402967  68d8c04000       push 0x0040c0d8
        .text:0x0040296c  6a00             push 0
        .text:0x0040296e  e841170000       call 0x004040b4    ;_strtok(0,0x0040c0d8)
        .text:0x00402973  83c408           add esp,8
        .text:0x00402976  8985f8fbffff     mov dword [ebp - 1032],eax
        .text:0x0040297c  8b8df8fbffff     mov ecx,dword [ebp - 1032]
        .text:0x00402982  51               push ecx
        .text:0x00402983  e8a2100000       call 0x00403a2a    ;_atoi(sub_004040b4(0,0x0040c0d8))
        .text:0x00402988  83c404           add esp,4
        .text:0x0040298b  8985fcfbffff     mov dword [ebp - 1028],eax
        .text:0x00402991  8b95fcfbffff     mov edx,dword [ebp - 1028]
        .text:0x00402997  69d2e8030000     imul edx,edx,1000
        .text:0x0040299d  52               push edx
        .text:0x0040299e  ff1538b04000     call dword [0x0040b038]    ;kernel32.Sleep(0x520fba98)
        .text:0x004029a4  e984020000       jmp 0x00402c2d
        .text:0x004029a9  loc_004029a9: [1 XREFS]
        .text:0x004029a9  bfd0c04000       mov edi,0x0040c0d0
        .text:0x004029ae  83c9ff           or ecx,0xffffffff
        .text:0x004029b1  33c0             xor eax,eax
        .text:0x004029b3  f2ae             repnz: scasb 
        .text:0x004029b5  f7d1             not ecx
        .text:0x004029b7  83c1ff           add ecx,0xffffffff
        .text:0x004029ba  51               push ecx
        .text:0x004029bb  68d0c04000       push 0x0040c0d0
        .text:0x004029c0  8d8500fcffff     lea eax,dword [ebp - 1024]
        .text:0x004029c6  50               push eax
        .text:0x004029c7  e884170000       call 0x00404150    ;_strncmp(local1028,0x0040c0d0,0xffffffff)
        .text:0x004029cc  83c40c           add esp,12
        .text:0x004029cf  85c0             test eax,eax
        .text:0x004029d1  0f8586000000     jnz 0x00402a5d
        .text:0x004029d7  68d8c04000       push 0x0040c0d8
        .text:0x004029dc  8d8d00fcffff     lea ecx,dword [ebp - 1024]
        .text:0x004029e2  51               push ecx
        .text:0x004029e3  e8cc160000       call 0x004040b4    ;_strtok(local1028,0x0040c0d8)
        .text:0x004029e8  83c408           add esp,8
        .text:0x004029eb  8985f4fbffff     mov dword [ebp - 1036],eax
        .text:0x004029f1  68d8c04000       push 0x0040c0d8
        .text:0x004029f6  6a00             push 0
        .text:0x004029f8  e8b7160000       call 0x004040b4    ;_strtok(0,0x0040c0d8)
        .text:0x004029fd  83c408           add esp,8
        .text:0x00402a00  8985f4fbffff     mov dword [ebp - 1036],eax
        .text:0x00402a06  8b95f4fbffff     mov edx,dword [ebp - 1036]
        .text:0x00402a0c  52               push edx
        .text:0x00402a0d  e818100000       call 0x00403a2a    ;_atoi(sub_004040b4(0,0x0040c0d8))
        .text:0x00402a12  83c404           add esp,4
        .text:0x00402a15  8985f0fbffff     mov dword [ebp - 1040],eax
        .text:0x00402a1b  68d8c04000       push 0x0040c0d8
        .text:0x00402a20  6a00             push 0
        .text:0x00402a22  e88d160000       call 0x004040b4    ;_strtok(0,0x0040c0d8)
        .text:0x00402a27  83c408           add esp,8
        .text:0x00402a2a  8985f4fbffff     mov dword [ebp - 1036],eax
        .text:0x00402a30  8b85f4fbffff     mov eax,dword [ebp - 1036]
        .text:0x00402a36  50               push eax
        .text:0x00402a37  8b8df0fbffff     mov ecx,dword [ebp - 1040]
        .text:0x00402a3d  51               push ecx
        .text:0x00402a3e  8b5508           mov edx,dword [ebp + 8]
        .text:0x00402a41  52               push edx
        .text:0x00402a42  e8d9f5ffff       call 0x00402020    ;sub_00402020(arg0,sub_00403a2a(<0x004029f8>),sub_004040b4(0,0x0040c0d8))
        .text:0x00402a47  83c40c           add esp,12
        .text:0x00402a4a  85c0             test eax,eax
        .text:0x00402a4c  740a             jz 0x00402a58
        .text:0x00402a4e  b801000000       mov eax,1
        .text:0x00402a53  e9d7010000       jmp 0x00402c2f
        .text:0x00402a58  loc_00402a58: [1 XREFS]
        .text:0x00402a58  e9d0010000       jmp 0x00402c2d
        .text:0x00402a5d  loc_00402a5d: [1 XREFS]
        .text:0x00402a5d  bfc4c04000       mov edi,0x0040c0c4
        .text:0x00402a62  83c9ff           or ecx,0xffffffff
        .text:0x00402a65  33c0             xor eax,eax
        .text:0x00402a67  f2ae             repnz: scasb 
        .text:0x00402a69  f7d1             not ecx
        .text:0x00402a6b  83c1ff           add ecx,0xffffffff
        .text:0x00402a6e  51               push ecx
        .text:0x00402a6f  68c4c04000       push 0x0040c0c4
        .text:0x00402a74  8d8500fcffff     lea eax,dword [ebp - 1024]
        .text:0x00402a7a  50               push eax
        .text:0x00402a7b  e8d0160000       call 0x00404150    ;_strncmp(local1028,0x0040c0c4,0xffffffff)
        .text:0x00402a80  83c40c           add esp,12
        .text:0x00402a83  85c0             test eax,eax
        .text:0x00402a85  0f8586000000     jnz 0x00402b11
        .text:0x00402a8b  68d8c04000       push 0x0040c0d8
        .text:0x00402a90  8d8d00fcffff     lea ecx,dword [ebp - 1024]
        .text:0x00402a96  51               push ecx
        .text:0x00402a97  e818160000       call 0x004040b4    ;_strtok(local1028,0x0040c0d8)
        .text:0x00402a9c  83c408           add esp,8
        .text:0x00402a9f  8985ecfbffff     mov dword [ebp - 1044],eax
        .text:0x00402aa5  68d8c04000       push 0x0040c0d8
        .text:0x00402aaa  6a00             push 0
        .text:0x00402aac  e803160000       call 0x004040b4    ;_strtok(0,0x0040c0d8)
        .text:0x00402ab1  83c408           add esp,8
        .text:0x00402ab4  8985ecfbffff     mov dword [ebp - 1044],eax
        .text:0x00402aba  8b95ecfbffff     mov edx,dword [ebp - 1044]
        .text:0x00402ac0  52               push edx
        .text:0x00402ac1  e8640f0000       call 0x00403a2a    ;_atoi(sub_004040b4(0,0x0040c0d8))
        .text:0x00402ac6  83c404           add esp,4
        .text:0x00402ac9  8985e8fbffff     mov dword [ebp - 1048],eax
        .text:0x00402acf  68d8c04000       push 0x0040c0d8
        .text:0x00402ad4  6a00             push 0
        .text:0x00402ad6  e8d9150000       call 0x004040b4    ;_strtok(0,0x0040c0d8)
        .text:0x00402adb  83c408           add esp,8
        .text:0x00402ade  8985ecfbffff     mov dword [ebp - 1044],eax
        .text:0x00402ae4  8b85ecfbffff     mov eax,dword [ebp - 1044]
        .text:0x00402aea  50               push eax
        .text:0x00402aeb  8b8de8fbffff     mov ecx,dword [ebp - 1048]
        .text:0x00402af1  51               push ecx
        .text:0x00402af2  8b5508           mov edx,dword [ebp + 8]
        .text:0x00402af5  52               push edx
        .text:0x00402af6  e835f3ffff       call 0x00401e30    ;sub_00401e30(arg0,sub_00403a2a(<0x00402aac>),sub_004040b4(0,0x0040c0d8))
        .text:0x00402afb  83c40c           add esp,12
        .text:0x00402afe  85c0             test eax,eax
        .text:0x00402b00  740a             jz 0x00402b0c
        .text:0x00402b02  b801000000       mov eax,1
        .text:0x00402b07  e923010000       jmp 0x00402c2f
        .text:0x00402b0c  loc_00402b0c: [1 XREFS]
        .text:0x00402b0c  e91c010000       jmp 0x00402c2d
        .text:0x00402b11  loc_00402b11: [1 XREFS]
        .text:0x00402b11  bfc0c04000       mov edi,0x0040c0c0
        .text:0x00402b16  83c9ff           or ecx,0xffffffff
        .text:0x00402b19  33c0             xor eax,eax
        .text:0x00402b1b  f2ae             repnz: scasb 
        .text:0x00402b1d  f7d1             not ecx
        .text:0x00402b1f  83c1ff           add ecx,0xffffffff
        .text:0x00402b22  51               push ecx
        .text:0x00402b23  68c0c04000       push 0x0040c0c0
        .text:0x00402b28  8d8500fcffff     lea eax,dword [ebp - 1024]
        .text:0x00402b2e  50               push eax
        .text:0x00402b2f  e81c160000       call 0x00404150    ;_strncmp(local1028,0x0040c0c0,0xffffffff)
        .text:0x00402b34  83c40c           add esp,12
        .text:0x00402b37  85c0             test eax,eax
        .text:0x00402b39  0f85c8000000     jnz 0x00402c07
        .text:0x00402b3f  68d8c04000       push 0x0040c0d8
        .text:0x00402b44  8d8d00fcffff     lea ecx,dword [ebp - 1024]
        .text:0x00402b4a  51               push ecx
        .text:0x00402b4b  e864150000       call 0x004040b4    ;_strtok(local1028,0x0040c0d8)
        .text:0x00402b50  83c408           add esp,8
        .text:0x00402b53  8985e4fbffff     mov dword [ebp - 1052],eax
        .text:0x00402b59  68d8c04000       push 0x0040c0d8
        .text:0x00402b5e  6a00             push 0
        .text:0x00402b60  e84f150000       call 0x004040b4    ;_strtok(0,0x0040c0d8)
        .text:0x00402b65  83c408           add esp,8
        .text:0x00402b68  8985e4fbffff     mov dword [ebp - 1052],eax
        .text:0x00402b6e  8b95e4fbffff     mov edx,dword [ebp - 1052]
        .text:0x00402b74  52               push edx
        .text:0x00402b75  e8b00e0000       call 0x00403a2a    ;_atoi(sub_004040b4(0,0x0040c0d8))
        .text:0x00402b7a  83c404           add esp,4
        .text:0x00402b7d  8985dcfbffff     mov dword [ebp - 1060],eax
        .text:0x00402b83  68bcc04000       push 0x0040c0bc
        .text:0x00402b88  6a00             push 0
        .text:0x00402b8a  e825150000       call 0x004040b4    ;_strtok(0,0x0040c0bc)
        .text:0x00402b8f  83c408           add esp,8
        .text:0x00402b92  8985e4fbffff     mov dword [ebp - 1052],eax
        .text:0x00402b98  68b8c04000       push 0x0040c0b8
        .text:0x00402b9d  8b85e4fbffff     mov eax,dword [ebp - 1052]
        .text:0x00402ba3  50               push eax
        .text:0x00402ba4  e8fb100000       call 0x00403ca4    ;__popen(sub_004040b4(0,0x0040c0bc),<0x00402b60>,local1028,<0x00402b8a>)
        .text:0x00402ba9  83c408           add esp,8
        .text:0x00402bac  8985e0fbffff     mov dword [ebp - 1056],eax
        .text:0x00402bb2  83bde0fbffff00   cmp dword [ebp - 1056],0
        .text:0x00402bb9  7507             jnz 0x00402bc2
        .text:0x00402bbb  b801000000       mov eax,1
        .text:0x00402bc0  eb6d             jmp 0x00402c2f
        .text:0x00402bc2  loc_00402bc2: [1 XREFS]
        .text:0x00402bc2  8b8de0fbffff     mov ecx,dword [ebp - 1056]
        .text:0x00402bc8  51               push ecx
        .text:0x00402bc9  8b95dcfbffff     mov edx,dword [ebp - 1060]
        .text:0x00402bcf  52               push edx
        .text:0x00402bd0  8b4508           mov eax,dword [ebp + 8]
        .text:0x00402bd3  50               push eax
        .text:0x00402bd4  e8f7f0ffff       call 0x00401cd0    ;sub_00401cd0(arg0,sub_00403a2a(<0x00402b60>),sub_00403ca4(<0x00402b8a>,<0x00402b60>,local1028,<0x00402b8a>))
        .text:0x00402bd9  83c40c           add esp,12
        .text:0x00402bdc  85c0             test eax,eax
        .text:0x00402bde  7416             jz 0x00402bf6
        .text:0x00402be0  8b8de0fbffff     mov ecx,dword [ebp - 1056]
        .text:0x00402be6  51               push ecx
        .text:0x00402be7  e817140000       call 0x00404003    ;__pclose(<0x00402ba4>)
        .text:0x00402bec  83c404           add esp,4
        .text:0x00402bef  b801000000       mov eax,1
        .text:0x00402bf4  eb39             jmp 0x00402c2f
        .text:0x00402bf6  loc_00402bf6: [1 XREFS]
        .text:0x00402bf6  8b95e0fbffff     mov edx,dword [ebp - 1056]
        .text:0x00402bfc  52               push edx
        .text:0x00402bfd  e801140000       call 0x00404003    ;__pclose(<0x00402ba4>)
        .text:0x00402c02  83c404           add esp,4
        .text:0x00402c05  eb26             jmp 0x00402c2d
        .text:0x00402c07  loc_00402c07: [1 XREFS]
        .text:0x00402c07  bfb0c04000       mov edi,0x0040c0b0
        .text:0x00402c0c  83c9ff           or ecx,0xffffffff
        .text:0x00402c0f  33c0             xor eax,eax
        .text:0x00402c11  f2ae             repnz: scasb 
        .text:0x00402c13  f7d1             not ecx
        .text:0x00402c15  83c1ff           add ecx,0xffffffff
        .text:0x00402c18  51               push ecx
        .text:0x00402c19  68b0c04000       push 0x0040c0b0
        .text:0x00402c1e  8d8500fcffff     lea eax,dword [ebp - 1024]
        .text:0x00402c24  50               push eax
        .text:0x00402c25  e826150000       call 0x00404150    ;_strncmp(local1028,0x0040c0b0,0xffffffff)
        .text:0x00402c2a  83c40c           add esp,12
        .text:0x00402c2d  loc_00402c2d: [4 XREFS]
        .text:0x00402c2d  33c0             xor eax,eax
        .text:0x00402c2f  loc_00402c2f: [5 XREFS]
        .text:0x00402c2f  5f               pop edi
        .text:0x00402c30  5e               pop esi
        .text:0x00402c31  5b               pop ebx
        .text:0x00402c32  8be5             mov esp,ebp
        .text:0x00402c34  5d               pop ebp
        .text:0x00402c35  c3               ret 
        */
        $c39 = { 55 8B EC 81 EC 30 04 00 00 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? 68 00 04 00 00 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? BF DC C0 40 00 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 51 68 DC C0 40 00 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 75 ?? 68 D8 C0 40 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 08 89 85 ?? ?? ?? ?? 68 D8 C0 40 00 6A 00 E8 ?? ?? ?? ?? 83 C4 08 89 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 04 89 85 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 69 D2 E8 03 00 00 52 FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? BF D0 C0 40 00 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 51 68 D0 C0 40 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 0F 85 ?? ?? ?? ?? 68 D8 C0 40 00 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 08 89 85 ?? ?? ?? ?? 68 D8 C0 40 00 6A 00 E8 ?? ?? ?? ?? 83 C4 08 89 85 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 04 89 85 ?? ?? ?? ?? 68 D8 C0 40 00 6A 00 E8 ?? ?? ?? ?? 83 C4 08 89 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? BF C4 C0 40 00 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 51 68 C4 C0 40 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 0F 85 ?? ?? ?? ?? 68 D8 C0 40 00 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 08 89 85 ?? ?? ?? ?? 68 D8 C0 40 00 6A 00 E8 ?? ?? ?? ?? 83 C4 08 89 85 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 04 89 85 ?? ?? ?? ?? 68 D8 C0 40 00 6A 00 E8 ?? ?? ?? ?? 83 C4 08 89 85 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? BF C0 C0 40 00 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 51 68 C0 C0 40 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 0F 85 ?? ?? ?? ?? 68 D8 C0 40 00 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 08 89 85 ?? ?? ?? ?? 68 D8 C0 40 00 6A 00 E8 ?? ?? ?? ?? 83 C4 08 89 85 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 04 89 85 ?? ?? ?? ?? 68 BC C0 40 00 6A 00 E8 ?? ?? ?? ?? 83 C4 08 89 85 ?? ?? ?? ?? 68 B8 C0 40 00 8B 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 08 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? B8 01 00 00 00 EB ?? 8B 8D ?? ?? ?? ?? 51 8B 95 ?? ?? ?? ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 ?? 8B 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 04 B8 01 00 00 00 EB ?? 8B 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 04 EB ?? BF B0 C0 40 00 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 51 68 B0 C0 40 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00402c40@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB NtGlobalFlag flag
        .text:0x00402c40  
        .text:0x00402c40  FUNC: int cdecl sub_00402c40( ) [2 XREFS] 
        .text:0x00402c40  
        .text:0x00402c40  Stack Variables: (offset from initial top of stack)
        .text:0x00402c40          -1028: int local1028
        .text:0x00402c40          -2052: int local2052
        .text:0x00402c40          -3076: int local3076
        .text:0x00402c40          -4100: int local4100
        .text:0x00402c40          -4104: int local4104
        .text:0x00402c40          -4108: int local4108
        .text:0x00402c40          -4112: int local4112
        .text:0x00402c40  
        .text:0x00402c40  55               push ebp
        .text:0x00402c41  8bec             mov ebp,esp
        .text:0x00402c43  b80c100000       mov eax,0x0000100c
        .text:0x00402c48  e8230d0000       call 0x00403970    ;__alloca_probe()
        .text:0x00402c4d  53               push ebx
        .text:0x00402c4e  56               push esi
        .text:0x00402c4f  57               push edi
        .text:0x00402c50  c785f8efffff0000 mov dword [ebp - 4104],0
        .text:0x00402c5a  c785f4efffff0000 mov dword [ebp - 4108],0
        .text:0x00402c64  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402c6a  8a5802           mov bl,byte [eax + 2]
        .text:0x00402c6d  889dfcefffff     mov byte [ebp - 4100],bl
        .text:0x00402c73  0fbe85fcefffff   movsx eax,byte [ebp - 4100]
        .text:0x00402c7a  85c0             test eax,eax
        .text:0x00402c7c  7405             jz 0x00402c83
        .text:0x00402c7e  e87de3ffff       call 0x00401000    ;sub_00401000()
        .text:0x00402c83  loc_00402c83: [1 XREFS]
        .text:0x00402c83  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402c89  8b4018           mov eax,dword [eax + 24]
        .text:0x00402c8c  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x00402c90  8985f8efffff     mov dword [ebp - 4104],eax
        .text:0x00402c96  83bdf8efffff00   cmp dword [ebp - 4104],0
        .text:0x00402c9d  7405             jz 0x00402ca4
        .text:0x00402c9f  e85ce3ffff       call 0x00401000    ;sub_00401000()
        .text:0x00402ca4  loc_00402ca4: [1 XREFS]
        .text:0x00402ca4  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402caa  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x00402cae  83e870           sub eax,112
        .text:0x00402cb1  8985f4efffff     mov dword [ebp - 4108],eax
        .text:0x00402cb7  83bdf4efffff00   cmp dword [ebp - 4108],0
        .text:0x00402cbe  7505             jnz 0x00402cc5
        .text:0x00402cc0  e83be3ffff       call 0x00401000    ;sub_00401000()
        .text:0x00402cc5  loc_00402cc5: [2 XREFS]
        .text:0x00402cc5  b901000000       mov ecx,1
        .text:0x00402cca  85c9             test ecx,ecx
        .text:0x00402ccc  0f848e000000     jz 0x00402d60
        .text:0x00402cd2  6800040000       push 1024
        .text:0x00402cd7  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x00402cdd  52               push edx
        .text:0x00402cde  6800040000       push 1024
        .text:0x00402ce3  8d8500f0ffff     lea eax,dword [ebp - 4096]
        .text:0x00402ce9  50               push eax
        .text:0x00402cea  6800040000       push 1024
        .text:0x00402cef  8d8d00f8ffff     lea ecx,dword [ebp - 2048]
        .text:0x00402cf5  51               push ecx
        .text:0x00402cf6  6800040000       push 1024
        .text:0x00402cfb  8d9500f4ffff     lea edx,dword [ebp - 3072]
        .text:0x00402d01  52               push edx
        .text:0x00402d02  e8a9e7ffff       call 0x004014b0    ;sub_004014b0(local3076,1024,local2052,1024,local4100,1024,local1028)
        .text:0x00402d07  83c420           add esp,32
        .text:0x00402d0a  85c0             test eax,eax
        .text:0x00402d0c  7407             jz 0x00402d15
        .text:0x00402d0e  b801000000       mov eax,1
        .text:0x00402d13  eb4d             jmp 0x00402d62
        .text:0x00402d15  loc_00402d15: [1 XREFS]
        .text:0x00402d15  8d8500f0ffff     lea eax,dword [ebp - 4096]
        .text:0x00402d1b  50               push eax
        .text:0x00402d1c  e8090d0000       call 0x00403a2a    ;_atoi(local4100)
        .text:0x00402d21  83c404           add esp,4
        .text:0x00402d24  50               push eax
        .text:0x00402d25  8d8d00f8ffff     lea ecx,dword [ebp - 2048]
        .text:0x00402d2b  51               push ecx
        .text:0x00402d2c  e84ffbffff       call 0x00402880    ;sub_00402880(local2052)
        .text:0x00402d31  83c408           add esp,8
        .text:0x00402d34  85c0             test eax,eax
        .text:0x00402d36  7407             jz 0x00402d3f
        .text:0x00402d38  b801000000       mov eax,1
        .text:0x00402d3d  eb23             jmp 0x00402d62
        .text:0x00402d3f  loc_00402d3f: [1 XREFS]
        .text:0x00402d3f  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x00402d45  52               push edx
        .text:0x00402d46  e8df0c0000       call 0x00403a2a    ;_atoi(local1028)
        .text:0x00402d4b  83c404           add esp,4
        .text:0x00402d4e  69c0e8030000     imul eax,eax,1000
        .text:0x00402d54  50               push eax
        .text:0x00402d55  ff1538b04000     call dword [0x0040b038]    ;kernel32.Sleep(0x4751ba98)
        .text:0x00402d5b  e965ffffff       jmp 0x00402cc5
        .text:0x00402d60  loc_00402d60: [1 XREFS]
        .text:0x00402d60  33c0             xor eax,eax
        .text:0x00402d62  loc_00402d62: [2 XREFS]
        .text:0x00402d62  5f               pop edi
        .text:0x00402d63  5e               pop esi
        .text:0x00402d64  5b               pop ebx
        .text:0x00402d65  8be5             mov esp,ebp
        .text:0x00402d67  5d               pop ebp
        .text:0x00402d68  c3               ret 
        */
        $c40 = { 55 8B EC B8 0C 10 00 00 E8 ?? ?? ?? ?? 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? B9 01 00 00 00 85 C9 0F 84 ?? ?? ?? ?? 68 00 04 00 00 8D 95 ?? ?? ?? ?? 52 68 00 04 00 00 8D 85 ?? ?? ?? ?? 50 68 00 04 00 00 8D 8D ?? ?? ?? ?? 51 68 00 04 00 00 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 20 85 C0 74 ?? B8 01 00 00 00 EB ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 50 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? B8 01 00 00 00 EB ?? 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 04 69 C0 E8 03 00 00 50 FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00402d70@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB NtGlobalFlag flag
        .text:0x00402d70  
        .text:0x00402d70  FUNC: int cdecl sub_00402d70( int arg0, ) [2 XREFS] 
        .text:0x00402d70  
        .text:0x00402d70  Stack Variables: (offset from initial top of stack)
        .text:0x00402d70             4: int arg0
        .text:0x00402d70            -8: int local8
        .text:0x00402d70           -12: int local12
        .text:0x00402d70           -16: int local16
        .text:0x00402d70           -20: int local20
        .text:0x00402d70  
        .text:0x00402d70  55               push ebp
        .text:0x00402d71  8bec             mov ebp,esp
        .text:0x00402d73  83ec10           sub esp,16
        .text:0x00402d76  53               push ebx
        .text:0x00402d77  56               push esi
        .text:0x00402d78  57               push edi
        .text:0x00402d79  c745f400000000   mov dword [ebp - 12],0
        .text:0x00402d80  c745f000000000   mov dword [ebp - 16],0
        .text:0x00402d87  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402d8d  8a5802           mov bl,byte [eax + 2]
        .text:0x00402d90  885df8           mov byte [ebp - 8],bl
        .text:0x00402d93  0fbe45f8         movsx eax,byte [ebp - 8]
        .text:0x00402d97  85c0             test eax,eax
        .text:0x00402d99  7405             jz 0x00402da0
        .text:0x00402d9b  e860e2ffff       call 0x00401000    ;sub_00401000()
        .text:0x00402da0  loc_00402da0: [1 XREFS]
        .text:0x00402da0  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402da6  8b4018           mov eax,dword [eax + 24]
        .text:0x00402da9  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x00402dad  8945f4           mov dword [ebp - 12],eax
        .text:0x00402db0  837df400         cmp dword [ebp - 12],0
        .text:0x00402db4  7405             jz 0x00402dbb
        .text:0x00402db6  e845e2ffff       call 0x00401000    ;sub_00401000()
        .text:0x00402dbb  loc_00402dbb: [1 XREFS]
        .text:0x00402dbb  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402dc1  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x00402dc5  83e870           sub eax,112
        .text:0x00402dc8  8945f0           mov dword [ebp - 16],eax
        .text:0x00402dcb  837df000         cmp dword [ebp - 16],0
        .text:0x00402dcf  7505             jnz 0x00402dd6
        .text:0x00402dd1  e82ae2ffff       call 0x00401000    ;sub_00401000()
        .text:0x00402dd6  loc_00402dd6: [1 XREFS]
        .text:0x00402dd6  8b7d08           mov edi,dword [ebp + 8]
        .text:0x00402dd9  83c9ff           or ecx,0xffffffff
        .text:0x00402ddc  33c0             xor eax,eax
        .text:0x00402dde  f2ae             repnz: scasb 
        .text:0x00402de0  f7d1             not ecx
        .text:0x00402de2  83c1ff           add ecx,0xffffffff
        .text:0x00402de5  83f904           cmp ecx,4
        .text:0x00402de8  7404             jz 0x00402dee
        .text:0x00402dea  33c0             xor eax,eax
        .text:0x00402dec  eb74             jmp 0x00402e62
        .text:0x00402dee  loc_00402dee: [1 XREFS]
        .text:0x00402dee  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00402df1  8a11             mov dl,byte [ecx]
        .text:0x00402df3  8855fc           mov byte [ebp - 4],dl
        .text:0x00402df6  0fbe45fc         movsx eax,byte [ebp - 4]
        .text:0x00402dfa  83f861           cmp eax,97
        .text:0x00402dfd  7404             jz 0x00402e03
        .text:0x00402dff  33c0             xor eax,eax
        .text:0x00402e01  eb5f             jmp 0x00402e62
        .text:0x00402e03  loc_00402e03: [1 XREFS]
        .text:0x00402e03  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00402e06  8a5101           mov dl,byte [ecx + 1]
        .text:0x00402e09  8855fc           mov byte [ebp - 4],dl
        .text:0x00402e0c  8b4508           mov eax,dword [ebp + 8]
        .text:0x00402e0f  8a4dfc           mov cl,byte [ebp - 4]
        .text:0x00402e12  2a08             sub cl,byte [eax]
        .text:0x00402e14  884dfc           mov byte [ebp - 4],cl
        .text:0x00402e17  0fbe55fc         movsx edx,byte [ebp - 4]
        .text:0x00402e1b  83fa01           cmp edx,1
        .text:0x00402e1e  7404             jz 0x00402e24
        .text:0x00402e20  33c0             xor eax,eax
        .text:0x00402e22  eb3e             jmp 0x00402e62
        .text:0x00402e24  loc_00402e24: [1 XREFS]
        .text:0x00402e24  8a45fc           mov al,byte [ebp - 4]
        .text:0x00402e27  b163             mov cl,99
        .text:0x00402e29  f6e9             imul cl
        .text:0x00402e2b  8845fc           mov byte [ebp - 4],al
        .text:0x00402e2e  0fbe55fc         movsx edx,byte [ebp - 4]
        .text:0x00402e32  8b4508           mov eax,dword [ebp + 8]
        .text:0x00402e35  0fbe4802         movsx ecx,byte [eax + 2]
        .text:0x00402e39  3bd1             cmp edx,ecx
        .text:0x00402e3b  7404             jz 0x00402e41
        .text:0x00402e3d  33c0             xor eax,eax
        .text:0x00402e3f  eb21             jmp 0x00402e62
        .text:0x00402e41  loc_00402e41: [1 XREFS]
        .text:0x00402e41  8a55fc           mov dl,byte [ebp - 4]
        .text:0x00402e44  80c201           add dl,1
        .text:0x00402e47  8855fc           mov byte [ebp - 4],dl
        .text:0x00402e4a  0fbe45fc         movsx eax,byte [ebp - 4]
        .text:0x00402e4e  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00402e51  0fbe5103         movsx edx,byte [ecx + 3]
        .text:0x00402e55  3bc2             cmp eax,edx
        .text:0x00402e57  7404             jz 0x00402e5d
        .text:0x00402e59  33c0             xor eax,eax
        .text:0x00402e5b  eb05             jmp 0x00402e62
        .text:0x00402e5d  loc_00402e5d: [1 XREFS]
        .text:0x00402e5d  b801000000       mov eax,1
        .text:0x00402e62  loc_00402e62: [5 XREFS]
        .text:0x00402e62  5f               pop edi
        .text:0x00402e63  5e               pop esi
        .text:0x00402e64  5b               pop ebx
        .text:0x00402e65  8be5             mov esp,ebp
        .text:0x00402e67  5d               pop ebp
        .text:0x00402e68  c3               ret 
        */
        $c41 = { 55 8B EC 83 EC 10 53 56 57 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 5D ?? 0F BE 45 ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 45 ?? 83 7D ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 45 ?? 83 7D ?? 00 75 ?? E8 ?? ?? ?? ?? 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 83 F9 04 74 ?? 33 C0 EB ?? 8B 4D ?? 8A 11 88 55 ?? 0F BE 45 ?? 83 F8 61 74 ?? 33 C0 EB ?? 8B 4D ?? 8A 51 ?? 88 55 ?? 8B 45 ?? 8A 4D ?? 2A 08 88 4D ?? 0F BE 55 ?? 83 FA 01 74 ?? 33 C0 EB ?? 8A 45 ?? B1 63 F6 E9 88 45 ?? 0F BE 55 ?? 8B 45 ?? 0F BE 48 ?? 3B D1 74 ?? 33 C0 EB ?? 8A 55 ?? 80 C2 01 88 55 ?? 0F BE 45 ?? 8B 4D ?? 0F BE 51 ?? 3B C2 74 ?? 33 C0 EB ?? B8 01 00 00 00 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00402e70@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB NtGlobalFlag flag
        .text:0x00402e70  
        .text:0x00402e70  FUNC: int cdecl sub_00402e70( int arg0, ) [8 XREFS] 
        .text:0x00402e70  
        .text:0x00402e70  Stack Variables: (offset from initial top of stack)
        .text:0x00402e70             4: int arg0
        .text:0x00402e70          -1028: int local1028
        .text:0x00402e70          -1032: int local1032
        .text:0x00402e70          -1036: int local1036
        .text:0x00402e70          -1040: int local1040
        .text:0x00402e70  
        .text:0x00402e70  55               push ebp
        .text:0x00402e71  8bec             mov ebp,esp
        .text:0x00402e73  81ec0c040000     sub esp,1036
        .text:0x00402e79  53               push ebx
        .text:0x00402e7a  56               push esi
        .text:0x00402e7b  57               push edi
        .text:0x00402e7c  c785f8fbffff0000 mov dword [ebp - 1032],0
        .text:0x00402e86  c785f4fbffff0000 mov dword [ebp - 1036],0
        .text:0x00402e90  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402e96  8a5802           mov bl,byte [eax + 2]
        .text:0x00402e99  889dfcfbffff     mov byte [ebp - 1028],bl
        .text:0x00402e9f  0fbe85fcfbffff   movsx eax,byte [ebp - 1028]
        .text:0x00402ea6  85c0             test eax,eax
        .text:0x00402ea8  7405             jz 0x00402eaf
        .text:0x00402eaa  e851e1ffff       call 0x00401000    ;sub_00401000()
        .text:0x00402eaf  loc_00402eaf: [1 XREFS]
        .text:0x00402eaf  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402eb5  8b4018           mov eax,dword [eax + 24]
        .text:0x00402eb8  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x00402ebc  8985f8fbffff     mov dword [ebp - 1032],eax
        .text:0x00402ec2  83bdf8fbffff00   cmp dword [ebp - 1032],0
        .text:0x00402ec9  7405             jz 0x00402ed0
        .text:0x00402ecb  e830e1ffff       call 0x00401000    ;sub_00401000()
        .text:0x00402ed0  loc_00402ed0: [1 XREFS]
        .text:0x00402ed0  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402ed6  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x00402eda  83e870           sub eax,112
        .text:0x00402edd  8985f4fbffff     mov dword [ebp - 1036],eax
        .text:0x00402ee3  83bdf4fbffff00   cmp dword [ebp - 1036],0
        .text:0x00402eea  7505             jnz 0x00402ef1
        .text:0x00402eec  e80fe1ffff       call 0x00401000    ;sub_00401000()
        .text:0x00402ef1  loc_00402ef1: [1 XREFS]
        .text:0x00402ef1  6800040000       push 1024
        .text:0x00402ef6  8d8d00fcffff     lea ecx,dword [ebp - 1024]
        .text:0x00402efc  51               push ecx
        .text:0x00402efd  6a00             push 0
        .text:0x00402eff  ff155cb04000     call dword [0x0040b05c]    ;kernel32.GetModuleFileNameA(0,local1028,1024)
        .text:0x00402f05  85c0             test eax,eax
        .text:0x00402f07  7507             jnz 0x00402f10
        .text:0x00402f09  b801000000       mov eax,1
        .text:0x00402f0e  eb1b             jmp 0x00402f2b
        .text:0x00402f10  loc_00402f10: [1 XREFS]
        .text:0x00402f10  6a00             push 0
        .text:0x00402f12  8b5508           mov edx,dword [ebp + 8]
        .text:0x00402f15  52               push edx
        .text:0x00402f16  6a00             push 0
        .text:0x00402f18  6a00             push 0
        .text:0x00402f1a  8d8500fcffff     lea eax,dword [ebp - 1024]
        .text:0x00402f20  50               push eax
        .text:0x00402f21  e862120000       call 0x00404188    ;__splitpath(local1028,arg0,local1028,local1028,0,0,arg0)
        .text:0x00402f26  83c414           add esp,20
        .text:0x00402f29  33c0             xor eax,eax
        .text:0x00402f2b  loc_00402f2b: [1 XREFS]
        .text:0x00402f2b  5f               pop edi
        .text:0x00402f2c  5e               pop esi
        .text:0x00402f2d  5b               pop ebx
        .text:0x00402f2e  8be5             mov esp,ebp
        .text:0x00402f30  5d               pop ebp
        .text:0x00402f31  c3               ret 
        */
        $c42 = { 55 8B EC 81 EC 0C 04 00 00 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? 68 00 04 00 00 8D 8D ?? ?? ?? ?? 51 6A 00 FF 15 ?? ?? ?? ?? 85 C0 75 ?? B8 01 00 00 00 EB ?? 6A 00 8B 55 ?? 52 6A 00 6A 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 14 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00402f40@7faafc7e4a5c736ebfee6abbbc812d80 with 6 features:
          - check for PEB NtGlobalFlag flag
          - copy file
          - create service
          - modify service
          - persist via Windows service
          - query environment variable
        .text:0x00402f40  
        .text:0x00402f40  FUNC: int cdecl sub_00402f40( int arg0, ) [4 XREFS] 
        .text:0x00402f40  
        .text:0x00402f40  Stack Variables: (offset from initial top of stack)
        .text:0x00402f40             4: int arg0
        .text:0x00402f40          -1028: int local1028
        .text:0x00402f40          -1032: int local1032
        .text:0x00402f40          -2056: int local2056
        .text:0x00402f40          -3080: int local3080
        .text:0x00402f40          -4104: int local4104
        .text:0x00402f40          -5128: int local5128
        .text:0x00402f40          -5132: int local5132
        .text:0x00402f40          -5136: int local5136
        .text:0x00402f40          -5140: int local5140
        .text:0x00402f40          -5144: int local5144
        .text:0x00402f40  
        .text:0x00402f40  55               push ebp
        .text:0x00402f41  8bec             mov ebp,esp
        .text:0x00402f43  b814140000       mov eax,0x00001414
        .text:0x00402f48  e8230a0000       call 0x00403970    ;__alloca_probe()
        .text:0x00402f4d  53               push ebx
        .text:0x00402f4e  56               push esi
        .text:0x00402f4f  57               push edi
        .text:0x00402f50  c785f0ebffff0000 mov dword [ebp - 5136],0
        .text:0x00402f5a  c785ecebffff0000 mov dword [ebp - 5140],0
        .text:0x00402f64  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402f6a  8a5802           mov bl,byte [eax + 2]
        .text:0x00402f6d  889df4ebffff     mov byte [ebp - 5132],bl
        .text:0x00402f73  0fbe85f4ebffff   movsx eax,byte [ebp - 5132]
        .text:0x00402f7a  85c0             test eax,eax
        .text:0x00402f7c  7405             jz 0x00402f83
        .text:0x00402f7e  e87de0ffff       call 0x00401000    ;sub_00401000()
        .text:0x00402f83  loc_00402f83: [1 XREFS]
        .text:0x00402f83  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402f89  8b4018           mov eax,dword [eax + 24]
        .text:0x00402f8c  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x00402f90  8985f0ebffff     mov dword [ebp - 5136],eax
        .text:0x00402f96  83bdf0ebffff00   cmp dword [ebp - 5136],0
        .text:0x00402f9d  7405             jz 0x00402fa4
        .text:0x00402f9f  e85ce0ffff       call 0x00401000    ;sub_00401000()
        .text:0x00402fa4  loc_00402fa4: [1 XREFS]
        .text:0x00402fa4  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00402faa  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x00402fae  83e870           sub eax,112
        .text:0x00402fb1  8985ecebffff     mov dword [ebp - 5140],eax
        .text:0x00402fb7  83bdecebffff00   cmp dword [ebp - 5140],0
        .text:0x00402fbe  7505             jnz 0x00402fc5
        .text:0x00402fc0  e83be0ffff       call 0x00401000    ;sub_00401000()
        .text:0x00402fc5  loc_00402fc5: [1 XREFS]
        .text:0x00402fc5  6800040000       push 1024
        .text:0x00402fca  8d8dfcebffff     lea ecx,dword [ebp - 5124]
        .text:0x00402fd0  51               push ecx
        .text:0x00402fd1  e89afeffff       call 0x00402e70    ;sub_00402e70(local5128)
        .text:0x00402fd6  83c408           add esp,8
        .text:0x00402fd9  85c0             test eax,eax
        .text:0x00402fdb  740a             jz 0x00402fe7
        .text:0x00402fdd  b801000000       mov eax,1
        .text:0x00402fe2  e9c3020000       jmp 0x004032aa
        .text:0x00402fe7  loc_00402fe7: [1 XREFS]
        .text:0x00402fe7  bf34c14000       mov edi,0x0040c134
        .text:0x00402fec  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x00402ff2  83c9ff           or ecx,0xffffffff
        .text:0x00402ff5  33c0             xor eax,eax
        .text:0x00402ff7  f2ae             repnz: scasb 
        .text:0x00402ff9  f7d1             not ecx
        .text:0x00402ffb  2bf9             sub edi,ecx
        .text:0x00402ffd  8bf7             mov esi,edi
        .text:0x00402fff  8bc1             mov eax,ecx
        .text:0x00403001  8bfa             mov edi,edx
        .text:0x00403003  c1e902           shr ecx,2
        .text:0x00403006  f3a5             rep: movsd 
        .text:0x00403008  8bc8             mov ecx,eax
        .text:0x0040300a  83e103           and ecx,3
        .text:0x0040300d  f3a4             rep: movsb 
        .text:0x0040300f  8dbdfcebffff     lea edi,dword [ebp - 5124]
        .text:0x00403015  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x0040301b  83c9ff           or ecx,0xffffffff
        .text:0x0040301e  33c0             xor eax,eax
        .text:0x00403020  f2ae             repnz: scasb 
        .text:0x00403022  f7d1             not ecx
        .text:0x00403024  2bf9             sub edi,ecx
        .text:0x00403026  8bf7             mov esi,edi
        .text:0x00403028  8bd9             mov ebx,ecx
        .text:0x0040302a  8bfa             mov edi,edx
        .text:0x0040302c  83c9ff           or ecx,0xffffffff
        .text:0x0040302f  33c0             xor eax,eax
        .text:0x00403031  f2ae             repnz: scasb 
        .text:0x00403033  83c7ff           add edi,0xffffffff
        .text:0x00403036  8bcb             mov ecx,ebx
        .text:0x00403038  c1e902           shr ecx,2
        .text:0x0040303b  f3a5             rep: movsd 
        .text:0x0040303d  8bcb             mov ecx,ebx
        .text:0x0040303f  83e103           and ecx,3
        .text:0x00403042  f3a4             rep: movsb 
        .text:0x00403044  bf2cc14000       mov edi,0x0040c12c
        .text:0x00403049  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x0040304f  83c9ff           or ecx,0xffffffff
        .text:0x00403052  33c0             xor eax,eax
        .text:0x00403054  f2ae             repnz: scasb 
        .text:0x00403056  f7d1             not ecx
        .text:0x00403058  2bf9             sub edi,ecx
        .text:0x0040305a  8bf7             mov esi,edi
        .text:0x0040305c  8bd9             mov ebx,ecx
        .text:0x0040305e  8bfa             mov edi,edx
        .text:0x00403060  83c9ff           or ecx,0xffffffff
        .text:0x00403063  33c0             xor eax,eax
        .text:0x00403065  f2ae             repnz: scasb 
        .text:0x00403067  83c7ff           add edi,0xffffffff
        .text:0x0040306a  8bcb             mov ecx,ebx
        .text:0x0040306c  c1e902           shr ecx,2
        .text:0x0040306f  f3a5             rep: movsd 
        .text:0x00403071  8bcb             mov ecx,ebx
        .text:0x00403073  83e103           and ecx,3
        .text:0x00403076  f3a4             rep: movsb 
        .text:0x00403078  683f000f00       push 0x000f003f
        .text:0x0040307d  6a00             push 0
        .text:0x0040307f  6a00             push 0
        .text:0x00403081  ff1500b04000     call dword [0x0040b000]    ;advapi32.OpenSCManagerA(0,0,0x000f003f)
        .text:0x00403087  8985fcfbffff     mov dword [ebp - 1028],eax
        .text:0x0040308d  83bdfcfbffff00   cmp dword [ebp - 1028],0
        .text:0x00403094  750a             jnz 0x004030a0
        .text:0x00403096  b801000000       mov eax,1
        .text:0x0040309b  e90a020000       jmp 0x004032aa
        .text:0x004030a0  loc_004030a0: [1 XREFS]
        .text:0x004030a0  68ff010f00       push 0x000f01ff
        .text:0x004030a5  8b4508           mov eax,dword [ebp + 8]
        .text:0x004030a8  50               push eax
        .text:0x004030a9  8b8dfcfbffff     mov ecx,dword [ebp - 1028]
        .text:0x004030af  51               push ecx
        .text:0x004030b0  ff1504b04000     call dword [0x0040b004]    ;advapi32.OpenServiceA(advapi32.OpenSCManagerA(0,0,0x000f003f),arg0,0x000f01ff)
        .text:0x004030b6  8985f8ebffff     mov dword [ebp - 5128],eax
        .text:0x004030bc  83bdf8ebffff00   cmp dword [ebp - 5128],0
        .text:0x004030c3  746d             jz 0x00403132
        .text:0x004030c5  6a00             push 0
        .text:0x004030c7  6a00             push 0
        .text:0x004030c9  6a00             push 0
        .text:0x004030cb  6a00             push 0
        .text:0x004030cd  6a00             push 0
        .text:0x004030cf  6a00             push 0
        .text:0x004030d1  8d95fcf7ffff     lea edx,dword [ebp - 2052]
        .text:0x004030d7  52               push edx
        .text:0x004030d8  6aff             push 0xffffffff
        .text:0x004030da  6a02             push 2
        .text:0x004030dc  6aff             push 0xffffffff
        .text:0x004030de  8b85f8ebffff     mov eax,dword [ebp - 5128]
        .text:0x004030e4  50               push eax
        .text:0x004030e5  ff1508b04000     call dword [0x0040b008]    ;advapi32.ChangeServiceConfigA(advapi32.OpenServiceA(<0x00403081>,arg0,0x000f01ff),0xffffffff,2,0xffffffff,local2056,0,0,0,0,0,0)
        .text:0x004030eb  85c0             test eax,eax
        .text:0x004030ed  7524             jnz 0x00403113
        .text:0x004030ef  8b8df8ebffff     mov ecx,dword [ebp - 5128]
        .text:0x004030f5  51               push ecx
        .text:0x004030f6  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x004030b0>)
        .text:0x004030fc  8b95fcfbffff     mov edx,dword [ebp - 1028]
        .text:0x00403102  52               push edx
        .text:0x00403103  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x00403081>)
        .text:0x00403109  b801000000       mov eax,1
        .text:0x0040310e  e997010000       jmp 0x004032aa
        .text:0x00403113  loc_00403113: [1 XREFS]
        .text:0x00403113  8b85f8ebffff     mov eax,dword [ebp - 5128]
        .text:0x00403119  50               push eax
        .text:0x0040311a  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x004030b0>)
        .text:0x00403120  8b8dfcfbffff     mov ecx,dword [ebp - 1028]
        .text:0x00403126  51               push ecx
        .text:0x00403127  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x00403081>)
        .text:0x0040312d  e9ce000000       jmp 0x00403200
        .text:0x00403132  loc_00403132: [1 XREFS]
        .text:0x00403132  8b7d08           mov edi,dword [ebp + 8]
        .text:0x00403135  8d95fcf3ffff     lea edx,dword [ebp - 3076]
        .text:0x0040313b  83c9ff           or ecx,0xffffffff
        .text:0x0040313e  33c0             xor eax,eax
        .text:0x00403140  f2ae             repnz: scasb 
        .text:0x00403142  f7d1             not ecx
        .text:0x00403144  2bf9             sub edi,ecx
        .text:0x00403146  8bf7             mov esi,edi
        .text:0x00403148  8bc1             mov eax,ecx
        .text:0x0040314a  8bfa             mov edi,edx
        .text:0x0040314c  c1e902           shr ecx,2
        .text:0x0040314f  f3a5             rep: movsd 
        .text:0x00403151  8bc8             mov ecx,eax
        .text:0x00403153  83e103           and ecx,3
        .text:0x00403156  f3a4             rep: movsb 
        .text:0x00403158  bf18c14000       mov edi,0x0040c118
        .text:0x0040315d  8d95fcf3ffff     lea edx,dword [ebp - 3076]
        .text:0x00403163  83c9ff           or ecx,0xffffffff
        .text:0x00403166  33c0             xor eax,eax
        .text:0x00403168  f2ae             repnz: scasb 
        .text:0x0040316a  f7d1             not ecx
        .text:0x0040316c  2bf9             sub edi,ecx
        .text:0x0040316e  8bf7             mov esi,edi
        .text:0x00403170  8bd9             mov ebx,ecx
        .text:0x00403172  8bfa             mov edi,edx
        .text:0x00403174  83c9ff           or ecx,0xffffffff
        .text:0x00403177  33c0             xor eax,eax
        .text:0x00403179  f2ae             repnz: scasb 
        .text:0x0040317b  83c7ff           add edi,0xffffffff
        .text:0x0040317e  8bcb             mov ecx,ebx
        .text:0x00403180  c1e902           shr ecx,2
        .text:0x00403183  f3a5             rep: movsd 
        .text:0x00403185  8bcb             mov ecx,ebx
        .text:0x00403187  83e103           and ecx,3
        .text:0x0040318a  f3a4             rep: movsb 
        .text:0x0040318c  6a00             push 0
        .text:0x0040318e  6a00             push 0
        .text:0x00403190  6a00             push 0
        .text:0x00403192  6a00             push 0
        .text:0x00403194  6a00             push 0
        .text:0x00403196  8d8500fcffff     lea eax,dword [ebp - 1024]
        .text:0x0040319c  50               push eax
        .text:0x0040319d  6a01             push 1
        .text:0x0040319f  6a02             push 2
        .text:0x004031a1  6a20             push 32
        .text:0x004031a3  68ff010f00       push 0x000f01ff
        .text:0x004031a8  8d8dfcf3ffff     lea ecx,dword [ebp - 3076]
        .text:0x004031ae  51               push ecx
        .text:0x004031af  8b5508           mov edx,dword [ebp + 8]
        .text:0x004031b2  52               push edx
        .text:0x004031b3  8b85fcfbffff     mov eax,dword [ebp - 1028]
        .text:0x004031b9  50               push eax
        .text:0x004031ba  ff1510b04000     call dword [0x0040b010]    ;advapi32.CreateServiceA(<0x00403081>,arg0,local3080,0x000f01ff,32,2,1,local1028,0,0,0,0,0)
        .text:0x004031c0  8985f8ebffff     mov dword [ebp - 5128],eax
        .text:0x004031c6  83bdf8ebffff00   cmp dword [ebp - 5128],0
        .text:0x004031cd  7517             jnz 0x004031e6
        .text:0x004031cf  8b8dfcfbffff     mov ecx,dword [ebp - 1028]
        .text:0x004031d5  51               push ecx
        .text:0x004031d6  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x00403081>)
        .text:0x004031dc  b801000000       mov eax,1
        .text:0x004031e1  e9c4000000       jmp 0x004032aa
        .text:0x004031e6  loc_004031e6: [1 XREFS]
        .text:0x004031e6  8b95f8ebffff     mov edx,dword [ebp - 5128]
        .text:0x004031ec  52               push edx
        .text:0x004031ed  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(advapi32.CreateServiceA(<0x00403081>,arg0,local3080,0x000f01ff,32,2,1,local1028,0,0,0,0,0))
        .text:0x004031f3  8b85fcfbffff     mov eax,dword [ebp - 1028]
        .text:0x004031f9  50               push eax
        .text:0x004031fa  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x00403081>)
        .text:0x00403200  loc_00403200: [1 XREFS]
        .text:0x00403200  6800040000       push 1024
        .text:0x00403205  8d8dfcf7ffff     lea ecx,dword [ebp - 2052]
        .text:0x0040320b  51               push ecx
        .text:0x0040320c  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x00403212  52               push edx
        .text:0x00403213  ff1530b04000     call dword [0x0040b030]    ;kernel32.ExpandEnvironmentStringsA(local1028,local2056,1024)
        .text:0x00403219  85c0             test eax,eax
        .text:0x0040321b  750a             jnz 0x00403227
        .text:0x0040321d  b801000000       mov eax,1
        .text:0x00403222  e983000000       jmp 0x004032aa
        .text:0x00403227  loc_00403227: [1 XREFS]
        .text:0x00403227  6800040000       push 1024
        .text:0x0040322c  8d85fcefffff     lea eax,dword [ebp - 4100]
        .text:0x00403232  50               push eax
        .text:0x00403233  6a00             push 0
        .text:0x00403235  ff155cb04000     call dword [0x0040b05c]    ;kernel32.GetModuleFileNameA(0,local4104,1024)
        .text:0x0040323b  85c0             test eax,eax
        .text:0x0040323d  7507             jnz 0x00403246
        .text:0x0040323f  b801000000       mov eax,1
        .text:0x00403244  eb64             jmp 0x004032aa
        .text:0x00403246  loc_00403246: [1 XREFS]
        .text:0x00403246  6a00             push 0
        .text:0x00403248  8d8dfcf7ffff     lea ecx,dword [ebp - 2052]
        .text:0x0040324e  51               push ecx
        .text:0x0040324f  8d95fcefffff     lea edx,dword [ebp - 4100]
        .text:0x00403255  52               push edx
        .text:0x00403256  ff1534b04000     call dword [0x0040b034]    ;kernel32.CopyFileA(local4104,local2056,0)
        .text:0x0040325c  85c0             test eax,eax
        .text:0x0040325e  7507             jnz 0x00403267
        .text:0x00403260  b801000000       mov eax,1
        .text:0x00403265  eb43             jmp 0x004032aa
        .text:0x00403267  loc_00403267: [1 XREFS]
        .text:0x00403267  8d85fcf7ffff     lea eax,dword [ebp - 2052]
        .text:0x0040326d  50               push eax
        .text:0x0040326e  e83de7ffff       call 0x004019b0    ;sub_004019b0(local2056)
        .text:0x00403273  83c404           add esp,4
        .text:0x00403276  85c0             test eax,eax
        .text:0x00403278  7407             jz 0x00403281
        .text:0x0040327a  b801000000       mov eax,1
        .text:0x0040327f  eb29             jmp 0x004032aa
        .text:0x00403281  loc_00403281: [1 XREFS]
        .text:0x00403281  6814c14000       push 0x0040c114
        .text:0x00403286  6810c14000       push 0x0040c110
        .text:0x0040328b  68e8c04000       push 0x0040c0e8
        .text:0x00403290  68e4c04000       push 0x0040c0e4
        .text:0x00403295  e836dfffff       call 0x004011d0    ;sub_004011d0(0x0040c0e4,0x0040c0e8,0x0040c110,0x0040c114)
        .text:0x0040329a  83c410           add esp,16
        .text:0x0040329d  85c0             test eax,eax
        .text:0x0040329f  7407             jz 0x004032a8
        .text:0x004032a1  b801000000       mov eax,1
        .text:0x004032a6  eb02             jmp 0x004032aa
        .text:0x004032a8  loc_004032a8: [1 XREFS]
        .text:0x004032a8  33c0             xor eax,eax
        .text:0x004032aa  loc_004032aa: [9 XREFS]
        .text:0x004032aa  5f               pop edi
        .text:0x004032ab  5e               pop esi
        .text:0x004032ac  5b               pop ebx
        .text:0x004032ad  8be5             mov esp,ebp
        .text:0x004032af  5d               pop ebp
        .text:0x004032b0  c3               ret 
        */
        $c43 = { 55 8B EC B8 14 14 00 00 E8 ?? ?? ?? ?? 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? 68 00 04 00 00 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? BF 34 C1 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8D BD ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 BF 2C C1 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 68 3F 00 0F 00 6A 00 6A 00 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 68 FF 01 0F 00 8B 45 ?? 50 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? 6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 8D 95 ?? ?? ?? ?? 52 6A FF 6A 02 6A FF 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 7D ?? 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 BF 18 C1 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 6A 00 6A 00 6A 00 6A 00 6A 00 8D 85 ?? ?? ?? ?? 50 6A 01 6A 02 6A 20 68 FF 01 0F 00 8D 8D ?? ?? ?? ?? 51 8B 55 ?? 52 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 68 00 04 00 00 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 68 00 04 00 00 8D 85 ?? ?? ?? ?? 50 6A 00 FF 15 ?? ?? ?? ?? 85 C0 75 ?? B8 01 00 00 00 EB ?? 6A 00 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? B8 01 00 00 00 EB ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 ?? B8 01 00 00 00 EB ?? 68 14 C1 40 00 68 10 C1 40 00 68 E8 C0 40 00 68 E4 C0 40 00 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 ?? B8 01 00 00 00 EB ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x004032c0@7faafc7e4a5c736ebfee6abbbc812d80 with 4 features:
          - check for PEB NtGlobalFlag flag
          - delete file
          - delete service
          - query environment variable
        .text:0x004032c0  
        .text:0x004032c0  FUNC: int cdecl sub_004032c0( int arg0, ) [4 XREFS] 
        .text:0x004032c0  
        .text:0x004032c0  Stack Variables: (offset from initial top of stack)
        .text:0x004032c0             4: int arg0
        .text:0x004032c0          -1028: int local1028
        .text:0x004032c0          -1032: int local1032
        .text:0x004032c0          -2056: int local2056
        .text:0x004032c0          -3080: int local3080
        .text:0x004032c0          -3084: int local3084
        .text:0x004032c0          -3088: int local3088
        .text:0x004032c0          -3092: int local3092
        .text:0x004032c0          -3096: int local3096
        .text:0x004032c0  
        .text:0x004032c0  55               push ebp
        .text:0x004032c1  8bec             mov ebp,esp
        .text:0x004032c3  81ec140c0000     sub esp,3092
        .text:0x004032c9  53               push ebx
        .text:0x004032ca  56               push esi
        .text:0x004032cb  57               push edi
        .text:0x004032cc  c785f0f3ffff0000 mov dword [ebp - 3088],0
        .text:0x004032d6  c785ecf3ffff0000 mov dword [ebp - 3092],0
        .text:0x004032e0  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x004032e6  8a5802           mov bl,byte [eax + 2]
        .text:0x004032e9  889df4f3ffff     mov byte [ebp - 3084],bl
        .text:0x004032ef  0fbe85f4f3ffff   movsx eax,byte [ebp - 3084]
        .text:0x004032f6  85c0             test eax,eax
        .text:0x004032f8  7405             jz 0x004032ff
        .text:0x004032fa  e801ddffff       call 0x00401000    ;sub_00401000()
        .text:0x004032ff  loc_004032ff: [1 XREFS]
        .text:0x004032ff  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00403305  8b4018           mov eax,dword [eax + 24]
        .text:0x00403308  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x0040330c  8985f0f3ffff     mov dword [ebp - 3088],eax
        .text:0x00403312  83bdf0f3ffff00   cmp dword [ebp - 3088],0
        .text:0x00403319  7405             jz 0x00403320
        .text:0x0040331b  e8e0dcffff       call 0x00401000    ;sub_00401000()
        .text:0x00403320  loc_00403320: [1 XREFS]
        .text:0x00403320  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00403326  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x0040332a  83e870           sub eax,112
        .text:0x0040332d  8985ecf3ffff     mov dword [ebp - 3092],eax
        .text:0x00403333  83bdecf3ffff00   cmp dword [ebp - 3092],0
        .text:0x0040333a  7505             jnz 0x00403341
        .text:0x0040333c  e8bfdcffff       call 0x00401000    ;sub_00401000()
        .text:0x00403341  loc_00403341: [1 XREFS]
        .text:0x00403341  683f000f00       push 0x000f003f
        .text:0x00403346  6a00             push 0
        .text:0x00403348  6a00             push 0
        .text:0x0040334a  ff1500b04000     call dword [0x0040b000]    ;advapi32.OpenSCManagerA(0,0,0x000f003f)
        .text:0x00403350  8985fcfbffff     mov dword [ebp - 1028],eax
        .text:0x00403356  83bdfcfbffff00   cmp dword [ebp - 1028],0
        .text:0x0040335d  750a             jnz 0x00403369
        .text:0x0040335f  b801000000       mov eax,1
        .text:0x00403364  e9b3010000       jmp 0x0040351c
        .text:0x00403369  loc_00403369: [1 XREFS]
        .text:0x00403369  68ff010f00       push 0x000f01ff
        .text:0x0040336e  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00403371  51               push ecx
        .text:0x00403372  8b95fcfbffff     mov edx,dword [ebp - 1028]
        .text:0x00403378  52               push edx
        .text:0x00403379  ff1504b04000     call dword [0x0040b004]    ;advapi32.OpenServiceA(advapi32.OpenSCManagerA(0,0,0x000f003f),arg0,0x000f01ff)
        .text:0x0040337f  8985f8f3ffff     mov dword [ebp - 3080],eax
        .text:0x00403385  83bdf8f3ffff00   cmp dword [ebp - 3080],0
        .text:0x0040338c  7517             jnz 0x004033a5
        .text:0x0040338e  8b85fcfbffff     mov eax,dword [ebp - 1028]
        .text:0x00403394  50               push eax
        .text:0x00403395  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x0040334a>)
        .text:0x0040339b  b801000000       mov eax,1
        .text:0x004033a0  e977010000       jmp 0x0040351c
        .text:0x004033a5  loc_004033a5: [1 XREFS]
        .text:0x004033a5  8b8df8f3ffff     mov ecx,dword [ebp - 3080]
        .text:0x004033ab  51               push ecx
        .text:0x004033ac  ff1528b04000     call dword [0x0040b028]    ;advapi32.DeleteService(advapi32.OpenServiceA(<0x0040334a>,arg0,0x000f01ff))
        .text:0x004033b2  85c0             test eax,eax
        .text:0x004033b4  7524             jnz 0x004033da
        .text:0x004033b6  8b95fcfbffff     mov edx,dword [ebp - 1028]
        .text:0x004033bc  52               push edx
        .text:0x004033bd  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x0040334a>)
        .text:0x004033c3  8b85f8f3ffff     mov eax,dword [ebp - 3080]
        .text:0x004033c9  50               push eax
        .text:0x004033ca  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x00403379>)
        .text:0x004033d0  b801000000       mov eax,1
        .text:0x004033d5  e942010000       jmp 0x0040351c
        .text:0x004033da  loc_004033da: [1 XREFS]
        .text:0x004033da  8b8dfcfbffff     mov ecx,dword [ebp - 1028]
        .text:0x004033e0  51               push ecx
        .text:0x004033e1  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x0040334a>)
        .text:0x004033e7  8b95f8f3ffff     mov edx,dword [ebp - 3080]
        .text:0x004033ed  52               push edx
        .text:0x004033ee  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x00403379>)
        .text:0x004033f4  6800040000       push 1024
        .text:0x004033f9  8d85fcf3ffff     lea eax,dword [ebp - 3076]
        .text:0x004033ff  50               push eax
        .text:0x00403400  e86bfaffff       call 0x00402e70    ;sub_00402e70(local3080)
        .text:0x00403405  83c408           add esp,8
        .text:0x00403408  85c0             test eax,eax
        .text:0x0040340a  740a             jz 0x00403416
        .text:0x0040340c  b801000000       mov eax,1
        .text:0x00403411  e906010000       jmp 0x0040351c
        .text:0x00403416  loc_00403416: [1 XREFS]
        .text:0x00403416  bf34c14000       mov edi,0x0040c134
        .text:0x0040341b  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x00403421  83c9ff           or ecx,0xffffffff
        .text:0x00403424  33c0             xor eax,eax
        .text:0x00403426  f2ae             repnz: scasb 
        .text:0x00403428  f7d1             not ecx
        .text:0x0040342a  2bf9             sub edi,ecx
        .text:0x0040342c  8bf7             mov esi,edi
        .text:0x0040342e  8bc1             mov eax,ecx
        .text:0x00403430  8bfa             mov edi,edx
        .text:0x00403432  c1e902           shr ecx,2
        .text:0x00403435  f3a5             rep: movsd 
        .text:0x00403437  8bc8             mov ecx,eax
        .text:0x00403439  83e103           and ecx,3
        .text:0x0040343c  f3a4             rep: movsb 
        .text:0x0040343e  8dbdfcf3ffff     lea edi,dword [ebp - 3076]
        .text:0x00403444  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x0040344a  83c9ff           or ecx,0xffffffff
        .text:0x0040344d  33c0             xor eax,eax
        .text:0x0040344f  f2ae             repnz: scasb 
        .text:0x00403451  f7d1             not ecx
        .text:0x00403453  2bf9             sub edi,ecx
        .text:0x00403455  8bf7             mov esi,edi
        .text:0x00403457  8bd9             mov ebx,ecx
        .text:0x00403459  8bfa             mov edi,edx
        .text:0x0040345b  83c9ff           or ecx,0xffffffff
        .text:0x0040345e  33c0             xor eax,eax
        .text:0x00403460  f2ae             repnz: scasb 
        .text:0x00403462  83c7ff           add edi,0xffffffff
        .text:0x00403465  8bcb             mov ecx,ebx
        .text:0x00403467  c1e902           shr ecx,2
        .text:0x0040346a  f3a5             rep: movsd 
        .text:0x0040346c  8bcb             mov ecx,ebx
        .text:0x0040346e  83e103           and ecx,3
        .text:0x00403471  f3a4             rep: movsb 
        .text:0x00403473  bf2cc14000       mov edi,0x0040c12c
        .text:0x00403478  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x0040347e  83c9ff           or ecx,0xffffffff
        .text:0x00403481  33c0             xor eax,eax
        .text:0x00403483  f2ae             repnz: scasb 
        .text:0x00403485  f7d1             not ecx
        .text:0x00403487  2bf9             sub edi,ecx
        .text:0x00403489  8bf7             mov esi,edi
        .text:0x0040348b  8bd9             mov ebx,ecx
        .text:0x0040348d  8bfa             mov edi,edx
        .text:0x0040348f  83c9ff           or ecx,0xffffffff
        .text:0x00403492  33c0             xor eax,eax
        .text:0x00403494  f2ae             repnz: scasb 
        .text:0x00403496  83c7ff           add edi,0xffffffff
        .text:0x00403499  8bcb             mov ecx,ebx
        .text:0x0040349b  c1e902           shr ecx,2
        .text:0x0040349e  f3a5             rep: movsd 
        .text:0x004034a0  8bcb             mov ecx,ebx
        .text:0x004034a2  83e103           and ecx,3
        .text:0x004034a5  f3a4             rep: movsb 
        .text:0x004034a7  6800040000       push 1024
        .text:0x004034ac  8d85fcf7ffff     lea eax,dword [ebp - 2052]
        .text:0x004034b2  50               push eax
        .text:0x004034b3  8d8d00fcffff     lea ecx,dword [ebp - 1024]
        .text:0x004034b9  51               push ecx
        .text:0x004034ba  ff1530b04000     call dword [0x0040b030]    ;kernel32.ExpandEnvironmentStringsA(local1028,local2056,1024)
        .text:0x004034c0  85c0             test eax,eax
        .text:0x004034c2  7507             jnz 0x004034cb
        .text:0x004034c4  b801000000       mov eax,1
        .text:0x004034c9  eb51             jmp 0x0040351c
        .text:0x004034cb  loc_004034cb: [1 XREFS]
        .text:0x004034cb  8d95fcf7ffff     lea edx,dword [ebp - 2052]
        .text:0x004034d1  52               push edx
        .text:0x004034d2  ff1560b04000     call dword [0x0040b060]    ;kernel32.DeleteFileA(local2056)
        .text:0x004034d8  85c0             test eax,eax
        .text:0x004034da  7507             jnz 0x004034e3
        .text:0x004034dc  b801000000       mov eax,1
        .text:0x004034e1  eb39             jmp 0x0040351c
        .text:0x004034e3  loc_004034e3: [1 XREFS]
        .text:0x004034e3  6860eb4000       push 0x0040eb60
        .text:0x004034e8  6860eb4000       push 0x0040eb60
        .text:0x004034ed  6860eb4000       push 0x0040eb60
        .text:0x004034f2  6860eb4000       push 0x0040eb60
        .text:0x004034f7  e8d4dcffff       call 0x004011d0    ;sub_004011d0(0x0040eb60,0x0040eb60,0x0040eb60,0x0040eb60)
        .text:0x004034fc  83c410           add esp,16
        .text:0x004034ff  85c0             test eax,eax
        .text:0x00403501  7407             jz 0x0040350a
        .text:0x00403503  b801000000       mov eax,1
        .text:0x00403508  eb12             jmp 0x0040351c
        .text:0x0040350a  loc_0040350a: [1 XREFS]
        .text:0x0040350a  e8d1deffff       call 0x004013e0    ;sub_004013e0()
        .text:0x0040350f  85c0             test eax,eax
        .text:0x00403511  7407             jz 0x0040351a
        .text:0x00403513  b801000000       mov eax,1
        .text:0x00403518  eb02             jmp 0x0040351c
        .text:0x0040351a  loc_0040351a: [1 XREFS]
        .text:0x0040351a  33c0             xor eax,eax
        .text:0x0040351c  loc_0040351c: [8 XREFS]
        .text:0x0040351c  5f               pop edi
        .text:0x0040351d  5e               pop esi
        .text:0x0040351e  5b               pop ebx
        .text:0x0040351f  8be5             mov esp,ebp
        .text:0x00403521  5d               pop ebp
        .text:0x00403522  c3               ret 
        */
        $c44 = { 55 8B EC 81 EC 14 0C 00 00 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? 68 3F 00 0F 00 6A 00 6A 00 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 68 FF 01 0F 00 8B 4D ?? 51 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 68 00 04 00 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? BF 34 C1 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8D BD ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 BF 2C C1 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 68 00 04 00 00 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 85 C0 75 ?? B8 01 00 00 00 EB ?? 8D 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? B8 01 00 00 00 EB ?? 68 60 EB 40 00 68 60 EB 40 00 68 60 EB 40 00 68 60 EB 40 00 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 ?? B8 01 00 00 00 EB ?? E8 ?? ?? ?? ?? 85 C0 74 ?? B8 01 00 00 00 EB ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00403530@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - check for PEB NtGlobalFlag flag
        .text:0x00403530  
        .text:0x00403530  FUNC: int cdecl sub_00403530( int arg0, int arg1, ) [2 XREFS] 
        .text:0x00403530  
        .text:0x00403530  Stack Variables: (offset from initial top of stack)
        .text:0x00403530             8: int arg1
        .text:0x00403530             4: int arg0
        .text:0x00403530            -8: int local8
        .text:0x00403530          -1032: int local1032
        .text:0x00403530          -1036: int local1036
        .text:0x00403530          -2060: int local2060
        .text:0x00403530          -2064: int local2064
        .text:0x00403530          -2068: int local2068
        .text:0x00403530          -2072: int local2072
        .text:0x00403530          -2076: int local2076
        .text:0x00403530          -2080: int local2080
        .text:0x00403530          -3104: int local3104
        .text:0x00403530          -4128: int local4128
        .text:0x00403530          -5152: int local5152
        .text:0x00403530          -6176: int local6176
        .text:0x00403530          -6180: int local6180
        .text:0x00403530          -6184: int local6184
        .text:0x00403530          -6188: int local6188
        .text:0x00403530          -6192: int local6192
        .text:0x00403530          -6196: int local6196
        .text:0x00403530          -6200: int local6200
        .text:0x00403530          -6204: int local6204
        .text:0x00403530  
        .text:0x00403530  55               push ebp
        .text:0x00403531  8bec             mov ebp,esp
        .text:0x00403533  b838180000       mov eax,0x00001838
        .text:0x00403538  e833040000       call 0x00403970    ;__alloca_probe()
        .text:0x0040353d  53               push ebx
        .text:0x0040353e  56               push esi
        .text:0x0040353f  57               push edi
        .text:0x00403540  c785dce7ffff0000 mov dword [ebp - 6180],0
        .text:0x0040354a  c785d8e7ffff0000 mov dword [ebp - 6184],0
        .text:0x00403554  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040355a  8a5802           mov bl,byte [eax + 2]
        .text:0x0040355d  889de0e7ffff     mov byte [ebp - 6176],bl
        .text:0x00403563  0fbe85e0e7ffff   movsx eax,byte [ebp - 6176]
        .text:0x0040356a  85c0             test eax,eax
        .text:0x0040356c  7405             jz 0x00403573
        .text:0x0040356e  e88ddaffff       call 0x00401000    ;sub_00401000()
        .text:0x00403573  loc_00403573: [1 XREFS]
        .text:0x00403573  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x00403579  8b4018           mov eax,dword [eax + 24]
        .text:0x0040357c  3e8b4010         ds: mov eax,dword [eax + 16]
        .text:0x00403580  8985dce7ffff     mov dword [ebp - 6180],eax
        .text:0x00403586  83bddce7ffff00   cmp dword [ebp - 6180],0
        .text:0x0040358d  7405             jz 0x00403594
        .text:0x0040358f  e86cdaffff       call 0x00401000    ;sub_00401000()
        .text:0x00403594  loc_00403594: [1 XREFS]
        .text:0x00403594  64a130000000     fs: mov eax,dword [0x00000030]
        .text:0x0040359a  3e8b4068         ds: mov eax,dword [eax + 104]
        .text:0x0040359e  83e870           sub eax,112
        .text:0x004035a1  8985d8e7ffff     mov dword [ebp - 6184],eax
        .text:0x004035a7  83bdd8e7ffff00   cmp dword [ebp - 6184],0
        .text:0x004035ae  7505             jnz 0x004035b5
        .text:0x004035b0  e84bdaffff       call 0x00401000    ;sub_00401000()
        .text:0x004035b5  loc_004035b5: [1 XREFS]
        .text:0x004035b5  837d0801         cmp dword [ebp + 8],1
        .text:0x004035b9  751a             jnz 0x004035d5
        .text:0x004035bb  e840dbffff       call 0x00401100    ;sub_00401100()
        .text:0x004035c0  85c0             test eax,eax
        .text:0x004035c2  7407             jz 0x004035cb
        .text:0x004035c4  e877f6ffff       call 0x00402c40    ;sub_00402c40()
        .text:0x004035c9  eb05             jmp 0x004035d0
        .text:0x004035cb  loc_004035cb: [1 XREFS]
        .text:0x004035cb  e830daffff       call 0x00401000    ;sub_00401000()
        .text:0x004035d0  loc_004035d0: [1 XREFS]
        .text:0x004035d0  e959020000       jmp 0x0040382e
        .text:0x004035d5  loc_004035d5: [1 XREFS]
        .text:0x004035d5  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x004035d8  8b550c           mov edx,dword [ebp + 12]
        .text:0x004035db  8b448afc         mov eax,dword [edx + ecx * 4 + -4]
        .text:0x004035df  8945fc           mov dword [ebp - 4],eax
        .text:0x004035e2  8b4dfc           mov ecx,dword [ebp - 4]
        .text:0x004035e5  51               push ecx
        .text:0x004035e6  e885f7ffff       call 0x00402d70    ;sub_00402d70(0x61616161)
        .text:0x004035eb  83c404           add esp,4
        .text:0x004035ee  85c0             test eax,eax
        .text:0x004035f0  7505             jnz 0x004035f7
        .text:0x004035f2  e809daffff       call 0x00401000    ;sub_00401000()
        .text:0x004035f7  loc_004035f7: [1 XREFS]
        .text:0x004035f7  8b550c           mov edx,dword [ebp + 12]
        .text:0x004035fa  8b4204           mov eax,dword [edx + 4]
        .text:0x004035fd  8985d4e7ffff     mov dword [ebp - 6188],eax
        .text:0x00403603  6870c14000       push 0x0040c170
        .text:0x00403608  8b8dd4e7ffff     mov ecx,dword [ebp - 6188]
        .text:0x0040360e  51               push ecx
        .text:0x0040360f  e8bb0c0000       call 0x004042cf    ;__mbscmp(0x61616161,arg1,0x61616161)
        .text:0x00403614  83c408           add esp,8
        .text:0x00403617  85c0             test eax,eax
        .text:0x00403619  7564             jnz 0x0040367f
        .text:0x0040361b  837d0803         cmp dword [ebp + 8],3
        .text:0x0040361f  7531             jnz 0x00403652
        .text:0x00403621  6800040000       push 1024
        .text:0x00403626  8d95fcfbffff     lea edx,dword [ebp - 1028]
        .text:0x0040362c  52               push edx
        .text:0x0040362d  e83ef8ffff       call 0x00402e70    ;sub_00402e70(local1032)
        .text:0x00403632  83c408           add esp,8
        .text:0x00403635  85c0             test eax,eax
        .text:0x00403637  7408             jz 0x00403641
        .text:0x00403639  83c8ff           or eax,0xffffffff
        .text:0x0040363c  e9ef010000       jmp 0x00403830
        .text:0x00403641  loc_00403641: [1 XREFS]
        .text:0x00403641  8d85fcfbffff     lea eax,dword [ebp - 1028]
        .text:0x00403647  50               push eax
        .text:0x00403648  e8f3f8ffff       call 0x00402f40    ;sub_00402f40(local1032)
        .text:0x0040364d  83c404           add esp,4
        .text:0x00403650  eb28             jmp 0x0040367a
        .text:0x00403652  loc_00403652: [1 XREFS]
        .text:0x00403652  837d0804         cmp dword [ebp + 8],4
        .text:0x00403656  751d             jnz 0x00403675
        .text:0x00403658  8b4d0c           mov ecx,dword [ebp + 12]
        .text:0x0040365b  8b5108           mov edx,dword [ecx + 8]
        .text:0x0040365e  8995f8fbffff     mov dword [ebp - 1032],edx
        .text:0x00403664  8b85f8fbffff     mov eax,dword [ebp - 1032]
        .text:0x0040366a  50               push eax
        .text:0x0040366b  e8d0f8ffff       call 0x00402f40    ;sub_00402f40(0x61616161)
        .text:0x00403670  83c404           add esp,4
        .text:0x00403673  eb05             jmp 0x0040367a
        .text:0x00403675  loc_00403675: [1 XREFS]
        .text:0x00403675  e886d9ffff       call 0x00401000    ;sub_00401000()
        .text:0x0040367a  loc_0040367a: [2 XREFS]
        .text:0x0040367a  e9af010000       jmp 0x0040382e
        .text:0x0040367f  loc_0040367f: [1 XREFS]
        .text:0x0040367f  8b4d0c           mov ecx,dword [ebp + 12]
        .text:0x00403682  8b5104           mov edx,dword [ecx + 4]
        .text:0x00403685  8995d0e7ffff     mov dword [ebp - 6192],edx
        .text:0x0040368b  686cc14000       push 0x0040c16c
        .text:0x00403690  8b85d0e7ffff     mov eax,dword [ebp - 6192]
        .text:0x00403696  50               push eax
        .text:0x00403697  e8330c0000       call 0x004042cf    ;__mbscmp(0x61616161,0x61616161,arg1)
        .text:0x0040369c  83c408           add esp,8
        .text:0x0040369f  85c0             test eax,eax
        .text:0x004036a1  7564             jnz 0x00403707
        .text:0x004036a3  837d0803         cmp dword [ebp + 8],3
        .text:0x004036a7  7531             jnz 0x004036da
        .text:0x004036a9  6800040000       push 1024
        .text:0x004036ae  8d8df8f7ffff     lea ecx,dword [ebp - 2056]
        .text:0x004036b4  51               push ecx
        .text:0x004036b5  e8b6f7ffff       call 0x00402e70    ;sub_00402e70(local2060)
        .text:0x004036ba  83c408           add esp,8
        .text:0x004036bd  85c0             test eax,eax
        .text:0x004036bf  7408             jz 0x004036c9
        .text:0x004036c1  83c8ff           or eax,0xffffffff
        .text:0x004036c4  e967010000       jmp 0x00403830
        .text:0x004036c9  loc_004036c9: [1 XREFS]
        .text:0x004036c9  8d95f8f7ffff     lea edx,dword [ebp - 2056]
        .text:0x004036cf  52               push edx
        .text:0x004036d0  e8ebfbffff       call 0x004032c0    ;sub_004032c0(local2060)
        .text:0x004036d5  83c404           add esp,4
        .text:0x004036d8  eb28             jmp 0x00403702
        .text:0x004036da  loc_004036da: [1 XREFS]
        .text:0x004036da  837d0804         cmp dword [ebp + 8],4
        .text:0x004036de  751d             jnz 0x004036fd
        .text:0x004036e0  8b450c           mov eax,dword [ebp + 12]
        .text:0x004036e3  8b4808           mov ecx,dword [eax + 8]
        .text:0x004036e6  898df4f7ffff     mov dword [ebp - 2060],ecx
        .text:0x004036ec  8b95f4f7ffff     mov edx,dword [ebp - 2060]
        .text:0x004036f2  52               push edx
        .text:0x004036f3  e8c8fbffff       call 0x004032c0    ;sub_004032c0(0x61616161)
        .text:0x004036f8  83c404           add esp,4
        .text:0x004036fb  eb05             jmp 0x00403702
        .text:0x004036fd  loc_004036fd: [1 XREFS]
        .text:0x004036fd  e8fed8ffff       call 0x00401000    ;sub_00401000()
        .text:0x00403702  loc_00403702: [2 XREFS]
        .text:0x00403702  e927010000       jmp 0x0040382e
        .text:0x00403707  loc_00403707: [1 XREFS]
        .text:0x00403707  8b450c           mov eax,dword [ebp + 12]
        .text:0x0040370a  8b4804           mov ecx,dword [eax + 4]
        .text:0x0040370d  898dcce7ffff     mov dword [ebp - 6196],ecx
        .text:0x00403713  6868c14000       push 0x0040c168
        .text:0x00403718  8b95cce7ffff     mov edx,dword [ebp - 6196]
        .text:0x0040371e  52               push edx
        .text:0x0040371f  e8ab0b0000       call 0x004042cf    ;__mbscmp(arg1,0x61616161,0x61616161)
        .text:0x00403724  83c408           add esp,8
        .text:0x00403727  85c0             test eax,eax
        .text:0x00403729  7566             jnz 0x00403791
        .text:0x0040372b  837d0807         cmp dword [ebp + 8],7
        .text:0x0040372f  7556             jnz 0x00403787
        .text:0x00403731  8b450c           mov eax,dword [ebp + 12]
        .text:0x00403734  8b4808           mov ecx,dword [eax + 8]
        .text:0x00403737  898de8f7ffff     mov dword [ebp - 2072],ecx
        .text:0x0040373d  8b550c           mov edx,dword [ebp + 12]
        .text:0x00403740  8b420c           mov eax,dword [edx + 12]
        .text:0x00403743  8985ecf7ffff     mov dword [ebp - 2068],eax
        .text:0x00403749  8b4d0c           mov ecx,dword [ebp + 12]
        .text:0x0040374c  8b5110           mov edx,dword [ecx + 16]
        .text:0x0040374f  8995e4f7ffff     mov dword [ebp - 2076],edx
        .text:0x00403755  8b450c           mov eax,dword [ebp + 12]
        .text:0x00403758  8b4814           mov ecx,dword [eax + 20]
        .text:0x0040375b  898df0f7ffff     mov dword [ebp - 2064],ecx
        .text:0x00403761  8b95f0f7ffff     mov edx,dword [ebp - 2064]
        .text:0x00403767  52               push edx
        .text:0x00403768  8b85e4f7ffff     mov eax,dword [ebp - 2076]
        .text:0x0040376e  50               push eax
        .text:0x0040376f  8b8decf7ffff     mov ecx,dword [ebp - 2068]
        .text:0x00403775  51               push ecx
        .text:0x00403776  8b95e8f7ffff     mov edx,dword [ebp - 2072]
        .text:0x0040377c  52               push edx
        .text:0x0040377d  e84edaffff       call 0x004011d0    ;sub_004011d0(0x61616161,0x61616161,0x61616161,0x61616161)
        .text:0x00403782  83c410           add esp,16
        .text:0x00403785  eb05             jmp 0x0040378c
        .text:0x00403787  loc_00403787: [1 XREFS]
        .text:0x00403787  e874d8ffff       call 0x00401000    ;sub_00401000()
        .text:0x0040378c  loc_0040378c: [1 XREFS]
        .text:0x0040378c  e99d000000       jmp 0x0040382e
        .text:0x00403791  loc_00403791: [1 XREFS]
        .text:0x00403791  8b450c           mov eax,dword [ebp + 12]
        .text:0x00403794  8b4804           mov ecx,dword [eax + 4]
        .text:0x00403797  898dc8e7ffff     mov dword [ebp - 6200],ecx
        .text:0x0040379d  6864c14000       push 0x0040c164
        .text:0x004037a2  8b95c8e7ffff     mov edx,dword [ebp - 6200]
        .text:0x004037a8  52               push edx
        .text:0x004037a9  e8210b0000       call 0x004042cf    ;__mbscmp(arg1,0x61616161,0x61616161)
        .text:0x004037ae  83c408           add esp,8
        .text:0x004037b1  85c0             test eax,eax
        .text:0x004037b3  7574             jnz 0x00403829
        .text:0x004037b5  837d0803         cmp dword [ebp + 8],3
        .text:0x004037b9  7567             jnz 0x00403822
        .text:0x004037bb  6800040000       push 1024
        .text:0x004037c0  8d85e4f3ffff     lea eax,dword [ebp - 3100]
        .text:0x004037c6  50               push eax
        .text:0x004037c7  6800040000       push 1024
        .text:0x004037cc  8d8de4e7ffff     lea ecx,dword [ebp - 6172]
        .text:0x004037d2  51               push ecx
        .text:0x004037d3  6800040000       push 1024
        .text:0x004037d8  8d95e4efffff     lea edx,dword [ebp - 4124]
        .text:0x004037de  52               push edx
        .text:0x004037df  6800040000       push 1024
        .text:0x004037e4  8d85e4ebffff     lea eax,dword [ebp - 5148]
        .text:0x004037ea  50               push eax
        .text:0x004037eb  e8c0dcffff       call 0x004014b0    ;sub_004014b0(local5152,1024,local4128,1024,local6176,1024,local3104)
        .text:0x004037f0  83c420           add esp,32
        .text:0x004037f3  85c0             test eax,eax
        .text:0x004037f5  7529             jnz 0x00403820
        .text:0x004037f7  8d8de4f3ffff     lea ecx,dword [ebp - 3100]
        .text:0x004037fd  51               push ecx
        .text:0x004037fe  8d95e4e7ffff     lea edx,dword [ebp - 6172]
        .text:0x00403804  52               push edx
        .text:0x00403805  8d85e4efffff     lea eax,dword [ebp - 4124]
        .text:0x0040380b  50               push eax
        .text:0x0040380c  8d8de4ebffff     lea ecx,dword [ebp - 5148]
        .text:0x00403812  51               push ecx
        .text:0x00403813  684cc14000       push 0x0040c14c
        .text:0x00403818  e81c010000       call 0x00403939    ;sub_00403939(0x0040c14c,local5152)
        .text:0x0040381d  83c414           add esp,20
        .text:0x00403820  loc_00403820: [1 XREFS]
        .text:0x00403820  eb05             jmp 0x00403827
        .text:0x00403822  loc_00403822: [1 XREFS]
        .text:0x00403822  e8d9d7ffff       call 0x00401000    ;sub_00401000()
        .text:0x00403827  loc_00403827: [1 XREFS]
        .text:0x00403827  eb05             jmp 0x0040382e
        .text:0x00403829  loc_00403829: [1 XREFS]
        .text:0x00403829  e8d2d7ffff       call 0x00401000    ;sub_00401000()
        .text:0x0040382e  loc_0040382e: [5 XREFS]
        .text:0x0040382e  33c0             xor eax,eax
        .text:0x00403830  loc_00403830: [2 XREFS]
        .text:0x00403830  5f               pop edi
        .text:0x00403831  5e               pop esi
        .text:0x00403832  5b               pop ebx
        .text:0x00403833  8be5             mov esp,ebp
        .text:0x00403835  5d               pop ebp
        .text:0x00403836  c3               ret 
        */
        $c45 = { 55 8B EC B8 38 18 00 00 E8 ?? ?? ?? ?? 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 64 A1 ?? ?? ?? ?? 8A 58 ?? 88 9D ?? ?? ?? ?? 0F BE 85 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 8B 40 ?? 3E 8B 40 ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? 3E 8B 40 ?? 83 E8 70 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? E8 ?? ?? ?? ?? 83 7D ?? 01 75 ?? E8 ?? ?? ?? ?? 85 C0 74 ?? E8 ?? ?? ?? ?? EB ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 4D ?? 8B 55 ?? 8B 44 8A ?? 89 45 ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 04 85 C0 75 ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B 42 ?? 89 85 ?? ?? ?? ?? 68 70 C1 40 00 8B 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 08 85 C0 75 ?? 83 7D ?? 03 75 ?? 68 00 04 00 00 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? 83 C8 FF E9 ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 EB ?? 83 7D ?? 04 75 ?? 8B 4D ?? 8B 51 ?? 89 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 EB ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 4D ?? 8B 51 ?? 89 95 ?? ?? ?? ?? 68 6C C1 40 00 8B 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 08 85 C0 75 ?? 83 7D ?? 03 75 ?? 68 00 04 00 00 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? 83 C8 FF E9 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 04 EB ?? 83 7D ?? 04 75 ?? 8B 45 ?? 8B 48 ?? 89 8D ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 04 EB ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 45 ?? 8B 48 ?? 89 8D ?? ?? ?? ?? 68 68 C1 40 00 8B 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 08 85 C0 75 ?? 83 7D ?? 07 75 ?? 8B 45 ?? 8B 48 ?? 89 8D ?? ?? ?? ?? 8B 55 ?? 8B 42 ?? 89 85 ?? ?? ?? ?? 8B 4D ?? 8B 51 ?? 89 95 ?? ?? ?? ?? 8B 45 ?? 8B 48 ?? 89 8D ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 8B 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? ?? 51 8B 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 10 EB ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 45 ?? 8B 48 ?? 89 8D ?? ?? ?? ?? 68 64 C1 40 00 8B 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 08 85 C0 75 ?? 83 7D ?? 03 75 ?? 68 00 04 00 00 8D 85 ?? ?? ?? ?? 50 68 00 04 00 00 8D 8D ?? ?? ?? ?? 51 68 00 04 00 00 8D 95 ?? ?? ?? ?? 52 68 00 04 00 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 20 85 C0 75 ?? 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? 51 68 4C C1 40 00 E8 ?? ?? ?? ?? 83 C4 14 EB ?? E8 ?? ?? ?? ?? EB ?? E8 ?? ?? ?? ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
    condition:
        all of them
}

rule super_rule_b94af
{
    meta:
        author = "CAPA Matches"
        date_created = "EXPECTED_DATE"
        date_modified = "EXPECTED_DATE"
        description = ""
        md5 = "b94af4a4d4af6eac81fc135abda1c40c"
    strings:
        /*
Basic Block at 0x00402410@b94af4a4d4af6eac81fc135abda1c40c with 1 features:
          - create process on Windows
        .text:0x00402410  
        .text:0x00402410  FUNC: int cdecl sub_00402410( ) [14 XREFS] 
        .text:0x00402410  
        .text:0x00402410  Stack Variables: (offset from initial top of stack)
        .text:0x00402410          -264: int local264
        .text:0x00402410          -524: int local524
        .text:0x00402410  
        .text:0x00402410  55               push ebp
        .text:0x00402411  8bec             mov ebp,esp
        .text:0x00402413  81ec08020000     sub esp,520
        .text:0x00402419  53               push ebx
        .text:0x0040241a  56               push esi
        .text:0x0040241b  57               push edi
        .text:0x0040241c  6804010000       push 260
        .text:0x00402421  8d85f8fdffff     lea eax,dword [ebp - 520]
        .text:0x00402427  50               push eax
        .text:0x00402428  6a00             push 0
        .text:0x0040242a  ff1538b04000     call dword [0x0040b038]    ;kernel32.GetModuleFileNameA(0,local524,260)
        .text:0x00402430  6804010000       push 260
        .text:0x00402435  8d8df8fdffff     lea ecx,dword [ebp - 520]
        .text:0x0040243b  51               push ecx
        .text:0x0040243c  8d95f8fdffff     lea edx,dword [ebp - 520]
        .text:0x00402442  52               push edx
        .text:0x00402443  ff153cb04000     call dword [0x0040b03c]    ;kernel32.GetShortPathNameA(local524,local524,260)
        .text:0x00402449  bfdcc04000       mov edi,0x0040c0dc
        .text:0x0040244e  8d95fcfeffff     lea edx,dword [ebp - 260]
        .text:0x00402454  83c9ff           or ecx,0xffffffff
        .text:0x00402457  33c0             xor eax,eax
        .text:0x00402459  f2ae             repnz: scasb 
        .text:0x0040245b  f7d1             not ecx
        .text:0x0040245d  2bf9             sub edi,ecx
        .text:0x0040245f  8bf7             mov esi,edi
        .text:0x00402461  8bc1             mov eax,ecx
        .text:0x00402463  8bfa             mov edi,edx
        .text:0x00402465  c1e902           shr ecx,2
        .text:0x00402468  f3a5             rep: movsd 
        .text:0x0040246a  8bc8             mov ecx,eax
        .text:0x0040246c  83e103           and ecx,3
        .text:0x0040246f  f3a4             rep: movsb 
        .text:0x00402471  8dbdf8fdffff     lea edi,dword [ebp - 520]
        .text:0x00402477  8d95fcfeffff     lea edx,dword [ebp - 260]
        .text:0x0040247d  83c9ff           or ecx,0xffffffff
        .text:0x00402480  33c0             xor eax,eax
        .text:0x00402482  f2ae             repnz: scasb 
        .text:0x00402484  f7d1             not ecx
        .text:0x00402486  2bf9             sub edi,ecx
        .text:0x00402488  8bf7             mov esi,edi
        .text:0x0040248a  8bd9             mov ebx,ecx
        .text:0x0040248c  8bfa             mov edi,edx
        .text:0x0040248e  83c9ff           or ecx,0xffffffff
        .text:0x00402491  33c0             xor eax,eax
        .text:0x00402493  f2ae             repnz: scasb 
        .text:0x00402495  83c7ff           add edi,0xffffffff
        .text:0x00402498  8bcb             mov ecx,ebx
        .text:0x0040249a  c1e902           shr ecx,2
        .text:0x0040249d  f3a5             rep: movsd 
        .text:0x0040249f  8bcb             mov ecx,ebx
        .text:0x004024a1  83e103           and ecx,3
        .text:0x004024a4  f3a4             rep: movsb 
        .text:0x004024a6  bfd4c04000       mov edi,0x0040c0d4
        .text:0x004024ab  8d95fcfeffff     lea edx,dword [ebp - 260]
        .text:0x004024b1  83c9ff           or ecx,0xffffffff
        .text:0x004024b4  33c0             xor eax,eax
        .text:0x004024b6  f2ae             repnz: scasb 
        .text:0x004024b8  f7d1             not ecx
        .text:0x004024ba  2bf9             sub edi,ecx
        .text:0x004024bc  8bf7             mov esi,edi
        .text:0x004024be  8bd9             mov ebx,ecx
        .text:0x004024c0  8bfa             mov edi,edx
        .text:0x004024c2  83c9ff           or ecx,0xffffffff
        .text:0x004024c5  33c0             xor eax,eax
        .text:0x004024c7  f2ae             repnz: scasb 
        .text:0x004024c9  83c7ff           add edi,0xffffffff
        .text:0x004024cc  8bcb             mov ecx,ebx
        .text:0x004024ce  c1e902           shr ecx,2
        .text:0x004024d1  f3a5             rep: movsd 
        .text:0x004024d3  8bcb             mov ecx,ebx
        .text:0x004024d5  83e103           and ecx,3
        .text:0x004024d8  f3a4             rep: movsb 
        .text:0x004024da  6a00             push 0
        .text:0x004024dc  6a00             push 0
        .text:0x004024de  8d85fcfeffff     lea eax,dword [ebp - 260]
        .text:0x004024e4  50               push eax
        .text:0x004024e5  68ccc04000       push 0x0040c0cc
        .text:0x004024ea  6a00             push 0
        .text:0x004024ec  6a00             push 0
        .text:0x004024ee  ff1538b14000     call dword [0x0040b138]    ;shell32.ShellExecuteA(0,0,0x0040c0cc,local264,0,0)
        .text:0x004024f4  6a00             push 0
        .text:0x004024f6  e8ae080000       call 0x00402da9    ;_exit(0)
        .text:0x004024fb  5f               pop edi
        .text:0x004024fc  5e               pop esi
        .text:0x004024fd  5b               pop ebx
        .text:0x004024fe  8be5             mov esp,ebp
        .text:0x00402500  5d               pop ebp
        .text:0x00402501  c3               ret 
        */
        $c46 = { 55 8B EC 81 EC 08 02 00 00 53 56 57 68 04 01 00 00 8D 85 ?? ?? ?? ?? 50 6A 00 FF 15 ?? ?? ?? ?? 68 04 01 00 00 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? BF DC C0 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8D BD ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 BF D4 C0 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 6A 00 6A 00 8D 85 ?? ?? ?? ?? 50 68 CC C0 40 00 6A 00 6A 00 FF 15 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x004014e0@b94af4a4d4af6eac81fc135abda1c40c with 1 features:
          - timestomp file
        .text:0x004014e0  
        .text:0x004014e0  FUNC: int cdecl sub_004014e0( int arg0, int arg1, ) [2 XREFS] 
        .text:0x004014e0  
        .text:0x004014e0  Stack Variables: (offset from initial top of stack)
        .text:0x004014e0             8: int arg1
        .text:0x004014e0             4: int arg0
        .text:0x004014e0           -12: int local12
        .text:0x004014e0           -20: int local20
        .text:0x004014e0           -28: int local28
        .text:0x004014e0           -32: int local32
        .text:0x004014e0  
        .text:0x004014e0  55               push ebp
        .text:0x004014e1  8bec             mov ebp,esp
        .text:0x004014e3  83ec1c           sub esp,28
        .text:0x004014e6  6a00             push 0
        .text:0x004014e8  6880000000       push 128
        .text:0x004014ed  6a03             push 3
        .text:0x004014ef  6a00             push 0
        .text:0x004014f1  6a01             push 1
        .text:0x004014f3  6800000080       push 0x80000000
        .text:0x004014f8  8b450c           mov eax,dword [ebp + 12]
        .text:0x004014fb  50               push eax
        .text:0x004014fc  ff1554b04000     call dword [0x0040b054]    ;kernel32.CreateFileA(arg1,0x80000000,1,0,3,128,0)
        .text:0x00401502  8945e4           mov dword [ebp - 28],eax
        .text:0x00401505  837de400         cmp dword [ebp - 28],0
        .text:0x00401509  750a             jnz 0x00401515
        .text:0x0040150b  b801000000       mov eax,1
        .text:0x00401510  e98b000000       jmp 0x004015a0
        .text:0x00401515  loc_00401515: [1 XREFS]
        .text:0x00401515  8d4df0           lea ecx,dword [ebp - 16]
        .text:0x00401518  51               push ecx
        .text:0x00401519  8d55e8           lea edx,dword [ebp - 24]
        .text:0x0040151c  52               push edx
        .text:0x0040151d  8d45f8           lea eax,dword [ebp - 8]
        .text:0x00401520  50               push eax
        .text:0x00401521  8b4de4           mov ecx,dword [ebp - 28]
        .text:0x00401524  51               push ecx
        .text:0x00401525  ff1558b04000     call dword [0x0040b058]    ;kernel32.GetFileTime(kernel32.CreateFileA(arg1,0x80000000,1,0,3,128,0),local12,local28,local20)
        .text:0x0040152b  85c0             test eax,eax
        .text:0x0040152d  7511             jnz 0x00401540
        .text:0x0040152f  8b55e4           mov edx,dword [ebp - 28]
        .text:0x00401532  52               push edx
        .text:0x00401533  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(<0x004014fc>)
        .text:0x00401539  b801000000       mov eax,1
        .text:0x0040153e  eb60             jmp 0x004015a0
        .text:0x00401540  loc_00401540: [1 XREFS]
        .text:0x00401540  8b45e4           mov eax,dword [ebp - 28]
        .text:0x00401543  50               push eax
        .text:0x00401544  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(<0x004014fc>)
        .text:0x0040154a  6a00             push 0
        .text:0x0040154c  6880000000       push 128
        .text:0x00401551  6a03             push 3
        .text:0x00401553  6a00             push 0
        .text:0x00401555  6a02             push 2
        .text:0x00401557  6800000040       push 0x40000000
        .text:0x0040155c  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x0040155f  51               push ecx
        .text:0x00401560  ff1554b04000     call dword [0x0040b054]    ;kernel32.CreateFileA(arg0,0x40000000,2,0,3,128,0)
        .text:0x00401566  8945e4           mov dword [ebp - 28],eax
        .text:0x00401569  8d55f0           lea edx,dword [ebp - 16]
        .text:0x0040156c  52               push edx
        .text:0x0040156d  8d45e8           lea eax,dword [ebp - 24]
        .text:0x00401570  50               push eax
        .text:0x00401571  8d4df8           lea ecx,dword [ebp - 8]
        .text:0x00401574  51               push ecx
        .text:0x00401575  8b55e4           mov edx,dword [ebp - 28]
        .text:0x00401578  52               push edx
        .text:0x00401579  ff155cb04000     call dword [0x0040b05c]    ;kernel32.SetFileTime(kernel32.CreateFileA(arg0,0x40000000,2,0,3,128,0),local12,local28,local20)
        .text:0x0040157f  85c0             test eax,eax
        .text:0x00401581  7511             jnz 0x00401594
        .text:0x00401583  8b45e4           mov eax,dword [ebp - 28]
        .text:0x00401586  50               push eax
        .text:0x00401587  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(<0x00401560>)
        .text:0x0040158d  b801000000       mov eax,1
        .text:0x00401592  eb0c             jmp 0x004015a0
        .text:0x00401594  loc_00401594: [1 XREFS]
        .text:0x00401594  8b4de4           mov ecx,dword [ebp - 28]
        .text:0x00401597  51               push ecx
        .text:0x00401598  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(<0x00401560>)
        .text:0x0040159e  33c0             xor eax,eax
        .text:0x004015a0  loc_004015a0: [3 XREFS]
        .text:0x004015a0  8be5             mov esp,ebp
        .text:0x004015a2  5d               pop ebp
        .text:0x004015a3  c3               ret 
        */
        $c47 = { 55 8B EC 83 EC 1C 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 00 75 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8D 4D ?? 51 8D 55 ?? 52 8D 45 ?? 50 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 6A 00 68 80 00 00 00 6A 03 6A 00 6A 02 68 00 00 00 40 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 45 ?? 8D 55 ?? 52 8D 45 ?? 50 8D 4D ?? 51 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 33 C0 8B E5 5D C3 }
        /*
function at 0x004019e0@b94af4a4d4af6eac81fc135abda1c40c with 4 features:
          - receive and write data from server to client
          - receive data
          - receive data on socket
          - write file on Windows
        .text:0x004019e0  
        .text:0x004019e0  FUNC: int cdecl sub_004019e0( int arg0, int arg1, int arg2, ) [2 XREFS] 
        .text:0x004019e0  
        .text:0x004019e0  Stack Variables: (offset from initial top of stack)
        .text:0x004019e0            12: int arg2
        .text:0x004019e0             8: int arg1
        .text:0x004019e0             4: int arg0
        .text:0x004019e0            -8: int local8
        .text:0x004019e0           -12: int local12
        .text:0x004019e0          -524: int local524
        .text:0x004019e0          -528: int local528
        .text:0x004019e0  
        .text:0x004019e0  55               push ebp
        .text:0x004019e1  8bec             mov ebp,esp
        .text:0x004019e3  81ec0c020000     sub esp,524
        .text:0x004019e9  c745f800000000   mov dword [ebp - 8],0
        .text:0x004019f0  8b450c           mov eax,dword [ebp + 12]
        .text:0x004019f3  50               push eax
        .text:0x004019f4  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x004019f7  51               push ecx
        .text:0x004019f8  8d55f8           lea edx,dword [ebp - 8]
        .text:0x004019fb  52               push edx
        .text:0x004019fc  e83ffcffff       call 0x00401640    ;sub_00401640(local12,arg0,arg1)
        .text:0x00401a01  83c40c           add esp,12
        .text:0x00401a04  85c0             test eax,eax
        .text:0x00401a06  740a             jz 0x00401a12
        .text:0x00401a08  b801000000       mov eax,1
        .text:0x00401a0d  e9d4000000       jmp 0x00401ae6
        .text:0x00401a12  loc_00401a12: [1 XREFS]
        .text:0x00401a12  6a00             push 0
        .text:0x00401a14  6880000000       push 128
        .text:0x00401a19  6a02             push 2
        .text:0x00401a1b  6a00             push 0
        .text:0x00401a1d  6a02             push 2
        .text:0x00401a1f  6800000040       push 0x40000000
        .text:0x00401a24  8b4510           mov eax,dword [ebp + 16]
        .text:0x00401a27  50               push eax
        .text:0x00401a28  ff1554b04000     call dword [0x0040b054]    ;kernel32.CreateFileA(arg2,0x40000000,2,0,2,128,0)
        .text:0x00401a2e  8985f4fdffff     mov dword [ebp - 524],eax
        .text:0x00401a34  83bdf4fdffffff   cmp dword [ebp - 524],0xffffffff
        .text:0x00401a3b  7516             jnz 0x00401a53
        .text:0x00401a3d  8d4df8           lea ecx,dword [ebp - 8]
        .text:0x00401a40  51               push ecx
        .text:0x00401a41  e8fafcffff       call 0x00401740    ;sub_00401740(local12)
        .text:0x00401a46  83c404           add esp,4
        .text:0x00401a49  b801000000       mov eax,1
        .text:0x00401a4e  e993000000       jmp 0x00401ae6
        .text:0x00401a53  loc_00401a53: [2 XREFS]
        .text:0x00401a53  6a00             push 0
        .text:0x00401a55  6800020000       push 512
        .text:0x00401a5a  8d95f8fdffff     lea edx,dword [ebp - 520]
        .text:0x00401a60  52               push edx
        .text:0x00401a61  8b45f8           mov eax,dword [ebp - 8]
        .text:0x00401a64  50               push eax
        .text:0x00401a65  ff1560b14000     call dword [0x0040b160]    ;ws2_32.recv(0,local524,512)
        .text:0x00401a6b  8945fc           mov dword [ebp - 4],eax
        .text:0x00401a6e  6a00             push 0
        .text:0x00401a70  6a00             push 0
        .text:0x00401a72  8b4dfc           mov ecx,dword [ebp - 4]
        .text:0x00401a75  51               push ecx
        .text:0x00401a76  8d95f8fdffff     lea edx,dword [ebp - 520]
        .text:0x00401a7c  52               push edx
        .text:0x00401a7d  8b85f4fdffff     mov eax,dword [ebp - 524]
        .text:0x00401a83  50               push eax
        .text:0x00401a84  ff1544b04000     call dword [0x0040b044]    ;kernel32.WriteFile(kernel32.CreateFileA(arg2,0x40000000,2,0,2,128,0),local524,ws2_32.recv(0,local524,512),0,0)
        .text:0x00401a8a  85c0             test eax,eax
        .text:0x00401a8c  7520             jnz 0x00401aae
        .text:0x00401a8e  8d4df8           lea ecx,dword [ebp - 8]
        .text:0x00401a91  51               push ecx
        .text:0x00401a92  e8a9fcffff       call 0x00401740    ;sub_00401740(local12)
        .text:0x00401a97  83c404           add esp,4
        .text:0x00401a9a  8b95f4fdffff     mov edx,dword [ebp - 524]
        .text:0x00401aa0  52               push edx
        .text:0x00401aa1  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(<0x00401a28>)
        .text:0x00401aa7  b801000000       mov eax,1
        .text:0x00401aac  eb38             jmp 0x00401ae6
        .text:0x00401aae  loc_00401aae: [1 XREFS]
        .text:0x00401aae  837dfc00         cmp dword [ebp - 4],0
        .text:0x00401ab2  7f9f             jg 0x00401a53
        .text:0x00401ab4  8b85f4fdffff     mov eax,dword [ebp - 524]
        .text:0x00401aba  50               push eax
        .text:0x00401abb  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(<0x00401a28>)
        .text:0x00401ac1  8d4df8           lea ecx,dword [ebp - 8]
        .text:0x00401ac4  51               push ecx
        .text:0x00401ac5  e876fcffff       call 0x00401740    ;sub_00401740(local12)
        .text:0x00401aca  83c404           add esp,4
        .text:0x00401acd  85c0             test eax,eax
        .text:0x00401acf  7407             jz 0x00401ad8
        .text:0x00401ad1  b801000000       mov eax,1
        .text:0x00401ad6  eb0e             jmp 0x00401ae6
        .text:0x00401ad8  loc_00401ad8: [1 XREFS]
        .text:0x00401ad8  8b5510           mov edx,dword [ebp + 16]
        .text:0x00401adb  52               push edx
        .text:0x00401adc  e8cffaffff       call 0x004015b0    ;sub_004015b0(local12,arg2)
        .text:0x00401ae1  83c404           add esp,4
        .text:0x00401ae4  33c0             xor eax,eax
        .text:0x00401ae6  loc_00401ae6: [4 XREFS]
        .text:0x00401ae6  8be5             mov esp,ebp
        .text:0x00401ae8  5d               pop ebp
        .text:0x00401ae9  c3               ret 
        */
        $c48 = { 55 8B EC 81 EC 0C 02 00 00 C7 45 ?? 00 00 00 00 8B 45 ?? 50 8B 4D ?? 51 8D 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 6A 00 68 80 00 00 00 6A 02 6A 00 6A 02 68 00 00 00 40 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? FF 75 ?? 8D 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 04 B8 01 00 00 00 E9 ?? ?? ?? ?? 6A 00 68 00 02 00 00 8D 95 ?? ?? ?? ?? 52 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 45 ?? 6A 00 6A 00 8B 4D ?? 51 8D 95 ?? ?? ?? ?? 52 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8D 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 04 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 83 7D ?? 00 7F ?? 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8D 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 ?? B8 01 00 00 00 EB ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 04 33 C0 8B E5 5D C3 }
        /*
function at 0x00401af0@b94af4a4d4af6eac81fc135abda1c40c with 5 features:
          - receive data
          - receive data on socket
          - send HTTP request
          - send data
          - send data on socket
        .text:0x00401af0  
        .text:0x00401af0  FUNC: int cdecl sub_00401af0( int arg0, int arg1, int arg2, int arg3, int arg4, ) [2 XREFS] 
        .text:0x00401af0  
        .text:0x00401af0  Stack Variables: (offset from initial top of stack)
        .text:0x00401af0            20: int arg4
        .text:0x00401af0            16: int arg3
        .text:0x00401af0            12: int arg2
        .text:0x00401af0             8: int arg1
        .text:0x00401af0             4: int arg0
        .text:0x00401af0            -8: int local8
        .text:0x00401af0          -1032: int local1032
        .text:0x00401af0          -1036: int local1036
        .text:0x00401af0          -1040: int local1040
        .text:0x00401af0          -1552: int local1552
        .text:0x00401af0          -1556: int local1556
        .text:0x00401af0  
        .text:0x00401af0  55               push ebp
        .text:0x00401af1  8bec             mov ebp,esp
        .text:0x00401af3  81ec10060000     sub esp,1552
        .text:0x00401af9  53               push ebx
        .text:0x00401afa  56               push esi
        .text:0x00401afb  57               push edi
        .text:0x00401afc  c785f4fbffff0000 mov dword [ebp - 1036],0
        .text:0x00401b06  c785f8fbffff0000 mov dword [ebp - 1032],0
        .text:0x00401b10  8b450c           mov eax,dword [ebp + 12]
        .text:0x00401b13  50               push eax
        .text:0x00401b14  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00401b17  51               push ecx
        .text:0x00401b18  8d95f4fbffff     lea edx,dword [ebp - 1036]
        .text:0x00401b1e  52               push edx
        .text:0x00401b1f  e81cfbffff       call 0x00401640    ;sub_00401640(local1040,arg0,arg1)
        .text:0x00401b24  83c40c           add esp,12
        .text:0x00401b27  85c0             test eax,eax
        .text:0x00401b29  740a             jz 0x00401b35
        .text:0x00401b2b  b801000000       mov eax,1
        .text:0x00401b30  e9c7010000       jmp 0x00401cfc
        .text:0x00401b35  loc_00401b35: [1 XREFS]
        .text:0x00401b35  bf80c04000       mov edi,0x0040c080
        .text:0x00401b3a  8d95fcfbffff     lea edx,dword [ebp - 1028]
        .text:0x00401b40  83c9ff           or ecx,0xffffffff
        .text:0x00401b43  33c0             xor eax,eax
        .text:0x00401b45  f2ae             repnz: scasb 
        .text:0x00401b47  f7d1             not ecx
        .text:0x00401b49  2bf9             sub edi,ecx
        .text:0x00401b4b  8bf7             mov esi,edi
        .text:0x00401b4d  8bc1             mov eax,ecx
        .text:0x00401b4f  8bfa             mov edi,edx
        .text:0x00401b51  c1e902           shr ecx,2
        .text:0x00401b54  f3a5             rep: movsd 
        .text:0x00401b56  8bc8             mov ecx,eax
        .text:0x00401b58  83e103           and ecx,3
        .text:0x00401b5b  f3a4             rep: movsb 
        .text:0x00401b5d  8b7d10           mov edi,dword [ebp + 16]
        .text:0x00401b60  8d95fcfbffff     lea edx,dword [ebp - 1028]
        .text:0x00401b66  83c9ff           or ecx,0xffffffff
        .text:0x00401b69  33c0             xor eax,eax
        .text:0x00401b6b  f2ae             repnz: scasb 
        .text:0x00401b6d  f7d1             not ecx
        .text:0x00401b6f  2bf9             sub edi,ecx
        .text:0x00401b71  8bf7             mov esi,edi
        .text:0x00401b73  8bd9             mov ebx,ecx
        .text:0x00401b75  8bfa             mov edi,edx
        .text:0x00401b77  83c9ff           or ecx,0xffffffff
        .text:0x00401b7a  33c0             xor eax,eax
        .text:0x00401b7c  f2ae             repnz: scasb 
        .text:0x00401b7e  83c7ff           add edi,0xffffffff
        .text:0x00401b81  8bcb             mov ecx,ebx
        .text:0x00401b83  c1e902           shr ecx,2
        .text:0x00401b86  f3a5             rep: movsd 
        .text:0x00401b88  8bcb             mov ecx,ebx
        .text:0x00401b8a  83e103           and ecx,3
        .text:0x00401b8d  f3a4             rep: movsb 
        .text:0x00401b8f  bf70c04000       mov edi,0x0040c070
        .text:0x00401b94  8d95fcfbffff     lea edx,dword [ebp - 1028]
        .text:0x00401b9a  83c9ff           or ecx,0xffffffff
        .text:0x00401b9d  33c0             xor eax,eax
        .text:0x00401b9f  f2ae             repnz: scasb 
        .text:0x00401ba1  f7d1             not ecx
        .text:0x00401ba3  2bf9             sub edi,ecx
        .text:0x00401ba5  8bf7             mov esi,edi
        .text:0x00401ba7  8bd9             mov ebx,ecx
        .text:0x00401ba9  8bfa             mov edi,edx
        .text:0x00401bab  83c9ff           or ecx,0xffffffff
        .text:0x00401bae  33c0             xor eax,eax
        .text:0x00401bb0  f2ae             repnz: scasb 
        .text:0x00401bb2  83c7ff           add edi,0xffffffff
        .text:0x00401bb5  8bcb             mov ecx,ebx
        .text:0x00401bb7  c1e902           shr ecx,2
        .text:0x00401bba  f3a5             rep: movsd 
        .text:0x00401bbc  8bcb             mov ecx,ebx
        .text:0x00401bbe  83e103           and ecx,3
        .text:0x00401bc1  f3a4             rep: movsb 
        .text:0x00401bc3  6a00             push 0
        .text:0x00401bc5  8dbdfcfbffff     lea edi,dword [ebp - 1028]
        .text:0x00401bcb  83c9ff           or ecx,0xffffffff
        .text:0x00401bce  33c0             xor eax,eax
        .text:0x00401bd0  f2ae             repnz: scasb 
        .text:0x00401bd2  f7d1             not ecx
        .text:0x00401bd4  83c1ff           add ecx,0xffffffff
        .text:0x00401bd7  51               push ecx
        .text:0x00401bd8  8d85fcfbffff     lea eax,dword [ebp - 1028]
        .text:0x00401bde  50               push eax
        .text:0x00401bdf  8b8df4fbffff     mov ecx,dword [ebp - 1036]
        .text:0x00401be5  51               push ecx
        .text:0x00401be6  ff154cb14000     call dword [0x0040b14c]    ;ws2_32.send(0,local1032,0xffffffff,0)
        .text:0x00401bec  8985f0f9ffff     mov dword [ebp - 1552],eax
        .text:0x00401bf2  83bdf0f9ffffff   cmp dword [ebp - 1552],0xffffffff
        .text:0x00401bf9  751d             jnz 0x00401c18
        .text:0x00401bfb  8b95f4fbffff     mov edx,dword [ebp - 1036]
        .text:0x00401c01  52               push edx
        .text:0x00401c02  ff155cb14000     call dword [0x0040b15c]    ;ws2_32.closesocket(0)
        .text:0x00401c08  ff1564b14000     call dword [0x0040b164]    ;ws2_32.WSACleanup()
        .text:0x00401c0e  b801000000       mov eax,1
        .text:0x00401c13  e9e4000000       jmp 0x00401cfc
        .text:0x00401c18  loc_00401c18: [2 XREFS]
        .text:0x00401c18  6a00             push 0
        .text:0x00401c1a  6800020000       push 512
        .text:0x00401c1f  8d85f4f9ffff     lea eax,dword [ebp - 1548]
        .text:0x00401c25  50               push eax
        .text:0x00401c26  8b8df4fbffff     mov ecx,dword [ebp - 1036]
        .text:0x00401c2c  51               push ecx
        .text:0x00401c2d  ff1560b14000     call dword [0x0040b160]    ;ws2_32.recv(0,local1552,512)
        .text:0x00401c33  8945fc           mov dword [ebp - 4],eax
        .text:0x00401c36  837dfc00         cmp dword [ebp - 4],0
        .text:0x00401c3a  7e71             jle 0x00401cad
        .text:0x00401c3c  8b95f8fbffff     mov edx,dword [ebp - 1032]
        .text:0x00401c42  0355fc           add edx,dword [ebp - 4]
        .text:0x00401c45  8b4518           mov eax,dword [ebp + 24]
        .text:0x00401c48  3b10             cmp edx,dword [eax]
        .text:0x00401c4a  7619             jbe 0x00401c65
        .text:0x00401c4c  8d8df4fbffff     lea ecx,dword [ebp - 1036]
        .text:0x00401c52  51               push ecx
        .text:0x00401c53  e8e8faffff       call 0x00401740    ;sub_00401740(local1040)
        .text:0x00401c58  83c404           add esp,4
        .text:0x00401c5b  b801000000       mov eax,1
        .text:0x00401c60  e997000000       jmp 0x00401cfc
        .text:0x00401c65  loc_00401c65: [1 XREFS]
        .text:0x00401c65  8b4dfc           mov ecx,dword [ebp - 4]
        .text:0x00401c68  8db5f4f9ffff     lea esi,dword [ebp - 1548]
        .text:0x00401c6e  8b7d14           mov edi,dword [ebp + 20]
        .text:0x00401c71  03bdf8fbffff     add edi,dword [ebp - 1032]
        .text:0x00401c77  8bd1             mov edx,ecx
        .text:0x00401c79  c1e902           shr ecx,2
        .text:0x00401c7c  f3a5             rep: movsd 
        .text:0x00401c7e  8bca             mov ecx,edx
        .text:0x00401c80  83e103           and ecx,3
        .text:0x00401c83  f3a4             rep: movsb 
        .text:0x00401c85  8b85f8fbffff     mov eax,dword [ebp - 1032]
        .text:0x00401c8b  0345fc           add eax,dword [ebp - 4]
        .text:0x00401c8e  8985f8fbffff     mov dword [ebp - 1032],eax
        .text:0x00401c94  6868c04000       push 0x0040c068
        .text:0x00401c99  8b4d14           mov ecx,dword [ebp + 20]
        .text:0x00401c9c  51               push ecx
        .text:0x00401c9d  e8be130000       call 0x00403060    ;_strstr(arg3,0x0040c068)
        .text:0x00401ca2  83c408           add esp,8
        .text:0x00401ca5  85c0             test eax,eax
        .text:0x00401ca7  7402             jz 0x00401cab
        .text:0x00401ca9  eb2a             jmp 0x00401cd5
        .text:0x00401cab  loc_00401cab: [1 XREFS]
        .text:0x00401cab  eb1e             jmp 0x00401ccb
        .text:0x00401cad  loc_00401cad: [1 XREFS]
        .text:0x00401cad  837dfc00         cmp dword [ebp - 4],0
        .text:0x00401cb1  7502             jnz 0x00401cb5
        .text:0x00401cb3  eb16             jmp 0x00401ccb
        .text:0x00401cb5  loc_00401cb5: [1 XREFS]
        .text:0x00401cb5  8d95f4fbffff     lea edx,dword [ebp - 1036]
        .text:0x00401cbb  52               push edx
        .text:0x00401cbc  e87ffaffff       call 0x00401740    ;sub_00401740(local1040)
        .text:0x00401cc1  83c404           add esp,4
        .text:0x00401cc4  b801000000       mov eax,1
        .text:0x00401cc9  eb31             jmp 0x00401cfc
        .text:0x00401ccb  loc_00401ccb: [2 XREFS]
        .text:0x00401ccb  837dfc00         cmp dword [ebp - 4],0
        .text:0x00401ccf  0f8f43ffffff     jg 0x00401c18
        .text:0x00401cd5  loc_00401cd5: [1 XREFS]
        .text:0x00401cd5  8d85f4fbffff     lea eax,dword [ebp - 1036]
        .text:0x00401cdb  50               push eax
        .text:0x00401cdc  e85ffaffff       call 0x00401740    ;sub_00401740(local1040)
        .text:0x00401ce1  83c404           add esp,4
        .text:0x00401ce4  85c0             test eax,eax
        .text:0x00401ce6  7407             jz 0x00401cef
        .text:0x00401ce8  b801000000       mov eax,1
        .text:0x00401ced  eb0d             jmp 0x00401cfc
        .text:0x00401cef  loc_00401cef: [1 XREFS]
        .text:0x00401cef  8b4d18           mov ecx,dword [ebp + 24]
        .text:0x00401cf2  8b95f8fbffff     mov edx,dword [ebp - 1032]
        .text:0x00401cf8  8911             mov dword [ecx],edx
        .text:0x00401cfa  33c0             xor eax,eax
        .text:0x00401cfc  loc_00401cfc: [5 XREFS]
        .text:0x00401cfc  5f               pop edi
        .text:0x00401cfd  5e               pop esi
        .text:0x00401cfe  5b               pop ebx
        .text:0x00401cff  8be5             mov esp,ebp
        .text:0x00401d01  5d               pop ebp
        .text:0x00401d02  c3               ret 
        */
        $c49 = { 55 8B EC 81 EC 10 06 00 00 53 56 57 C7 85 ?? ?? ?? ?? 00 00 00 00 C7 85 ?? ?? ?? ?? 00 00 00 00 8B 45 ?? 50 8B 4D ?? 51 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? BF 80 C0 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 BF 70 C0 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 6A 00 8D BD ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 51 8D 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? FF 75 ?? 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 6A 00 68 00 02 00 00 8D 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 00 7E ?? 8B 95 ?? ?? ?? ?? 03 55 ?? 8B 45 ?? 3B 10 76 ?? 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 04 B8 01 00 00 00 E9 ?? ?? ?? ?? 8B 4D ?? 8D B5 ?? ?? ?? ?? 8B 7D ?? 03 BD ?? ?? ?? ?? 8B D1 C1 E9 02 F3 A5 8B CA 83 E1 03 F3 A4 8B 85 ?? ?? ?? ?? 03 45 ?? 89 85 ?? ?? ?? ?? 68 68 C0 40 00 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? EB ?? EB ?? 83 7D ?? 00 75 ?? EB ?? 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 04 B8 01 00 00 00 EB ?? 83 7D ?? 00 0F 8F ?? ?? ?? ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 ?? B8 01 00 00 00 EB ?? 8B 4D ?? 8B 95 ?? ?? ?? ?? 89 11 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00401790@b94af4a4d4af6eac81fc135abda1c40c with 2 features:
          - send data
          - send data on socket
        .text:0x00401790  
        .text:0x00401790  FUNC: int cdecl sub_00401790( int arg0, int arg1, int arg2, ) [2 XREFS] 
        .text:0x00401790  
        .text:0x00401790  Stack Variables: (offset from initial top of stack)
        .text:0x00401790            12: int arg2
        .text:0x00401790             8: int arg1
        .text:0x00401790             4: int arg0
        .text:0x00401790            -8: int local8
        .text:0x00401790           -12: int local12
        .text:0x00401790          -524: int local524
        .text:0x00401790          -528: int local528
        .text:0x00401790          -532: int local532
        .text:0x00401790  
        .text:0x00401790  55               push ebp
        .text:0x00401791  8bec             mov ebp,esp
        .text:0x00401793  81ec10020000     sub esp,528
        .text:0x00401799  c745fc00000000   mov dword [ebp - 4],0
        .text:0x004017a0  8b450c           mov eax,dword [ebp + 12]
        .text:0x004017a3  50               push eax
        .text:0x004017a4  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x004017a7  51               push ecx
        .text:0x004017a8  8d55fc           lea edx,dword [ebp - 4]
        .text:0x004017ab  52               push edx
        .text:0x004017ac  e88ffeffff       call 0x00401640    ;sub_00401640(local8,arg0,arg1)
        .text:0x004017b1  83c40c           add esp,12
        .text:0x004017b4  85c0             test eax,eax
        .text:0x004017b6  740a             jz 0x004017c2
        .text:0x004017b8  b801000000       mov eax,1
        .text:0x004017bd  e9a0000000       jmp 0x00401862
        .text:0x004017c2  loc_004017c2: [2 XREFS]
        .text:0x004017c2  c785f4fdffff0000 mov dword [ebp - 524],0
        .text:0x004017cc  8b4510           mov eax,dword [ebp + 16]
        .text:0x004017cf  50               push eax
        .text:0x004017d0  6800020000       push 512
        .text:0x004017d5  6a01             push 1
        .text:0x004017d7  8d8df8fdffff     lea ecx,dword [ebp - 520]
        .text:0x004017dd  51               push ecx
        .text:0x004017de  e892170000       call 0x00402f75    ;?(local524,1,512,arg2)
        .text:0x004017e3  83c410           add esp,16
        .text:0x004017e6  8945f8           mov dword [ebp - 8],eax
        .text:0x004017e9  loc_004017e9: [1 XREFS]
        .text:0x004017e9  6a00             push 0
        .text:0x004017eb  8b55f8           mov edx,dword [ebp - 8]
        .text:0x004017ee  52               push edx
        .text:0x004017ef  8d85f8fdffff     lea eax,dword [ebp - 520]
        .text:0x004017f5  50               push eax
        .text:0x004017f6  8b4dfc           mov ecx,dword [ebp - 4]
        .text:0x004017f9  51               push ecx
        .text:0x004017fa  ff154cb14000     call dword [0x0040b14c]    ;ws2_32.send(0,local524,sub_00402f75(local524,1,512,arg2),0)
        .text:0x00401800  8985f0fdffff     mov dword [ebp - 528],eax
        .text:0x00401806  83bdf0fdffffff   cmp dword [ebp - 528],0xffffffff
        .text:0x0040180d  7513             jnz 0x00401822
        .text:0x0040180f  8d55fc           lea edx,dword [ebp - 4]
        .text:0x00401812  52               push edx
        .text:0x00401813  e828ffffff       call 0x00401740    ;sub_00401740(local8)
        .text:0x00401818  83c404           add esp,4
        .text:0x0040181b  b801000000       mov eax,1
        .text:0x00401820  eb40             jmp 0x00401862
        .text:0x00401822  loc_00401822: [1 XREFS]
        .text:0x00401822  8b85f4fdffff     mov eax,dword [ebp - 524]
        .text:0x00401828  0385f0fdffff     add eax,dword [ebp - 528]
        .text:0x0040182e  8985f4fdffff     mov dword [ebp - 524],eax
        .text:0x00401834  8b8df4fdffff     mov ecx,dword [ebp - 524]
        .text:0x0040183a  3b4df8           cmp ecx,dword [ebp - 8]
        .text:0x0040183d  72aa             jc 0x004017e9
        .text:0x0040183f  837df800         cmp dword [ebp - 8],0
        .text:0x00401843  0f8779ffffff     ja 0x004017c2
        .text:0x00401849  8d55fc           lea edx,dword [ebp - 4]
        .text:0x0040184c  52               push edx
        .text:0x0040184d  e8eefeffff       call 0x00401740    ;sub_00401740(local8)
        .text:0x00401852  83c404           add esp,4
        .text:0x00401855  85c0             test eax,eax
        .text:0x00401857  7407             jz 0x00401860
        .text:0x00401859  b801000000       mov eax,1
        .text:0x0040185e  eb02             jmp 0x00401862
        .text:0x00401860  loc_00401860: [1 XREFS]
        .text:0x00401860  33c0             xor eax,eax
        .text:0x00401862  loc_00401862: [3 XREFS]
        .text:0x00401862  8be5             mov esp,ebp
        .text:0x00401864  5d               pop ebp
        .text:0x00401865  c3               ret 
        */
        $c50 = { 55 8B EC 81 EC 10 02 00 00 C7 45 ?? 00 00 00 00 8B 45 ?? 50 8B 4D ?? 51 8D 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 8B 45 ?? 50 68 00 02 00 00 6A 01 8D 8D ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 10 89 45 ?? 6A 00 8B 55 ?? 52 8D 85 ?? ?? ?? ?? 50 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? FF 75 ?? 8D 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 04 B8 01 00 00 00 EB ?? 8B 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 3B 4D ?? 72 ?? 83 7D ?? 00 0F 87 ?? ?? ?? ?? 8D 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 ?? B8 01 00 00 00 EB ?? 33 C0 8B E5 5D C3 }
        /*
function at 0x00401870@b94af4a4d4af6eac81fc135abda1c40c with 4 features:
          - read and send data from client to server
          - read file on Windows
          - send data
          - send data on socket
        .text:0x00401870  
        .text:0x00401870  FUNC: int cdecl sub_00401870( int arg0, int arg1, int arg2, ) [2 XREFS] 
        .text:0x00401870  
        .text:0x00401870  Stack Variables: (offset from initial top of stack)
        .text:0x00401870            12: int arg2
        .text:0x00401870             8: int arg1
        .text:0x00401870             4: int arg0
        .text:0x00401870            -8: int local8
        .text:0x00401870           -12: int local12
        .text:0x00401870          -524: int local524
        .text:0x00401870          -528: int local528
        .text:0x00401870          -532: int local532
        .text:0x00401870          -536: int local536
        .text:0x00401870  
        .text:0x00401870  55               push ebp
        .text:0x00401871  8bec             mov ebp,esp
        .text:0x00401873  81ec14020000     sub esp,532
        .text:0x00401879  c745fc00000000   mov dword [ebp - 4],0
        .text:0x00401880  8b450c           mov eax,dword [ebp + 12]
        .text:0x00401883  50               push eax
        .text:0x00401884  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00401887  51               push ecx
        .text:0x00401888  8d55fc           lea edx,dword [ebp - 4]
        .text:0x0040188b  52               push edx
        .text:0x0040188c  e8affdffff       call 0x00401640    ;sub_00401640(local8,arg0,arg1)
        .text:0x00401891  83c40c           add esp,12
        .text:0x00401894  85c0             test eax,eax
        .text:0x00401896  740a             jz 0x004018a2
        .text:0x00401898  b801000000       mov eax,1
        .text:0x0040189d  e936010000       jmp 0x004019d8
        .text:0x004018a2  loc_004018a2: [1 XREFS]
        .text:0x004018a2  6a00             push 0
        .text:0x004018a4  6880000000       push 128
        .text:0x004018a9  6a03             push 3
        .text:0x004018ab  6a00             push 0
        .text:0x004018ad  6a01             push 1
        .text:0x004018af  6800000080       push 0x80000000
        .text:0x004018b4  8b4510           mov eax,dword [ebp + 16]
        .text:0x004018b7  50               push eax
        .text:0x004018b8  ff1554b04000     call dword [0x0040b054]    ;kernel32.CreateFileA(arg2,0x80000000,1,0,3,128,0)
        .text:0x004018be  8985f4fdffff     mov dword [ebp - 524],eax
        .text:0x004018c4  83bdf4fdffffff   cmp dword [ebp - 524],0xffffffff
        .text:0x004018cb  7516             jnz 0x004018e3
        .text:0x004018cd  8d4dfc           lea ecx,dword [ebp - 4]
        .text:0x004018d0  51               push ecx
        .text:0x004018d1  e86afeffff       call 0x00401740    ;sub_00401740(local8)
        .text:0x004018d6  83c404           add esp,4
        .text:0x004018d9  b801000000       mov eax,1
        .text:0x004018de  e9f5000000       jmp 0x004019d8
        .text:0x004018e3  loc_004018e3: [2 XREFS]
        .text:0x004018e3  c785f0fdffff0000 mov dword [ebp - 528],0
        .text:0x004018ed  6a00             push 0
        .text:0x004018ef  8d55f8           lea edx,dword [ebp - 8]
        .text:0x004018f2  52               push edx
        .text:0x004018f3  6800020000       push 512
        .text:0x004018f8  8d85f8fdffff     lea eax,dword [ebp - 520]
        .text:0x004018fe  50               push eax
        .text:0x004018ff  8b8df4fdffff     mov ecx,dword [ebp - 524]
        .text:0x00401905  51               push ecx
        .text:0x00401906  ff1548b04000     call dword [0x0040b048]    ;kernel32.ReadFile(kernel32.CreateFileA(arg2,0x80000000,1,0,3,128,0),local524,512,local12,0)
        .text:0x0040190c  85c0             test eax,eax
        .text:0x0040190e  7535             jnz 0x00401945
        .text:0x00401910  ff154cb04000     call dword [0x0040b04c]    ;ntdll.RtlGetLastWin32Error()
        .text:0x00401916  83f826           cmp eax,38
        .text:0x00401919  7423             jz 0x0040193e
        .text:0x0040191b  8d55fc           lea edx,dword [ebp - 4]
        .text:0x0040191e  52               push edx
        .text:0x0040191f  e81cfeffff       call 0x00401740    ;sub_00401740(local8)
        .text:0x00401924  83c404           add esp,4
        .text:0x00401927  8b85f4fdffff     mov eax,dword [ebp - 524]
        .text:0x0040192d  50               push eax
        .text:0x0040192e  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(<0x004018b8>)
        .text:0x00401934  b801000000       mov eax,1
        .text:0x00401939  e99a000000       jmp 0x004019d8
        .text:0x0040193e  loc_0040193e: [1 XREFS]
        .text:0x0040193e  c745f800000000   mov dword [ebp - 8],0
        .text:0x00401945  loc_00401945: [2 XREFS]
        .text:0x00401945  6a00             push 0
        .text:0x00401947  8b4df8           mov ecx,dword [ebp - 8]
        .text:0x0040194a  51               push ecx
        .text:0x0040194b  8d95f8fdffff     lea edx,dword [ebp - 520]
        .text:0x00401951  52               push edx
        .text:0x00401952  8b45fc           mov eax,dword [ebp - 4]
        .text:0x00401955  50               push eax
        .text:0x00401956  ff154cb14000     call dword [0x0040b14c]    ;ws2_32.send(0,local524,0xfefefefe,0)
        .text:0x0040195c  8985ecfdffff     mov dword [ebp - 532],eax
        .text:0x00401962  83bdecfdffffff   cmp dword [ebp - 532],0xffffffff
        .text:0x00401969  7520             jnz 0x0040198b
        .text:0x0040196b  8d4dfc           lea ecx,dword [ebp - 4]
        .text:0x0040196e  51               push ecx
        .text:0x0040196f  e8ccfdffff       call 0x00401740    ;sub_00401740(local8)
        .text:0x00401974  83c404           add esp,4
        .text:0x00401977  8b95f4fdffff     mov edx,dword [ebp - 524]
        .text:0x0040197d  52               push edx
        .text:0x0040197e  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(<0x004018b8>)
        .text:0x00401984  b801000000       mov eax,1
        .text:0x00401989  eb4d             jmp 0x004019d8
        .text:0x0040198b  loc_0040198b: [1 XREFS]
        .text:0x0040198b  8b85f0fdffff     mov eax,dword [ebp - 528]
        .text:0x00401991  0385ecfdffff     add eax,dword [ebp - 532]
        .text:0x00401997  8985f0fdffff     mov dword [ebp - 528],eax
        .text:0x0040199d  8b8df0fdffff     mov ecx,dword [ebp - 528]
        .text:0x004019a3  3b4df8           cmp ecx,dword [ebp - 8]
        .text:0x004019a6  729d             jc 0x00401945
        .text:0x004019a8  837df800         cmp dword [ebp - 8],0
        .text:0x004019ac  0f8731ffffff     ja 0x004018e3
        .text:0x004019b2  8b95f4fdffff     mov edx,dword [ebp - 524]
        .text:0x004019b8  52               push edx
        .text:0x004019b9  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(<0x004018b8>)
        .text:0x004019bf  8d45fc           lea eax,dword [ebp - 4]
        .text:0x004019c2  50               push eax
        .text:0x004019c3  e878fdffff       call 0x00401740    ;sub_00401740(local8)
        .text:0x004019c8  83c404           add esp,4
        .text:0x004019cb  85c0             test eax,eax
        .text:0x004019cd  7407             jz 0x004019d6
        .text:0x004019cf  b801000000       mov eax,1
        .text:0x004019d4  eb02             jmp 0x004019d8
        .text:0x004019d6  loc_004019d6: [1 XREFS]
        .text:0x004019d6  33c0             xor eax,eax
        .text:0x004019d8  loc_004019d8: [5 XREFS]
        .text:0x004019d8  8be5             mov esp,ebp
        .text:0x004019da  5d               pop ebp
        .text:0x004019db  c3               ret 
        */
        $c51 = { 55 8B EC 81 EC 14 02 00 00 C7 45 ?? 00 00 00 00 8B 45 ?? 50 8B 4D ?? 51 8D 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 0C 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? FF 75 ?? 8D 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 04 B8 01 00 00 00 E9 ?? ?? ?? ?? C7 85 ?? ?? ?? ?? 00 00 00 00 6A 00 8D 55 ?? 52 68 00 02 00 00 8D 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 85 C0 75 ?? FF 15 ?? ?? ?? ?? 83 F8 26 74 ?? 8D 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 04 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? C7 45 ?? 00 00 00 00 6A 00 8B 4D ?? 51 8D 95 ?? ?? ?? ?? 52 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? FF 75 ?? 8D 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 04 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 8B 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 3B 4D ?? 72 ?? 83 7D ?? 00 0F 87 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 8D 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 ?? B8 01 00 00 00 EB ?? 33 C0 8B E5 5D C3 }
        /*
function at 0x00401640@b94af4a4d4af6eac81fc135abda1c40c with 4 features:
          - act as TCP client
          - connect TCP socket
          - initialize Winsock library
          - resolve DNS
        .text:0x00401640  
        .text:0x00401640  FUNC: int cdecl sub_00401640( int arg0, int arg1, int arg2, ) [8 XREFS] 
        .text:0x00401640  
        .text:0x00401640  Stack Variables: (offset from initial top of stack)
        .text:0x00401640            12: int arg2
        .text:0x00401640             8: int arg1
        .text:0x00401640             4: int arg0
        .text:0x00401640          -404: int local404
        .text:0x00401640          -408: int local408
        .text:0x00401640          -420: int local420
        .text:0x00401640          -422: int local422
        .text:0x00401640          -424: int local424
        .text:0x00401640  
        .text:0x00401640  55               push ebp
        .text:0x00401641  8bec             mov ebp,esp
        .text:0x00401643  81eca4010000     sub esp,420
        .text:0x00401649  8b4508           mov eax,dword [ebp + 8]
        .text:0x0040164c  c700ffffffff     mov dword [eax],0xffffffff
        .text:0x00401652  8d8d70feffff     lea ecx,dword [ebp - 400]
        .text:0x00401658  51               push ecx
        .text:0x00401659  6802020000       push 514
        .text:0x0040165e  ff1544b14000     call dword [0x0040b144]    ;ws2_32.WSAStartup(514,local404)
        .text:0x00401664  85c0             test eax,eax
        .text:0x00401666  740a             jz 0x00401672
        .text:0x00401668  b801000000       mov eax,1
        .text:0x0040166d  e9bb000000       jmp 0x0040172d
        .text:0x00401672  loc_00401672: [1 XREFS]
        .text:0x00401672  8b550c           mov edx,dword [ebp + 12]
        .text:0x00401675  52               push edx
        .text:0x00401676  ff1548b14000     call dword [0x0040b148]    ;ws2_32.gethostbyname(arg1)
        .text:0x0040167c  89856cfeffff     mov dword [ebp - 404],eax
        .text:0x00401682  83bd6cfeffff00   cmp dword [ebp - 404],0
        .text:0x00401689  7510             jnz 0x0040169b
        .text:0x0040168b  ff1564b14000     call dword [0x0040b164]    ;ws2_32.WSACleanup()
        .text:0x00401691  b801000000       mov eax,1
        .text:0x00401696  e992000000       jmp 0x0040172d
        .text:0x0040169b  loc_0040169b: [1 XREFS]
        .text:0x0040169b  6a06             push 6
        .text:0x0040169d  6a01             push 1
        .text:0x0040169f  6a02             push 2
        .text:0x004016a1  ff1550b14000     call dword [0x0040b150]    ;ws2_32.socket(2,1,6)
        .text:0x004016a7  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x004016aa  8901             mov dword [ecx],eax
        .text:0x004016ac  8b5508           mov edx,dword [ebp + 8]
        .text:0x004016af  833aff           cmp dword [edx],0xffffffff
        .text:0x004016b2  750d             jnz 0x004016c1
        .text:0x004016b4  ff1564b14000     call dword [0x0040b164]    ;ws2_32.WSACleanup()
        .text:0x004016ba  b801000000       mov eax,1
        .text:0x004016bf  eb6c             jmp 0x0040172d
        .text:0x004016c1  loc_004016c1: [1 XREFS]
        .text:0x004016c1  66c7855cfeffff02 mov word [ebp - 420],2
        .text:0x004016ca  8b856cfeffff     mov eax,dword [ebp - 404]
        .text:0x004016d0  8b480c           mov ecx,dword [eax + 12]
        .text:0x004016d3  8b11             mov edx,dword [ecx]
        .text:0x004016d5  8b02             mov eax,dword [edx]
        .text:0x004016d7  898560feffff     mov dword [ebp - 416],eax
        .text:0x004016dd  668b4d10         mov cx,word [ebp + 16]
        .text:0x004016e1  51               push ecx
        .text:0x004016e2  ff1554b14000     call dword [0x0040b154]    ;ws2_32.htons(0x6161500f)
        .text:0x004016e8  6689855efeffff   mov word [ebp - 418],ax
        .text:0x004016ef  6a10             push 16
        .text:0x004016f1  8d955cfeffff     lea edx,dword [ebp - 420]
        .text:0x004016f7  52               push edx
        .text:0x004016f8  8b4508           mov eax,dword [ebp + 8]
        .text:0x004016fb  8b08             mov ecx,dword [eax]
        .text:0x004016fd  51               push ecx
        .text:0x004016fe  ff1558b14000     call dword [0x0040b158]    ;ws2_32.connect(0x61616161,local424,16)
        .text:0x00401704  83f8ff           cmp eax,0xffffffff
        .text:0x00401707  7522             jnz 0x0040172b
        .text:0x00401709  8b5508           mov edx,dword [ebp + 8]
        .text:0x0040170c  8b02             mov eax,dword [edx]
        .text:0x0040170e  50               push eax
        .text:0x0040170f  ff155cb14000     call dword [0x0040b15c]    ;ws2_32.closesocket(0x61616161)
        .text:0x00401715  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00401718  c701ffffffff     mov dword [ecx],0xffffffff
        .text:0x0040171e  ff1564b14000     call dword [0x0040b164]    ;ws2_32.WSACleanup()
        .text:0x00401724  b801000000       mov eax,1
        .text:0x00401729  eb02             jmp 0x0040172d
        .text:0x0040172b  loc_0040172b: [1 XREFS]
        .text:0x0040172b  33c0             xor eax,eax
        .text:0x0040172d  loc_0040172d: [4 XREFS]
        .text:0x0040172d  8be5             mov esp,ebp
        .text:0x0040172f  5d               pop ebp
        .text:0x00401730  c3               ret 
        */
        $c52 = { 55 8B EC 81 EC A4 01 00 00 8B 45 ?? C7 00 FF FF FF FF 8D 8D ?? ?? ?? ?? 51 68 02 02 00 00 FF 15 ?? ?? ?? ?? 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 6A 06 6A 01 6A 02 FF 15 ?? ?? ?? ?? 8B 4D ?? 89 01 8B 55 ?? 83 3A FF 75 ?? FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 66 C7 85 ?? ?? ?? ?? 02 00 8B 85 ?? ?? ?? ?? 8B 48 ?? 8B 11 8B 02 89 85 ?? ?? ?? ?? 66 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? 6A 10 8D 95 ?? ?? ?? ?? 52 8B 45 ?? 8B 08 51 FF 15 ?? ?? ?? ?? 83 F8 FF 75 ?? 8B 55 ?? 8B 02 50 FF 15 ?? ?? ?? ?? 8B 4D ?? C7 01 FF FF FF FF FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 33 C0 8B E5 5D C3 }
        /*
function at 0x00402600@b94af4a4d4af6eac81fc135abda1c40c with 5 features:
          - copy file
          - create service
          - modify service
          - persist via Windows service
          - query environment variable
        .text:0x00402600  
        .text:0x00402600  FUNC: int thiscall_caller sub_00402600( void * ecx, int arg1, ) [4 XREFS] 
        .text:0x00402600  
        .text:0x00402600  Stack Variables: (offset from initial top of stack)
        .text:0x00402600             4: int arg1
        .text:0x00402600          -1028: int local1028
        .text:0x00402600          -1032: int local1032
        .text:0x00402600          -2056: int local2056
        .text:0x00402600          -3080: int local3080
        .text:0x00402600          -4104: int local4104
        .text:0x00402600          -5128: int local5128
        .text:0x00402600          -5132: int local5132
        .text:0x00402600  
        .text:0x00402600  55               push ebp
        .text:0x00402601  8bec             mov ebp,esp
        .text:0x00402603  b808140000       mov eax,0x00001408
        .text:0x00402608  e8a3080000       call 0x00402eb0    ;__alloca_probe()
        .text:0x0040260d  53               push ebx
        .text:0x0040260e  56               push esi
        .text:0x0040260f  57               push edi
        .text:0x00402610  6800040000       push 1024
        .text:0x00402615  8d85fcebffff     lea eax,dword [ebp - 5124]
        .text:0x0040261b  50               push eax
        .text:0x0040261c  e88fffffff       call 0x004025b0    ;sub_004025b0(local5128)
        .text:0x00402621  83c408           add esp,8
        .text:0x00402624  85c0             test eax,eax
        .text:0x00402626  740a             jz 0x00402632
        .text:0x00402628  b801000000       mov eax,1
        .text:0x0040262d  e9c3020000       jmp 0x004028f5
        .text:0x00402632  loc_00402632: [1 XREFS]
        .text:0x00402632  bf34c14000       mov edi,0x0040c134
        .text:0x00402637  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x0040263d  83c9ff           or ecx,0xffffffff
        .text:0x00402640  33c0             xor eax,eax
        .text:0x00402642  f2ae             repnz: scasb 
        .text:0x00402644  f7d1             not ecx
        .text:0x00402646  2bf9             sub edi,ecx
        .text:0x00402648  8bf7             mov esi,edi
        .text:0x0040264a  8bc1             mov eax,ecx
        .text:0x0040264c  8bfa             mov edi,edx
        .text:0x0040264e  c1e902           shr ecx,2
        .text:0x00402651  f3a5             rep: movsd 
        .text:0x00402653  8bc8             mov ecx,eax
        .text:0x00402655  83e103           and ecx,3
        .text:0x00402658  f3a4             rep: movsb 
        .text:0x0040265a  8dbdfcebffff     lea edi,dword [ebp - 5124]
        .text:0x00402660  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x00402666  83c9ff           or ecx,0xffffffff
        .text:0x00402669  33c0             xor eax,eax
        .text:0x0040266b  f2ae             repnz: scasb 
        .text:0x0040266d  f7d1             not ecx
        .text:0x0040266f  2bf9             sub edi,ecx
        .text:0x00402671  8bf7             mov esi,edi
        .text:0x00402673  8bd9             mov ebx,ecx
        .text:0x00402675  8bfa             mov edi,edx
        .text:0x00402677  83c9ff           or ecx,0xffffffff
        .text:0x0040267a  33c0             xor eax,eax
        .text:0x0040267c  f2ae             repnz: scasb 
        .text:0x0040267e  83c7ff           add edi,0xffffffff
        .text:0x00402681  8bcb             mov ecx,ebx
        .text:0x00402683  c1e902           shr ecx,2
        .text:0x00402686  f3a5             rep: movsd 
        .text:0x00402688  8bcb             mov ecx,ebx
        .text:0x0040268a  83e103           and ecx,3
        .text:0x0040268d  f3a4             rep: movsb 
        .text:0x0040268f  bf2cc14000       mov edi,0x0040c12c
        .text:0x00402694  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x0040269a  83c9ff           or ecx,0xffffffff
        .text:0x0040269d  33c0             xor eax,eax
        .text:0x0040269f  f2ae             repnz: scasb 
        .text:0x004026a1  f7d1             not ecx
        .text:0x004026a3  2bf9             sub edi,ecx
        .text:0x004026a5  8bf7             mov esi,edi
        .text:0x004026a7  8bd9             mov ebx,ecx
        .text:0x004026a9  8bfa             mov edi,edx
        .text:0x004026ab  83c9ff           or ecx,0xffffffff
        .text:0x004026ae  33c0             xor eax,eax
        .text:0x004026b0  f2ae             repnz: scasb 
        .text:0x004026b2  83c7ff           add edi,0xffffffff
        .text:0x004026b5  8bcb             mov ecx,ebx
        .text:0x004026b7  c1e902           shr ecx,2
        .text:0x004026ba  f3a5             rep: movsd 
        .text:0x004026bc  8bcb             mov ecx,ebx
        .text:0x004026be  83e103           and ecx,3
        .text:0x004026c1  f3a4             rep: movsb 
        .text:0x004026c3  683f000f00       push 0x000f003f
        .text:0x004026c8  6a00             push 0
        .text:0x004026ca  6a00             push 0
        .text:0x004026cc  ff1500b04000     call dword [0x0040b000]    ;advapi32.OpenSCManagerA(0,0,0x000f003f)
        .text:0x004026d2  8985fcfbffff     mov dword [ebp - 1028],eax
        .text:0x004026d8  83bdfcfbffff00   cmp dword [ebp - 1028],0
        .text:0x004026df  750a             jnz 0x004026eb
        .text:0x004026e1  b801000000       mov eax,1
        .text:0x004026e6  e90a020000       jmp 0x004028f5
        .text:0x004026eb  loc_004026eb: [1 XREFS]
        .text:0x004026eb  68ff010f00       push 0x000f01ff
        .text:0x004026f0  8b4508           mov eax,dword [ebp + 8]
        .text:0x004026f3  50               push eax
        .text:0x004026f4  8b8dfcfbffff     mov ecx,dword [ebp - 1028]
        .text:0x004026fa  51               push ecx
        .text:0x004026fb  ff1504b04000     call dword [0x0040b004]    ;advapi32.OpenServiceA(advapi32.OpenSCManagerA(0,0,0x000f003f),arg1,0x000f01ff)
        .text:0x00402701  8985f8ebffff     mov dword [ebp - 5128],eax
        .text:0x00402707  83bdf8ebffff00   cmp dword [ebp - 5128],0
        .text:0x0040270e  746d             jz 0x0040277d
        .text:0x00402710  6a00             push 0
        .text:0x00402712  6a00             push 0
        .text:0x00402714  6a00             push 0
        .text:0x00402716  6a00             push 0
        .text:0x00402718  6a00             push 0
        .text:0x0040271a  6a00             push 0
        .text:0x0040271c  8d95fcf7ffff     lea edx,dword [ebp - 2052]
        .text:0x00402722  52               push edx
        .text:0x00402723  6aff             push 0xffffffff
        .text:0x00402725  6a02             push 2
        .text:0x00402727  6aff             push 0xffffffff
        .text:0x00402729  8b85f8ebffff     mov eax,dword [ebp - 5128]
        .text:0x0040272f  50               push eax
        .text:0x00402730  ff1508b04000     call dword [0x0040b008]    ;advapi32.ChangeServiceConfigA(advapi32.OpenServiceA(<0x004026cc>,arg1,0x000f01ff),0xffffffff,2,0xffffffff,local2056,0,0,0,0,0,0)
        .text:0x00402736  85c0             test eax,eax
        .text:0x00402738  7524             jnz 0x0040275e
        .text:0x0040273a  8b8df8ebffff     mov ecx,dword [ebp - 5128]
        .text:0x00402740  51               push ecx
        .text:0x00402741  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x004026fb>)
        .text:0x00402747  8b95fcfbffff     mov edx,dword [ebp - 1028]
        .text:0x0040274d  52               push edx
        .text:0x0040274e  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x004026cc>)
        .text:0x00402754  b801000000       mov eax,1
        .text:0x00402759  e997010000       jmp 0x004028f5
        .text:0x0040275e  loc_0040275e: [1 XREFS]
        .text:0x0040275e  8b85f8ebffff     mov eax,dword [ebp - 5128]
        .text:0x00402764  50               push eax
        .text:0x00402765  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x004026fb>)
        .text:0x0040276b  8b8dfcfbffff     mov ecx,dword [ebp - 1028]
        .text:0x00402771  51               push ecx
        .text:0x00402772  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x004026cc>)
        .text:0x00402778  e9ce000000       jmp 0x0040284b
        .text:0x0040277d  loc_0040277d: [1 XREFS]
        .text:0x0040277d  8b7d08           mov edi,dword [ebp + 8]
        .text:0x00402780  8d95fcf3ffff     lea edx,dword [ebp - 3076]
        .text:0x00402786  83c9ff           or ecx,0xffffffff
        .text:0x00402789  33c0             xor eax,eax
        .text:0x0040278b  f2ae             repnz: scasb 
        .text:0x0040278d  f7d1             not ecx
        .text:0x0040278f  2bf9             sub edi,ecx
        .text:0x00402791  8bf7             mov esi,edi
        .text:0x00402793  8bc1             mov eax,ecx
        .text:0x00402795  8bfa             mov edi,edx
        .text:0x00402797  c1e902           shr ecx,2
        .text:0x0040279a  f3a5             rep: movsd 
        .text:0x0040279c  8bc8             mov ecx,eax
        .text:0x0040279e  83e103           and ecx,3
        .text:0x004027a1  f3a4             rep: movsb 
        .text:0x004027a3  bf18c14000       mov edi,0x0040c118
        .text:0x004027a8  8d95fcf3ffff     lea edx,dword [ebp - 3076]
        .text:0x004027ae  83c9ff           or ecx,0xffffffff
        .text:0x004027b1  33c0             xor eax,eax
        .text:0x004027b3  f2ae             repnz: scasb 
        .text:0x004027b5  f7d1             not ecx
        .text:0x004027b7  2bf9             sub edi,ecx
        .text:0x004027b9  8bf7             mov esi,edi
        .text:0x004027bb  8bd9             mov ebx,ecx
        .text:0x004027bd  8bfa             mov edi,edx
        .text:0x004027bf  83c9ff           or ecx,0xffffffff
        .text:0x004027c2  33c0             xor eax,eax
        .text:0x004027c4  f2ae             repnz: scasb 
        .text:0x004027c6  83c7ff           add edi,0xffffffff
        .text:0x004027c9  8bcb             mov ecx,ebx
        .text:0x004027cb  c1e902           shr ecx,2
        .text:0x004027ce  f3a5             rep: movsd 
        .text:0x004027d0  8bcb             mov ecx,ebx
        .text:0x004027d2  83e103           and ecx,3
        .text:0x004027d5  f3a4             rep: movsb 
        .text:0x004027d7  6a00             push 0
        .text:0x004027d9  6a00             push 0
        .text:0x004027db  6a00             push 0
        .text:0x004027dd  6a00             push 0
        .text:0x004027df  6a00             push 0
        .text:0x004027e1  8d8500fcffff     lea eax,dword [ebp - 1024]
        .text:0x004027e7  50               push eax
        .text:0x004027e8  6a01             push 1
        .text:0x004027ea  6a02             push 2
        .text:0x004027ec  6a20             push 32
        .text:0x004027ee  68ff010f00       push 0x000f01ff
        .text:0x004027f3  8d8dfcf3ffff     lea ecx,dword [ebp - 3076]
        .text:0x004027f9  51               push ecx
        .text:0x004027fa  8b5508           mov edx,dword [ebp + 8]
        .text:0x004027fd  52               push edx
        .text:0x004027fe  8b85fcfbffff     mov eax,dword [ebp - 1028]
        .text:0x00402804  50               push eax
        .text:0x00402805  ff1510b04000     call dword [0x0040b010]    ;advapi32.CreateServiceA(<0x004026cc>,arg1,local3080,0x000f01ff,32,2,1,local1028,0,0,0,0,0)
        .text:0x0040280b  8985f8ebffff     mov dword [ebp - 5128],eax
        .text:0x00402811  83bdf8ebffff00   cmp dword [ebp - 5128],0
        .text:0x00402818  7517             jnz 0x00402831
        .text:0x0040281a  8b8dfcfbffff     mov ecx,dword [ebp - 1028]
        .text:0x00402820  51               push ecx
        .text:0x00402821  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x004026cc>)
        .text:0x00402827  b801000000       mov eax,1
        .text:0x0040282c  e9c4000000       jmp 0x004028f5
        .text:0x00402831  loc_00402831: [1 XREFS]
        .text:0x00402831  8b95f8ebffff     mov edx,dword [ebp - 5128]
        .text:0x00402837  52               push edx
        .text:0x00402838  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(advapi32.CreateServiceA(<0x004026cc>,arg1,local3080,0x000f01ff,32,2,1,local1028,0,0,0,0,0))
        .text:0x0040283e  8b85fcfbffff     mov eax,dword [ebp - 1028]
        .text:0x00402844  50               push eax
        .text:0x00402845  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x004026cc>)
        .text:0x0040284b  loc_0040284b: [1 XREFS]
        .text:0x0040284b  6800040000       push 1024
        .text:0x00402850  8d8dfcf7ffff     lea ecx,dword [ebp - 2052]
        .text:0x00402856  51               push ecx
        .text:0x00402857  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x0040285d  52               push edx
        .text:0x0040285e  ff1530b04000     call dword [0x0040b030]    ;kernel32.ExpandEnvironmentStringsA(local1028,local2056,1024)
        .text:0x00402864  85c0             test eax,eax
        .text:0x00402866  750a             jnz 0x00402872
        .text:0x00402868  b801000000       mov eax,1
        .text:0x0040286d  e983000000       jmp 0x004028f5
        .text:0x00402872  loc_00402872: [1 XREFS]
        .text:0x00402872  6800040000       push 1024
        .text:0x00402877  8d85fcefffff     lea eax,dword [ebp - 4100]
        .text:0x0040287d  50               push eax
        .text:0x0040287e  6a00             push 0
        .text:0x00402880  ff1538b04000     call dword [0x0040b038]    ;kernel32.GetModuleFileNameA(0,local4104,1024)
        .text:0x00402886  85c0             test eax,eax
        .text:0x00402888  7507             jnz 0x00402891
        .text:0x0040288a  b801000000       mov eax,1
        .text:0x0040288f  eb64             jmp 0x004028f5
        .text:0x00402891  loc_00402891: [1 XREFS]
        .text:0x00402891  6a00             push 0
        .text:0x00402893  8d8dfcf7ffff     lea ecx,dword [ebp - 2052]
        .text:0x00402899  51               push ecx
        .text:0x0040289a  8d95fcefffff     lea edx,dword [ebp - 4100]
        .text:0x004028a0  52               push edx
        .text:0x004028a1  ff1534b04000     call dword [0x0040b034]    ;kernel32.CopyFileA(local4104,local2056,0)
        .text:0x004028a7  85c0             test eax,eax
        .text:0x004028a9  7507             jnz 0x004028b2
        .text:0x004028ab  b801000000       mov eax,1
        .text:0x004028b0  eb43             jmp 0x004028f5
        .text:0x004028b2  loc_004028b2: [1 XREFS]
        .text:0x004028b2  8d85fcf7ffff     lea eax,dword [ebp - 2052]
        .text:0x004028b8  50               push eax
        .text:0x004028b9  e8f2ecffff       call 0x004015b0    ;sub_004015b0(local2056,local2056)
        .text:0x004028be  83c404           add esp,4
        .text:0x004028c1  85c0             test eax,eax
        .text:0x004028c3  7407             jz 0x004028cc
        .text:0x004028c5  b801000000       mov eax,1
        .text:0x004028ca  eb29             jmp 0x004028f5
        .text:0x004028cc  loc_004028cc: [1 XREFS]
        .text:0x004028cc  6814c14000       push 0x0040c114
        .text:0x004028d1  6810c14000       push 0x0040c110
        .text:0x004028d6  68e8c04000       push 0x0040c0e8
        .text:0x004028db  68e4c04000       push 0x0040c0e4
        .text:0x004028e0  e88be7ffff       call 0x00401070    ;sub_00401070(0x0040c0e4,0x0040c0e8,0x0040c110,0x0040c114)
        .text:0x004028e5  83c410           add esp,16
        .text:0x004028e8  85c0             test eax,eax
        .text:0x004028ea  7407             jz 0x004028f3
        .text:0x004028ec  b801000000       mov eax,1
        .text:0x004028f1  eb02             jmp 0x004028f5
        .text:0x004028f3  loc_004028f3: [1 XREFS]
        .text:0x004028f3  33c0             xor eax,eax
        .text:0x004028f5  loc_004028f5: [9 XREFS]
        .text:0x004028f5  5f               pop edi
        .text:0x004028f6  5e               pop esi
        .text:0x004028f7  5b               pop ebx
        .text:0x004028f8  8be5             mov esp,ebp
        .text:0x004028fa  5d               pop ebp
        .text:0x004028fb  c3               ret 
        */
        $c53 = { 55 8B EC B8 08 14 00 00 E8 ?? ?? ?? ?? 53 56 57 68 00 04 00 00 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? BF 34 C1 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8D BD ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 BF 2C C1 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 68 3F 00 0F 00 6A 00 6A 00 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 68 FF 01 0F 00 8B 45 ?? 50 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? 6A 00 6A 00 6A 00 6A 00 6A 00 6A 00 8D 95 ?? ?? ?? ?? 52 6A FF 6A 02 6A FF 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? E9 ?? ?? ?? ?? 8B 7D ?? 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 BF 18 C1 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 6A 00 6A 00 6A 00 6A 00 6A 00 8D 85 ?? ?? ?? ?? 50 6A 01 6A 02 6A 20 68 FF 01 0F 00 8D 8D ?? ?? ?? ?? 51 8B 55 ?? 52 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 68 00 04 00 00 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 68 00 04 00 00 8D 85 ?? ?? ?? ?? 50 6A 00 FF 15 ?? ?? ?? ?? 85 C0 75 ?? B8 01 00 00 00 EB ?? 6A 00 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? B8 01 00 00 00 EB ?? 8D 85 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 04 85 C0 74 ?? B8 01 00 00 00 EB ?? 68 14 C1 40 00 68 10 C1 40 00 68 E8 C0 40 00 68 E4 C0 40 00 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 ?? B8 01 00 00 00 EB ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00402900@b94af4a4d4af6eac81fc135abda1c40c with 3 features:
          - delete file
          - delete service
          - query environment variable
        .text:0x00402900  
        .text:0x00402900  FUNC: int cdecl sub_00402900( int arg0, ) [4 XREFS] 
        .text:0x00402900  
        .text:0x00402900  Stack Variables: (offset from initial top of stack)
        .text:0x00402900             4: int arg0
        .text:0x00402900          -1028: int local1028
        .text:0x00402900          -1032: int local1032
        .text:0x00402900          -2056: int local2056
        .text:0x00402900          -3080: int local3080
        .text:0x00402900          -3084: int local3084
        .text:0x00402900  
        .text:0x00402900  55               push ebp
        .text:0x00402901  8bec             mov ebp,esp
        .text:0x00402903  81ec080c0000     sub esp,3080
        .text:0x00402909  53               push ebx
        .text:0x0040290a  56               push esi
        .text:0x0040290b  57               push edi
        .text:0x0040290c  683f000f00       push 0x000f003f
        .text:0x00402911  6a00             push 0
        .text:0x00402913  6a00             push 0
        .text:0x00402915  ff1500b04000     call dword [0x0040b000]    ;advapi32.OpenSCManagerA(0,0,0x000f003f)
        .text:0x0040291b  8985fcfbffff     mov dword [ebp - 1028],eax
        .text:0x00402921  83bdfcfbffff00   cmp dword [ebp - 1028],0
        .text:0x00402928  750a             jnz 0x00402934
        .text:0x0040292a  b801000000       mov eax,1
        .text:0x0040292f  e9b3010000       jmp 0x00402ae7
        .text:0x00402934  loc_00402934: [1 XREFS]
        .text:0x00402934  68ff010f00       push 0x000f01ff
        .text:0x00402939  8b4508           mov eax,dword [ebp + 8]
        .text:0x0040293c  50               push eax
        .text:0x0040293d  8b8dfcfbffff     mov ecx,dword [ebp - 1028]
        .text:0x00402943  51               push ecx
        .text:0x00402944  ff1504b04000     call dword [0x0040b004]    ;advapi32.OpenServiceA(advapi32.OpenSCManagerA(0,0,0x000f003f),arg0,0x000f01ff)
        .text:0x0040294a  8985f8f3ffff     mov dword [ebp - 3080],eax
        .text:0x00402950  83bdf8f3ffff00   cmp dword [ebp - 3080],0
        .text:0x00402957  7517             jnz 0x00402970
        .text:0x00402959  8b95fcfbffff     mov edx,dword [ebp - 1028]
        .text:0x0040295f  52               push edx
        .text:0x00402960  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x00402915>)
        .text:0x00402966  b801000000       mov eax,1
        .text:0x0040296b  e977010000       jmp 0x00402ae7
        .text:0x00402970  loc_00402970: [1 XREFS]
        .text:0x00402970  8b85f8f3ffff     mov eax,dword [ebp - 3080]
        .text:0x00402976  50               push eax
        .text:0x00402977  ff1528b04000     call dword [0x0040b028]    ;advapi32.DeleteService(advapi32.OpenServiceA(<0x00402915>,arg0,0x000f01ff))
        .text:0x0040297d  85c0             test eax,eax
        .text:0x0040297f  7524             jnz 0x004029a5
        .text:0x00402981  8b8dfcfbffff     mov ecx,dword [ebp - 1028]
        .text:0x00402987  51               push ecx
        .text:0x00402988  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x00402915>)
        .text:0x0040298e  8b95f8f3ffff     mov edx,dword [ebp - 3080]
        .text:0x00402994  52               push edx
        .text:0x00402995  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x00402944>)
        .text:0x0040299b  b801000000       mov eax,1
        .text:0x004029a0  e942010000       jmp 0x00402ae7
        .text:0x004029a5  loc_004029a5: [1 XREFS]
        .text:0x004029a5  8b85fcfbffff     mov eax,dword [ebp - 1028]
        .text:0x004029ab  50               push eax
        .text:0x004029ac  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x00402915>)
        .text:0x004029b2  8b8df8f3ffff     mov ecx,dword [ebp - 3080]
        .text:0x004029b8  51               push ecx
        .text:0x004029b9  ff150cb04000     call dword [0x0040b00c]    ;advapi32.CloseServiceHandle(<0x00402944>)
        .text:0x004029bf  6800040000       push 1024
        .text:0x004029c4  8d95fcf3ffff     lea edx,dword [ebp - 3076]
        .text:0x004029ca  52               push edx
        .text:0x004029cb  e8e0fbffff       call 0x004025b0    ;sub_004025b0(local3080)
        .text:0x004029d0  83c408           add esp,8
        .text:0x004029d3  85c0             test eax,eax
        .text:0x004029d5  740a             jz 0x004029e1
        .text:0x004029d7  b801000000       mov eax,1
        .text:0x004029dc  e906010000       jmp 0x00402ae7
        .text:0x004029e1  loc_004029e1: [1 XREFS]
        .text:0x004029e1  bf34c14000       mov edi,0x0040c134
        .text:0x004029e6  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x004029ec  83c9ff           or ecx,0xffffffff
        .text:0x004029ef  33c0             xor eax,eax
        .text:0x004029f1  f2ae             repnz: scasb 
        .text:0x004029f3  f7d1             not ecx
        .text:0x004029f5  2bf9             sub edi,ecx
        .text:0x004029f7  8bf7             mov esi,edi
        .text:0x004029f9  8bc1             mov eax,ecx
        .text:0x004029fb  8bfa             mov edi,edx
        .text:0x004029fd  c1e902           shr ecx,2
        .text:0x00402a00  f3a5             rep: movsd 
        .text:0x00402a02  8bc8             mov ecx,eax
        .text:0x00402a04  83e103           and ecx,3
        .text:0x00402a07  f3a4             rep: movsb 
        .text:0x00402a09  8dbdfcf3ffff     lea edi,dword [ebp - 3076]
        .text:0x00402a0f  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x00402a15  83c9ff           or ecx,0xffffffff
        .text:0x00402a18  33c0             xor eax,eax
        .text:0x00402a1a  f2ae             repnz: scasb 
        .text:0x00402a1c  f7d1             not ecx
        .text:0x00402a1e  2bf9             sub edi,ecx
        .text:0x00402a20  8bf7             mov esi,edi
        .text:0x00402a22  8bd9             mov ebx,ecx
        .text:0x00402a24  8bfa             mov edi,edx
        .text:0x00402a26  83c9ff           or ecx,0xffffffff
        .text:0x00402a29  33c0             xor eax,eax
        .text:0x00402a2b  f2ae             repnz: scasb 
        .text:0x00402a2d  83c7ff           add edi,0xffffffff
        .text:0x00402a30  8bcb             mov ecx,ebx
        .text:0x00402a32  c1e902           shr ecx,2
        .text:0x00402a35  f3a5             rep: movsd 
        .text:0x00402a37  8bcb             mov ecx,ebx
        .text:0x00402a39  83e103           and ecx,3
        .text:0x00402a3c  f3a4             rep: movsb 
        .text:0x00402a3e  bf2cc14000       mov edi,0x0040c12c
        .text:0x00402a43  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x00402a49  83c9ff           or ecx,0xffffffff
        .text:0x00402a4c  33c0             xor eax,eax
        .text:0x00402a4e  f2ae             repnz: scasb 
        .text:0x00402a50  f7d1             not ecx
        .text:0x00402a52  2bf9             sub edi,ecx
        .text:0x00402a54  8bf7             mov esi,edi
        .text:0x00402a56  8bd9             mov ebx,ecx
        .text:0x00402a58  8bfa             mov edi,edx
        .text:0x00402a5a  83c9ff           or ecx,0xffffffff
        .text:0x00402a5d  33c0             xor eax,eax
        .text:0x00402a5f  f2ae             repnz: scasb 
        .text:0x00402a61  83c7ff           add edi,0xffffffff
        .text:0x00402a64  8bcb             mov ecx,ebx
        .text:0x00402a66  c1e902           shr ecx,2
        .text:0x00402a69  f3a5             rep: movsd 
        .text:0x00402a6b  8bcb             mov ecx,ebx
        .text:0x00402a6d  83e103           and ecx,3
        .text:0x00402a70  f3a4             rep: movsb 
        .text:0x00402a72  6800040000       push 1024
        .text:0x00402a77  8d85fcf7ffff     lea eax,dword [ebp - 2052]
        .text:0x00402a7d  50               push eax
        .text:0x00402a7e  8d8d00fcffff     lea ecx,dword [ebp - 1024]
        .text:0x00402a84  51               push ecx
        .text:0x00402a85  ff1530b04000     call dword [0x0040b030]    ;kernel32.ExpandEnvironmentStringsA(local1028,local2056,1024)
        .text:0x00402a8b  85c0             test eax,eax
        .text:0x00402a8d  7507             jnz 0x00402a96
        .text:0x00402a8f  b801000000       mov eax,1
        .text:0x00402a94  eb51             jmp 0x00402ae7
        .text:0x00402a96  loc_00402a96: [1 XREFS]
        .text:0x00402a96  8d95fcf7ffff     lea edx,dword [ebp - 2052]
        .text:0x00402a9c  52               push edx
        .text:0x00402a9d  ff1560b04000     call dword [0x0040b060]    ;kernel32.DeleteFileA(local2056)
        .text:0x00402aa3  85c0             test eax,eax
        .text:0x00402aa5  7507             jnz 0x00402aae
        .text:0x00402aa7  b801000000       mov eax,1
        .text:0x00402aac  eb39             jmp 0x00402ae7
        .text:0x00402aae  loc_00402aae: [1 XREFS]
        .text:0x00402aae  6860eb4000       push 0x0040eb60
        .text:0x00402ab3  6860eb4000       push 0x0040eb60
        .text:0x00402ab8  6860eb4000       push 0x0040eb60
        .text:0x00402abd  6860eb4000       push 0x0040eb60
        .text:0x00402ac2  e8a9e5ffff       call 0x00401070    ;sub_00401070(0x0040eb60,0x0040eb60,0x0040eb60,0x0040eb60)
        .text:0x00402ac7  83c410           add esp,16
        .text:0x00402aca  85c0             test eax,eax
        .text:0x00402acc  7407             jz 0x00402ad5
        .text:0x00402ace  b801000000       mov eax,1
        .text:0x00402ad3  eb12             jmp 0x00402ae7
        .text:0x00402ad5  loc_00402ad5: [1 XREFS]
        .text:0x00402ad5  e836e7ffff       call 0x00401210    ;sub_00401210()
        .text:0x00402ada  85c0             test eax,eax
        .text:0x00402adc  7407             jz 0x00402ae5
        .text:0x00402ade  b801000000       mov eax,1
        .text:0x00402ae3  eb02             jmp 0x00402ae7
        .text:0x00402ae5  loc_00402ae5: [1 XREFS]
        .text:0x00402ae5  33c0             xor eax,eax
        .text:0x00402ae7  loc_00402ae7: [8 XREFS]
        .text:0x00402ae7  5f               pop edi
        .text:0x00402ae8  5e               pop esi
        .text:0x00402ae9  5b               pop ebx
        .text:0x00402aea  8be5             mov esp,ebp
        .text:0x00402aec  5d               pop ebp
        .text:0x00402aed  c3               ret 
        */
        $c54 = { 55 8B EC 81 EC 08 0C 00 00 53 56 57 68 3F 00 0F 00 6A 00 6A 00 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 68 FF 01 0F 00 8B 45 ?? 50 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 75 ?? 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 68 00 04 00 00 8D 95 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? BF 34 C1 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8D BD ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 BF 2C C1 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 68 00 04 00 00 8D 85 ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 85 C0 75 ?? B8 01 00 00 00 EB ?? 8D 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 85 C0 75 ?? B8 01 00 00 00 EB ?? 68 60 EB 40 00 68 60 EB 40 00 68 60 EB 40 00 68 60 EB 40 00 E8 ?? ?? ?? ?? 83 C4 10 85 C0 74 ?? B8 01 00 00 00 EB ?? E8 ?? ?? ?? ?? 85 C0 74 ?? B8 01 00 00 00 EB ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x004015b0@b94af4a4d4af6eac81fc135abda1c40c with 1 features:
          - get common file path
        .text:0x004015b0  
        .text:0x004015b0  FUNC: int thiscall_caller sub_004015b0( void * ecx, int arg1, ) [4 XREFS] 
        .text:0x004015b0  
        .text:0x004015b0  Stack Variables: (offset from initial top of stack)
        .text:0x004015b0             4: int arg1
        .text:0x004015b0          -1028: int local1028
        .text:0x004015b0  
        .text:0x004015b0  55               push ebp
        .text:0x004015b1  8bec             mov ebp,esp
        .text:0x004015b3  81ec00040000     sub esp,1024
        .text:0x004015b9  53               push ebx
        .text:0x004015ba  56               push esi
        .text:0x004015bb  57               push edi
        .text:0x004015bc  6800040000       push 1024
        .text:0x004015c1  8d8500fcffff     lea eax,dword [ebp - 1024]
        .text:0x004015c7  50               push eax
        .text:0x004015c8  ff1550b04000     call dword [0x0040b050]    ;kernel32.GetSystemDirectoryA(local1028,1024)
        .text:0x004015ce  85c0             test eax,eax
        .text:0x004015d0  7507             jnz 0x004015d9
        .text:0x004015d2  b801000000       mov eax,1
        .text:0x004015d7  eb54             jmp 0x0040162d
        .text:0x004015d9  loc_004015d9: [1 XREFS]
        .text:0x004015d9  bf58c04000       mov edi,0x0040c058
        .text:0x004015de  8d9500fcffff     lea edx,dword [ebp - 1024]
        .text:0x004015e4  83c9ff           or ecx,0xffffffff
        .text:0x004015e7  33c0             xor eax,eax
        .text:0x004015e9  f2ae             repnz: scasb 
        .text:0x004015eb  f7d1             not ecx
        .text:0x004015ed  2bf9             sub edi,ecx
        .text:0x004015ef  8bf7             mov esi,edi
        .text:0x004015f1  8bd9             mov ebx,ecx
        .text:0x004015f3  8bfa             mov edi,edx
        .text:0x004015f5  83c9ff           or ecx,0xffffffff
        .text:0x004015f8  33c0             xor eax,eax
        .text:0x004015fa  f2ae             repnz: scasb 
        .text:0x004015fc  83c7ff           add edi,0xffffffff
        .text:0x004015ff  8bcb             mov ecx,ebx
        .text:0x00401601  c1e902           shr ecx,2
        .text:0x00401604  f3a5             rep: movsd 
        .text:0x00401606  8bcb             mov ecx,ebx
        .text:0x00401608  83e103           and ecx,3
        .text:0x0040160b  f3a4             rep: movsb 
        .text:0x0040160d  8d8500fcffff     lea eax,dword [ebp - 1024]
        .text:0x00401613  50               push eax
        .text:0x00401614  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00401617  51               push ecx
        .text:0x00401618  e8c3feffff       call 0x004014e0    ;sub_004014e0(arg1,local1028)
        .text:0x0040161d  83c408           add esp,8
        .text:0x00401620  85c0             test eax,eax
        .text:0x00401622  7407             jz 0x0040162b
        .text:0x00401624  b801000000       mov eax,1
        .text:0x00401629  eb02             jmp 0x0040162d
        .text:0x0040162b  loc_0040162b: [1 XREFS]
        .text:0x0040162b  33c0             xor eax,eax
        .text:0x0040162d  loc_0040162d: [2 XREFS]
        .text:0x0040162d  5f               pop edi
        .text:0x0040162e  5e               pop esi
        .text:0x0040162f  5b               pop ebx
        .text:0x00401630  8be5             mov esp,ebp
        .text:0x00401632  5d               pop ebp
        .text:0x00401633  c3               ret 
        */
        $c55 = { 55 8B EC 81 EC 00 04 00 00 53 56 57 68 00 04 00 00 8D 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 75 ?? B8 01 00 00 00 EB ?? BF 58 C0 40 00 8D 95 ?? ?? ?? ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF 33 C0 F2 AE 83 C7 FF 8B CB C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 8D 85 ?? ?? ?? ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 08 85 C0 74 ?? B8 01 00 00 00 EB ?? 33 C0 5F 5E 5B 8B E5 5D C3 }
        /*
function at 0x00401000@b94af4a4d4af6eac81fc135abda1c40c with 1 features:
          - query or enumerate registry value
        .text:0x00401000  Segment: .text (40960 bytes)
        .text:0x00401000  
        .text:0x00401000  FUNC: int cdecl sub_00401000( ) [2 XREFS] 
        .text:0x00401000  
        .text:0x00401000  Stack Variables: (offset from initial top of stack)
        .text:0x00401000            -8: int local8
        .text:0x00401000           -12: int local12
        .text:0x00401000  
        .text:0x00401000  55               push ebp
        .text:0x00401001  8bec             mov ebp,esp
        .text:0x00401003  83ec08           sub esp,8
        .text:0x00401006  8d45f8           lea eax,dword [ebp - 8]
        .text:0x00401009  50               push eax
        .text:0x0040100a  683f000f00       push 0x000f003f
        .text:0x0040100f  6a00             push 0
        .text:0x00401011  6840c04000       push 0x0040c040
        .text:0x00401016  6802000080       push 0x80000002
        .text:0x0040101b  ff1520b04000     call dword [0x0040b020]    ;advapi32.RegOpenKeyExA(0x80000002,0x0040c040,0,0x000f003f,local12)
        .text:0x00401021  85c0             test eax,eax
        .text:0x00401023  7404             jz 0x00401029
        .text:0x00401025  33c0             xor eax,eax
        .text:0x00401027  eb3d             jmp 0x00401066
        .text:0x00401029  loc_00401029: [1 XREFS]
        .text:0x00401029  6a00             push 0
        .text:0x0040102b  6a00             push 0
        .text:0x0040102d  6a00             push 0
        .text:0x0040102f  6a00             push 0
        .text:0x00401031  6830c04000       push 0x0040c030
        .text:0x00401036  8b4df8           mov ecx,dword [ebp - 8]
        .text:0x00401039  51               push ecx
        .text:0x0040103a  ff1524b04000     call dword [0x0040b024]    ;advapi32.RegQueryValueExA(0xfefefefe,0x0040c030,0,0,0,0)
        .text:0x00401040  8945fc           mov dword [ebp - 4],eax
        .text:0x00401043  837dfc00         cmp dword [ebp - 4],0
        .text:0x00401047  740e             jz 0x00401057
        .text:0x00401049  8b55f8           mov edx,dword [ebp - 8]
        .text:0x0040104c  52               push edx
        .text:0x0040104d  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x00401053  33c0             xor eax,eax
        .text:0x00401055  eb0f             jmp 0x00401066
        .text:0x00401057  loc_00401057: [1 XREFS]
        .text:0x00401057  8b45f8           mov eax,dword [ebp - 8]
        .text:0x0040105a  50               push eax
        .text:0x0040105b  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x00401061  b801000000       mov eax,1
        .text:0x00401066  loc_00401066: [2 XREFS]
        .text:0x00401066  8be5             mov esp,ebp
        .text:0x00401068  5d               pop ebp
        .text:0x00401069  c3               ret 
        */
        $c56 = { 55 8B EC 83 EC 08 8D 45 ?? 50 68 3F 00 0F 00 6A 00 68 40 C0 40 00 68 02 00 00 80 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 33 C0 EB ?? 6A 00 6A 00 6A 00 6A 00 68 30 C0 40 00 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 00 74 ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? 33 C0 EB ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? B8 01 00 00 00 8B E5 5D C3 }
        /*
function at 0x00401280@b94af4a4d4af6eac81fc135abda1c40c with 1 features:
          - query or enumerate registry value
        .text:0x00401280  
        .text:0x00401280  FUNC: int cdecl sub_00401280( int arg0, int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, ) [8 XREFS] 
        .text:0x00401280  
        .text:0x00401280  Stack Variables: (offset from initial top of stack)
        .text:0x00401280            28: int arg6
        .text:0x00401280            24: int arg5
        .text:0x00401280            20: int arg4
        .text:0x00401280            16: int arg3
        .text:0x00401280            12: int arg2
        .text:0x00401280             8: int arg1
        .text:0x00401280             4: int arg0
        .text:0x00401280            -8: int local8
        .text:0x00401280           -12: int local12
        .text:0x00401280          -4108: int local4108
        .text:0x00401280          -4112: int local4112
        .text:0x00401280          -4116: int local4116
        .text:0x00401280  
        .text:0x00401280  55               push ebp
        .text:0x00401281  8bec             mov ebp,esp
        .text:0x00401283  b810100000       mov eax,0x00001010
        .text:0x00401288  e8231c0000       call 0x00402eb0    ;__alloca_probe()
        .text:0x0040128d  56               push esi
        .text:0x0040128e  57               push edi
        .text:0x0040128f  c745f801100000   mov dword [ebp - 8],0x00001001
        .text:0x00401296  8d85f0efffff     lea eax,dword [ebp - 4112]
        .text:0x0040129c  50               push eax
        .text:0x0040129d  683f000f00       push 0x000f003f
        .text:0x004012a2  6a00             push 0
        .text:0x004012a4  6840c04000       push 0x0040c040
        .text:0x004012a9  6802000080       push 0x80000002
        .text:0x004012ae  ff1520b04000     call dword [0x0040b020]    ;advapi32.RegOpenKeyExA(0x80000002,0x0040c040,0,0x000f003f,local4116)
        .text:0x004012b4  85c0             test eax,eax
        .text:0x004012b6  740a             jz 0x004012c2
        .text:0x004012b8  b801000000       mov eax,1
        .text:0x004012bd  e94f010000       jmp 0x00401411
        .text:0x004012c2  loc_004012c2: [1 XREFS]
        .text:0x004012c2  8d4df8           lea ecx,dword [ebp - 8]
        .text:0x004012c5  51               push ecx
        .text:0x004012c6  8d95f8efffff     lea edx,dword [ebp - 4104]
        .text:0x004012cc  52               push edx
        .text:0x004012cd  6a00             push 0
        .text:0x004012cf  6a00             push 0
        .text:0x004012d1  6830c04000       push 0x0040c030
        .text:0x004012d6  8b85f0efffff     mov eax,dword [ebp - 4112]
        .text:0x004012dc  50               push eax
        .text:0x004012dd  ff1524b04000     call dword [0x0040b024]    ;advapi32.RegQueryValueExA(0xfefefefe,0x0040c030,0,0,local4108,local12)
        .text:0x004012e3  8985f4efffff     mov dword [ebp - 4108],eax
        .text:0x004012e9  83bdf4efffff00   cmp dword [ebp - 4108],0
        .text:0x004012f0  7417             jz 0x00401309
        .text:0x004012f2  8b8df0efffff     mov ecx,dword [ebp - 4112]
        .text:0x004012f8  51               push ecx
        .text:0x004012f9  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x004012ff  b801000000       mov eax,1
        .text:0x00401304  e908010000       jmp 0x00401411
        .text:0x00401309  loc_00401309: [1 XREFS]
        .text:0x00401309  8d95f8efffff     lea edx,dword [ebp - 4104]
        .text:0x0040130f  8955fc           mov dword [ebp - 4],edx
        .text:0x00401312  8b7dfc           mov edi,dword [ebp - 4]
        .text:0x00401315  8b5508           mov edx,dword [ebp + 8]
        .text:0x00401318  83c9ff           or ecx,0xffffffff
        .text:0x0040131b  33c0             xor eax,eax
        .text:0x0040131d  f2ae             repnz: scasb 
        .text:0x0040131f  f7d1             not ecx
        .text:0x00401321  2bf9             sub edi,ecx
        .text:0x00401323  8bf7             mov esi,edi
        .text:0x00401325  8bc1             mov eax,ecx
        .text:0x00401327  8bfa             mov edi,edx
        .text:0x00401329  c1e902           shr ecx,2
        .text:0x0040132c  f3a5             rep: movsd 
        .text:0x0040132e  8bc8             mov ecx,eax
        .text:0x00401330  83e103           and ecx,3
        .text:0x00401333  f3a4             rep: movsb 
        .text:0x00401335  8b7d08           mov edi,dword [ebp + 8]
        .text:0x00401338  83c9ff           or ecx,0xffffffff
        .text:0x0040133b  33c0             xor eax,eax
        .text:0x0040133d  f2ae             repnz: scasb 
        .text:0x0040133f  f7d1             not ecx
        .text:0x00401341  83c1ff           add ecx,0xffffffff
        .text:0x00401344  8b55fc           mov edx,dword [ebp - 4]
        .text:0x00401347  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x0040134b  8945fc           mov dword [ebp - 4],eax
        .text:0x0040134e  8b7dfc           mov edi,dword [ebp - 4]
        .text:0x00401351  8b5510           mov edx,dword [ebp + 16]
        .text:0x00401354  83c9ff           or ecx,0xffffffff
        .text:0x00401357  33c0             xor eax,eax
        .text:0x00401359  f2ae             repnz: scasb 
        .text:0x0040135b  f7d1             not ecx
        .text:0x0040135d  2bf9             sub edi,ecx
        .text:0x0040135f  8bf7             mov esi,edi
        .text:0x00401361  8bc1             mov eax,ecx
        .text:0x00401363  8bfa             mov edi,edx
        .text:0x00401365  c1e902           shr ecx,2
        .text:0x00401368  f3a5             rep: movsd 
        .text:0x0040136a  8bc8             mov ecx,eax
        .text:0x0040136c  83e103           and ecx,3
        .text:0x0040136f  f3a4             rep: movsb 
        .text:0x00401371  8b7d10           mov edi,dword [ebp + 16]
        .text:0x00401374  83c9ff           or ecx,0xffffffff
        .text:0x00401377  33c0             xor eax,eax
        .text:0x00401379  f2ae             repnz: scasb 
        .text:0x0040137b  f7d1             not ecx
        .text:0x0040137d  83c1ff           add ecx,0xffffffff
        .text:0x00401380  8b55fc           mov edx,dword [ebp - 4]
        .text:0x00401383  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x00401387  8945fc           mov dword [ebp - 4],eax
        .text:0x0040138a  8b7dfc           mov edi,dword [ebp - 4]
        .text:0x0040138d  8b5518           mov edx,dword [ebp + 24]
        .text:0x00401390  83c9ff           or ecx,0xffffffff
        .text:0x00401393  33c0             xor eax,eax
        .text:0x00401395  f2ae             repnz: scasb 
        .text:0x00401397  f7d1             not ecx
        .text:0x00401399  2bf9             sub edi,ecx
        .text:0x0040139b  8bf7             mov esi,edi
        .text:0x0040139d  8bc1             mov eax,ecx
        .text:0x0040139f  8bfa             mov edi,edx
        .text:0x004013a1  c1e902           shr ecx,2
        .text:0x004013a4  f3a5             rep: movsd 
        .text:0x004013a6  8bc8             mov ecx,eax
        .text:0x004013a8  83e103           and ecx,3
        .text:0x004013ab  f3a4             rep: movsb 
        .text:0x004013ad  8b7d18           mov edi,dword [ebp + 24]
        .text:0x004013b0  83c9ff           or ecx,0xffffffff
        .text:0x004013b3  33c0             xor eax,eax
        .text:0x004013b5  f2ae             repnz: scasb 
        .text:0x004013b7  f7d1             not ecx
        .text:0x004013b9  83c1ff           add ecx,0xffffffff
        .text:0x004013bc  8b55fc           mov edx,dword [ebp - 4]
        .text:0x004013bf  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x004013c3  8945fc           mov dword [ebp - 4],eax
        .text:0x004013c6  8b7dfc           mov edi,dword [ebp - 4]
        .text:0x004013c9  8b5520           mov edx,dword [ebp + 32]
        .text:0x004013cc  83c9ff           or ecx,0xffffffff
        .text:0x004013cf  33c0             xor eax,eax
        .text:0x004013d1  f2ae             repnz: scasb 
        .text:0x004013d3  f7d1             not ecx
        .text:0x004013d5  2bf9             sub edi,ecx
        .text:0x004013d7  8bf7             mov esi,edi
        .text:0x004013d9  8bc1             mov eax,ecx
        .text:0x004013db  8bfa             mov edi,edx
        .text:0x004013dd  c1e902           shr ecx,2
        .text:0x004013e0  f3a5             rep: movsd 
        .text:0x004013e2  8bc8             mov ecx,eax
        .text:0x004013e4  83e103           and ecx,3
        .text:0x004013e7  f3a4             rep: movsb 
        .text:0x004013e9  8b7d20           mov edi,dword [ebp + 32]
        .text:0x004013ec  83c9ff           or ecx,0xffffffff
        .text:0x004013ef  33c0             xor eax,eax
        .text:0x004013f1  f2ae             repnz: scasb 
        .text:0x004013f3  f7d1             not ecx
        .text:0x004013f5  83c1ff           add ecx,0xffffffff
        .text:0x004013f8  8b55fc           mov edx,dword [ebp - 4]
        .text:0x004013fb  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x004013ff  8945fc           mov dword [ebp - 4],eax
        .text:0x00401402  8b8df0efffff     mov ecx,dword [ebp - 4112]
        .text:0x00401408  51               push ecx
        .text:0x00401409  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x0040140f  33c0             xor eax,eax
        .text:0x00401411  loc_00401411: [2 XREFS]
        .text:0x00401411  5f               pop edi
        .text:0x00401412  5e               pop esi
        .text:0x00401413  8be5             mov esp,ebp
        .text:0x00401415  5d               pop ebp
        .text:0x00401416  c3               ret 
        */
        $c57 = { 55 8B EC B8 10 10 00 00 E8 ?? ?? ?? ?? 56 57 C7 45 ?? 01 10 00 00 8D 85 ?? ?? ?? ?? 50 68 3F 00 0F 00 6A 00 68 40 C0 40 00 68 02 00 00 80 FF 15 ?? ?? ?? ?? 85 C0 74 ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8D 4D ?? 51 8D 95 ?? ?? ?? ?? 52 6A 00 6A 00 68 30 C0 40 00 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 83 BD ?? ?? ?? ?? 00 74 ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? B8 01 00 00 00 E9 ?? ?? ?? ?? 8D 95 ?? ?? ?? ?? 89 55 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? 33 C0 5F 5E 8B E5 5D C3 }
        /*
function at 0x00401070@b94af4a4d4af6eac81fc135abda1c40c with 1 features:
          - set registry value
        .text:0x00401070  
        .text:0x00401070  FUNC: int cdecl sub_00401070( int arg0, int arg1, int arg2, int arg3, ) [6 XREFS] 
        .text:0x00401070  
        .text:0x00401070  Stack Variables: (offset from initial top of stack)
        .text:0x00401070            16: int arg3
        .text:0x00401070            12: int arg2
        .text:0x00401070             8: int arg1
        .text:0x00401070             4: int arg0
        .text:0x00401070            -8: int local8
        .text:0x00401070          -4108: int local4108
        .text:0x00401070          -4112: int local4112
        .text:0x00401070  
        .text:0x00401070  55               push ebp
        .text:0x00401071  8bec             mov ebp,esp
        .text:0x00401073  b80c100000       mov eax,0x0000100c
        .text:0x00401078  e8331e0000       call 0x00402eb0    ;__alloca_probe()
        .text:0x0040107d  56               push esi
        .text:0x0040107e  57               push edi
        .text:0x0040107f  b900040000       mov ecx,1024
        .text:0x00401084  33c0             xor eax,eax
        .text:0x00401086  8dbdf8efffff     lea edi,dword [ebp - 4104]
        .text:0x0040108c  f3ab             rep: stosd 
        .text:0x0040108e  aa               stosb 
        .text:0x0040108f  8d85f8efffff     lea eax,dword [ebp - 4104]
        .text:0x00401095  8945fc           mov dword [ebp - 4],eax
        .text:0x00401098  8b7d08           mov edi,dword [ebp + 8]
        .text:0x0040109b  8b55fc           mov edx,dword [ebp - 4]
        .text:0x0040109e  83c9ff           or ecx,0xffffffff
        .text:0x004010a1  33c0             xor eax,eax
        .text:0x004010a3  f2ae             repnz: scasb 
        .text:0x004010a5  f7d1             not ecx
        .text:0x004010a7  2bf9             sub edi,ecx
        .text:0x004010a9  8bf7             mov esi,edi
        .text:0x004010ab  8bc1             mov eax,ecx
        .text:0x004010ad  8bfa             mov edi,edx
        .text:0x004010af  c1e902           shr ecx,2
        .text:0x004010b2  f3a5             rep: movsd 
        .text:0x004010b4  8bc8             mov ecx,eax
        .text:0x004010b6  83e103           and ecx,3
        .text:0x004010b9  f3a4             rep: movsb 
        .text:0x004010bb  8b7d08           mov edi,dword [ebp + 8]
        .text:0x004010be  83c9ff           or ecx,0xffffffff
        .text:0x004010c1  33c0             xor eax,eax
        .text:0x004010c3  f2ae             repnz: scasb 
        .text:0x004010c5  f7d1             not ecx
        .text:0x004010c7  83c1ff           add ecx,0xffffffff
        .text:0x004010ca  8b55fc           mov edx,dword [ebp - 4]
        .text:0x004010cd  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x004010d1  8945fc           mov dword [ebp - 4],eax
        .text:0x004010d4  8b7d0c           mov edi,dword [ebp + 12]
        .text:0x004010d7  8b55fc           mov edx,dword [ebp - 4]
        .text:0x004010da  83c9ff           or ecx,0xffffffff
        .text:0x004010dd  33c0             xor eax,eax
        .text:0x004010df  f2ae             repnz: scasb 
        .text:0x004010e1  f7d1             not ecx
        .text:0x004010e3  2bf9             sub edi,ecx
        .text:0x004010e5  8bf7             mov esi,edi
        .text:0x004010e7  8bc1             mov eax,ecx
        .text:0x004010e9  8bfa             mov edi,edx
        .text:0x004010eb  c1e902           shr ecx,2
        .text:0x004010ee  f3a5             rep: movsd 
        .text:0x004010f0  8bc8             mov ecx,eax
        .text:0x004010f2  83e103           and ecx,3
        .text:0x004010f5  f3a4             rep: movsb 
        .text:0x004010f7  8b7d0c           mov edi,dword [ebp + 12]
        .text:0x004010fa  83c9ff           or ecx,0xffffffff
        .text:0x004010fd  33c0             xor eax,eax
        .text:0x004010ff  f2ae             repnz: scasb 
        .text:0x00401101  f7d1             not ecx
        .text:0x00401103  83c1ff           add ecx,0xffffffff
        .text:0x00401106  8b55fc           mov edx,dword [ebp - 4]
        .text:0x00401109  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x0040110d  8945fc           mov dword [ebp - 4],eax
        .text:0x00401110  8b7d10           mov edi,dword [ebp + 16]
        .text:0x00401113  8b55fc           mov edx,dword [ebp - 4]
        .text:0x00401116  83c9ff           or ecx,0xffffffff
        .text:0x00401119  33c0             xor eax,eax
        .text:0x0040111b  f2ae             repnz: scasb 
        .text:0x0040111d  f7d1             not ecx
        .text:0x0040111f  2bf9             sub edi,ecx
        .text:0x00401121  8bf7             mov esi,edi
        .text:0x00401123  8bc1             mov eax,ecx
        .text:0x00401125  8bfa             mov edi,edx
        .text:0x00401127  c1e902           shr ecx,2
        .text:0x0040112a  f3a5             rep: movsd 
        .text:0x0040112c  8bc8             mov ecx,eax
        .text:0x0040112e  83e103           and ecx,3
        .text:0x00401131  f3a4             rep: movsb 
        .text:0x00401133  8b7d10           mov edi,dword [ebp + 16]
        .text:0x00401136  83c9ff           or ecx,0xffffffff
        .text:0x00401139  33c0             xor eax,eax
        .text:0x0040113b  f2ae             repnz: scasb 
        .text:0x0040113d  f7d1             not ecx
        .text:0x0040113f  83c1ff           add ecx,0xffffffff
        .text:0x00401142  8b55fc           mov edx,dword [ebp - 4]
        .text:0x00401145  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x00401149  8945fc           mov dword [ebp - 4],eax
        .text:0x0040114c  8b7d14           mov edi,dword [ebp + 20]
        .text:0x0040114f  8b55fc           mov edx,dword [ebp - 4]
        .text:0x00401152  83c9ff           or ecx,0xffffffff
        .text:0x00401155  33c0             xor eax,eax
        .text:0x00401157  f2ae             repnz: scasb 
        .text:0x00401159  f7d1             not ecx
        .text:0x0040115b  2bf9             sub edi,ecx
        .text:0x0040115d  8bf7             mov esi,edi
        .text:0x0040115f  8bc1             mov eax,ecx
        .text:0x00401161  8bfa             mov edi,edx
        .text:0x00401163  c1e902           shr ecx,2
        .text:0x00401166  f3a5             rep: movsd 
        .text:0x00401168  8bc8             mov ecx,eax
        .text:0x0040116a  83e103           and ecx,3
        .text:0x0040116d  f3a4             rep: movsb 
        .text:0x0040116f  8b7d14           mov edi,dword [ebp + 20]
        .text:0x00401172  83c9ff           or ecx,0xffffffff
        .text:0x00401175  33c0             xor eax,eax
        .text:0x00401177  f2ae             repnz: scasb 
        .text:0x00401179  f7d1             not ecx
        .text:0x0040117b  83c1ff           add ecx,0xffffffff
        .text:0x0040117e  8b55fc           mov edx,dword [ebp - 4]
        .text:0x00401181  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x00401185  8945fc           mov dword [ebp - 4],eax
        .text:0x00401188  6a00             push 0
        .text:0x0040118a  8d8df4efffff     lea ecx,dword [ebp - 4108]
        .text:0x00401190  51               push ecx
        .text:0x00401191  6a00             push 0
        .text:0x00401193  683f000f00       push 0x000f003f
        .text:0x00401198  6a00             push 0
        .text:0x0040119a  6a00             push 0
        .text:0x0040119c  6a00             push 0
        .text:0x0040119e  6840c04000       push 0x0040c040
        .text:0x004011a3  6802000080       push 0x80000002
        .text:0x004011a8  ff1518b04000     call dword [0x0040b018]    ;advapi32.RegCreateKeyExA(0x80000002,0x0040c040,0,0,0,0x000f003f,0,local4112,0)
        .text:0x004011ae  85c0             test eax,eax
        .text:0x004011b0  7407             jz 0x004011b9
        .text:0x004011b2  b801000000       mov eax,1
        .text:0x004011b7  eb49             jmp 0x00401202
        .text:0x004011b9  loc_004011b9: [1 XREFS]
        .text:0x004011b9  6800100000       push 0x00001000
        .text:0x004011be  8d95f8efffff     lea edx,dword [ebp - 4104]
        .text:0x004011c4  52               push edx
        .text:0x004011c5  6a03             push 3
        .text:0x004011c7  6a00             push 0
        .text:0x004011c9  6830c04000       push 0x0040c030
        .text:0x004011ce  8b85f4efffff     mov eax,dword [ebp - 4108]
        .text:0x004011d4  50               push eax
        .text:0x004011d5  ff151cb04000     call dword [0x0040b01c]    ;advapi32.RegSetValueExA(0xfefefefe,0x0040c030,0,3,local4108,0x00001000)
        .text:0x004011db  85c0             test eax,eax
        .text:0x004011dd  7414             jz 0x004011f3
        .text:0x004011df  8b8df4efffff     mov ecx,dword [ebp - 4108]
        .text:0x004011e5  51               push ecx
        .text:0x004011e6  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x004011ec  b801000000       mov eax,1
        .text:0x004011f1  eb0f             jmp 0x00401202
        .text:0x004011f3  loc_004011f3: [1 XREFS]
        .text:0x004011f3  8b95f4efffff     mov edx,dword [ebp - 4108]
        .text:0x004011f9  52               push edx
        .text:0x004011fa  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x00401200  33c0             xor eax,eax
        .text:0x00401202  loc_00401202: [2 XREFS]
        .text:0x00401202  5f               pop edi
        .text:0x00401203  5e               pop esi
        .text:0x00401204  8be5             mov esp,ebp
        .text:0x00401206  5d               pop ebp
        .text:0x00401207  c3               ret 
        */
        $c58 = { 55 8B EC B8 0C 10 00 00 E8 ?? ?? ?? ?? 56 57 B9 00 04 00 00 33 C0 8D BD ?? ?? ?? ?? F3 AB AA 8D 85 ?? ?? ?? ?? 89 45 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 8B 7D ?? 8B 55 ?? 83 C9 FF 33 C0 F2 AE F7 D1 2B F9 8B F7 8B C1 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 7D ?? 83 C9 FF 33 C0 F2 AE F7 D1 83 C1 FF 8B 55 ?? 8D 44 0A ?? 89 45 ?? 6A 00 8D 8D ?? ?? ?? ?? 51 6A 00 68 3F 00 0F 00 6A 00 6A 00 6A 00 68 40 C0 40 00 68 02 00 00 80 FF 15 ?? ?? ?? ?? 85 C0 74 ?? B8 01 00 00 00 EB ?? 68 00 10 00 00 8D 95 ?? ?? ?? ?? 52 6A 03 6A 00 68 30 C0 40 00 8B 85 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 85 C0 74 ?? 8B 8D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 8B 95 ?? ?? ?? ?? 52 FF 15 ?? ?? ?? ?? 33 C0 5F 5E 8B E5 5D C3 }
        /*
function at 0x00401210@b94af4a4d4af6eac81fc135abda1c40c with 1 features:
          - delete registry value
        .text:0x00401210  
        .text:0x00401210  FUNC: int cdecl sub_00401210( ) [2 XREFS] 
        .text:0x00401210  
        .text:0x00401210  Stack Variables: (offset from initial top of stack)
        .text:0x00401210            -8: int local8
        .text:0x00401210           -12: int local12
        .text:0x00401210  
        .text:0x00401210  55               push ebp
        .text:0x00401211  8bec             mov ebp,esp
        .text:0x00401213  83ec08           sub esp,8
        .text:0x00401216  6a00             push 0
        .text:0x00401218  8d45f8           lea eax,dword [ebp - 8]
        .text:0x0040121b  50               push eax
        .text:0x0040121c  6a00             push 0
        .text:0x0040121e  683f000f00       push 0x000f003f
        .text:0x00401223  6a00             push 0
        .text:0x00401225  6a00             push 0
        .text:0x00401227  6a00             push 0
        .text:0x00401229  6840c04000       push 0x0040c040
        .text:0x0040122e  6802000080       push 0x80000002
        .text:0x00401233  ff1518b04000     call dword [0x0040b018]    ;advapi32.RegCreateKeyExA(0x80000002,0x0040c040,0,0,0,0x000f003f,0,local12,0)
        .text:0x00401239  85c0             test eax,eax
        .text:0x0040123b  7407             jz 0x00401244
        .text:0x0040123d  b801000000       mov eax,1
        .text:0x00401242  eb35             jmp 0x00401279
        .text:0x00401244  loc_00401244: [1 XREFS]
        .text:0x00401244  6830c04000       push 0x0040c030
        .text:0x00401249  8b4df8           mov ecx,dword [ebp - 8]
        .text:0x0040124c  51               push ecx
        .text:0x0040124d  ff1514b04000     call dword [0x0040b014]    ;advapi32.RegDeleteValueA(0xfefefefe,0x0040c030)
        .text:0x00401253  8945fc           mov dword [ebp - 4],eax
        .text:0x00401256  837dfc00         cmp dword [ebp - 4],0
        .text:0x0040125a  7411             jz 0x0040126d
        .text:0x0040125c  8b55f8           mov edx,dword [ebp - 8]
        .text:0x0040125f  52               push edx
        .text:0x00401260  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x00401266  b801000000       mov eax,1
        .text:0x0040126b  eb0c             jmp 0x00401279
        .text:0x0040126d  loc_0040126d: [1 XREFS]
        .text:0x0040126d  8b45f8           mov eax,dword [ebp - 8]
        .text:0x00401270  50               push eax
        .text:0x00401271  ff1564b04000     call dword [0x0040b064]    ;kernel32.CloseHandle(0xfefefefe)
        .text:0x00401277  33c0             xor eax,eax
        .text:0x00401279  loc_00401279: [2 XREFS]
        .text:0x00401279  8be5             mov esp,ebp
        .text:0x0040127b  5d               pop ebp
        .text:0x0040127c  c3               ret 
        */
        $c59 = { 55 8B EC 83 EC 08 6A 00 8D 45 ?? 50 6A 00 68 3F 00 0F 00 6A 00 6A 00 6A 00 68 40 C0 40 00 68 02 00 00 80 FF 15 ?? ?? ?? ?? 85 C0 74 ?? B8 01 00 00 00 EB ?? 68 30 C0 40 00 8B 4D ?? 51 FF 15 ?? ?? ?? ?? 89 45 ?? 83 7D ?? 00 74 ?? 8B 55 ?? 52 FF 15 ?? ?? ?? ?? B8 01 00 00 00 EB ?? 8B 45 ?? 50 FF 15 ?? ?? ?? ?? 33 C0 8B E5 5D C3 }
    condition:
        all of them
}

rule super_rule_7faaf_b94af
{
    meta:
        author = "CAPA Matches"
        date_created = "EXPECTED_DATE"
        date_modified = "EXPECTED_DATE"
        description = ""
        md5 = "7faafc7e4a5c736ebfee6abbbc812d80"
        md5 = "b94af4a4d4af6eac81fc135abda1c40c"
    strings:
        /*
Basic Block at 0x00401b83@7faafc7e4a5c736ebfee6abbbc812d80 with 1 features:
          - create TCP socket
        .text:0x00401b83  loc_00401b83: [1 XREFS]
        .text:0x00401b83  6a06             push 6
        .text:0x00401b85  6a01             push 1
        .text:0x00401b87  6a02             push 2
        .text:0x00401b89  ff1550b14000     call dword [0x0040b150]    ;ws2_32.socket(2,1,6)
        .text:0x00401b8f  8b4d08           mov ecx,dword [ebp + 8]
        .text:0x00401b92  8901             mov dword [ecx],eax
        .text:0x00401b94  8b5508           mov edx,dword [ebp + 8]
        .text:0x00401b97  833aff           cmp dword [edx],0xffffffff
        .text:0x00401b9a  750d             jnz 0x00401ba9
        */
        $c60 = { 6A 06 6A 01 6A 02 FF 15 ?? ?? ?? ?? 8B 4D ?? 89 01 8B 55 ?? 83 3A FF 75 ?? }
    condition:
        all of them
}

rule super_rule_18ec5_7faaf_b94af
{
    meta:
        author = "CAPA Matches"
        date_created = "EXPECTED_DATE"
        date_modified = "EXPECTED_DATE"
        description = ""
        md5 = "18ec5becfa3991fb654e105bafbd5a4b"
        md5 = "7faafc7e4a5c736ebfee6abbbc812d80"
        md5 = "b94af4a4d4af6eac81fc135abda1c40c"
    strings:
        /*
Basic Block at 0x00401a96@18ec5becfa3991fb654e105bafbd5a4b with 1 features:
          - get file attributes
        .text:0x00401a96  
        .text:0x00401a96  FUNC: int cdecl sub_00401a96( int arg0, int arg1, ) [6 XREFS] 
        .text:0x00401a96  
        .text:0x00401a96  Stack Variables: (offset from initial top of stack)
        .text:0x00401a96             8: int arg1
        .text:0x00401a96             4: int arg0
        .text:0x00401a96  
        .text:0x00401a96  ff742404         push dword [esp + 4]
        .text:0x00401a9a  ff1538804000     call dword [0x00408038]    ;kernel32.GetFileAttributesA(arg0)
        .text:0x00401aa0  83f8ff           cmp eax,0xffffffff
        .text:0x00401aa3  7511             jnz 0x00401ab6
        */
        $c61 = { FF 74 24 ?? FF 15 ?? ?? ?? ?? 83 F8 FF 75 ?? }
        /*
function at 0x00401a96@18ec5becfa3991fb654e105bafbd5a4b with 1 features:
          - check if file exists
        .text:0x00401a96  
        .text:0x00401a96  FUNC: int cdecl sub_00401a96( int arg0, int arg1, ) [6 XREFS] 
        .text:0x00401a96  
        .text:0x00401a96  Stack Variables: (offset from initial top of stack)
        .text:0x00401a96             8: int arg1
        .text:0x00401a96             4: int arg0
        .text:0x00401a96  
        .text:0x00401a96  ff742404         push dword [esp + 4]
        .text:0x00401a9a  ff1538804000     call dword [0x00408038]    ;kernel32.GetFileAttributesA(arg0)
        .text:0x00401aa0  83f8ff           cmp eax,0xffffffff
        .text:0x00401aa3  7511             jnz 0x00401ab6
        .text:0x00401aa5  ff1534804000     call dword [0x00408034]    ;ntdll.RtlGetLastWin32Error()
        .text:0x00401aab  50               push eax
        .text:0x00401aac  e806210000       call 0x00403bb7    ;__dosmaperr(kernel32.GetLastError())
        .text:0x00401ab1  59               pop ecx
        .text:0x00401ab2  loc_00401ab2: [1 XREFS]
        .text:0x00401ab2  83c8ff           or eax,0xffffffff
        .text:0x00401ab5  c3               ret 
        .text:0x00401ab6  loc_00401ab6: [1 XREFS]
        .text:0x00401ab6  a801             test al,1
        .text:0x00401ab8  741d             jz 0x00401ad7
        .text:0x00401aba  f644240802       test byte [esp + 8],2
        .text:0x00401abf  7416             jz 0x00401ad7
        .text:0x00401ac1  c705c0ba40000d00 mov dword [0x0040bac0],13
        .text:0x00401acb  c705c4ba40000500 mov dword [0x0040bac4],5
        .text:0x00401ad5  ebdb             jmp 0x00401ab2
        .text:0x00401ad7  loc_00401ad7: [2 XREFS]
        .text:0x00401ad7  33c0             xor eax,eax
        .text:0x00401ad9  c3               ret 
        */
        $c62 = { FF 74 24 ?? FF 15 ?? ?? ?? ?? 83 F8 FF 75 ?? FF 15 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 59 83 C8 FF C3 A8 01 74 ?? F6 44 24 ?? 02 74 ?? C7 05 ?? ?? ?? ?? 0D 00 00 00 C7 05 ?? ?? ?? ?? 05 00 00 00 EB ?? 33 C0 C3 }
    condition:
        all of them
}

