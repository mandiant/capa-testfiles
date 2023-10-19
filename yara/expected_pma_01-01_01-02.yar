rule super_rule_bb742
{
    meta:
        author = "CAPA Matches"
        date_created = "EXPECTED_DATE"
        date_modified = "EXPECTED_DATE"
        description = ""
        md5 = "bb7425b82141a1c0f7d60e5106676bb1"
    strings:
        /*
function at 0x00401440@bb7425b82141a1c0f7d60e5106676bb1 with 3 features:
          - copy file
          - read file via mapping
          - resolve function by parsing PE exports
        .text:0x00401440  
        .text:0x00401440  FUNC: int cdecl sub_00401440( int arg0, int arg1, ) [2 XREFS] 
        .text:0x00401440  
        .text:0x00401440  Stack Variables: (offset from initial top of stack)
        .text:0x00401440             8: int arg1
        .text:0x00401440             4: int arg0
        .text:0x00401440            -4: int local4
        .text:0x00401440            -8: int local8
        .text:0x00401440           -12: int local12
        .text:0x00401440           -16: int local16
        .text:0x00401440           -20: int local20
        .text:0x00401440           -24: int local24
        .text:0x00401440           -28: int local28
        .text:0x00401440           -32: int local32
        .text:0x00401440           -36: int local36
        .text:0x00401440           -40: int local40
        .text:0x00401440           -44: int local44
        .text:0x00401440           -48: int local48
        .text:0x00401440           -52: int local52
        .text:0x00401440           -56: int local56
        .text:0x00401440           -60: int local60
        .text:0x00401440           -64: int local64
        .text:0x00401440           -68: int local68
        .text:0x00401440  
        .text:0x00401440  8b442404         mov eax,dword [esp + 4]
        .text:0x00401444  83ec44           sub esp,68
        .text:0x00401447  83f802           cmp eax,2
        .text:0x0040144a  53               push ebx
        .text:0x0040144b  55               push ebp
        .text:0x0040144c  56               push esi
        .text:0x0040144d  57               push edi
        .text:0x0040144e  0f85bf030000     jnz 0x00401813
        .text:0x00401454  8b44245c         mov eax,dword [esp + 92]
        .text:0x00401458  beb0304000       mov esi,0x004030b0
        .text:0x0040145d  8b4004           mov eax,dword [eax + 4]
        .text:0x00401460  loc_00401460: [1 XREFS]
        .text:0x00401460  8a10             mov dl,byte [eax]
        .text:0x00401462  8a1e             mov bl,byte [esi]
        .text:0x00401464  8aca             mov cl,dl
        .text:0x00401466  3ad3             cmp dl,bl
        .text:0x00401468  751e             jnz 0x00401488
        .text:0x0040146a  84c9             test cl,cl
        .text:0x0040146c  7416             jz 0x00401484
        .text:0x0040146e  8a5001           mov dl,byte [eax + 1]
        .text:0x00401471  8a5e01           mov bl,byte [esi + 1]
        .text:0x00401474  8aca             mov cl,dl
        .text:0x00401476  3ad3             cmp dl,bl
        .text:0x00401478  750e             jnz 0x00401488
        .text:0x0040147a  83c002           add eax,2
        .text:0x0040147d  83c602           add esi,2
        .text:0x00401480  84c9             test cl,cl
        .text:0x00401482  75dc             jnz 0x00401460
        .text:0x00401484  loc_00401484: [1 XREFS]
        .text:0x00401484  33c0             xor eax,eax
        .text:0x00401486  eb05             jmp 0x0040148d
        .text:0x00401488  loc_00401488: [2 XREFS]
        .text:0x00401488  1bc0             sbb eax,eax
        .text:0x0040148a  83d8ff           sbb eax,0xffffffff
        .text:0x0040148d  loc_0040148d: [1 XREFS]
        .text:0x0040148d  85c0             test eax,eax
        .text:0x0040148f  0f857e030000     jnz 0x00401813
        .text:0x00401495  8b3d14204000     mov edi,dword [0x00402014]
        .text:0x0040149b  50               push eax
        .text:0x0040149c  50               push eax
        .text:0x0040149d  6a03             push 3
        .text:0x0040149f  50               push eax
        .text:0x004014a0  6a01             push 1
        .text:0x004014a2  6800000080       push 0x80000000
        .text:0x004014a7  688c304000       push 0x0040308c
        .text:0x004014ac  ffd7             call edi    ;kernel32.CreateFileA(0x0040308c,0x80000000,1,1,3,1,1)
        .text:0x004014ae  8b1d10204000     mov ebx,dword [0x00402010]
        .text:0x004014b4  6a00             push 0
        .text:0x004014b6  6a00             push 0
        .text:0x004014b8  6a00             push 0
        .text:0x004014ba  6a02             push 2
        .text:0x004014bc  6a00             push 0
        .text:0x004014be  50               push eax
        .text:0x004014bf  89442464         mov dword [esp + 100],eax
        .text:0x004014c3  ffd3             call ebx    ;kernel32.CreateFileMappingA(kernel32.CreateFileA(0x0040308c,0x80000000,1,1,3,1,1),0,2,0,0,0)
        .text:0x004014c5  8b2d0c204000     mov ebp,dword [0x0040200c]
        .text:0x004014cb  6a00             push 0
        .text:0x004014cd  6a00             push 0
        .text:0x004014cf  6a00             push 0
        .text:0x004014d1  6a04             push 4
        .text:0x004014d3  50               push eax
        .text:0x004014d4  ffd5             call ebp    ;kernel32.MapViewOfFile(kernel32.CreateFileMappingA(<0x004014ac>,0,2,0,0,0),4,0,0,0)
        .text:0x004014d6  6a00             push 0
        .text:0x004014d8  6a00             push 0
        .text:0x004014da  6a03             push 3
        .text:0x004014dc  6a00             push 0
        .text:0x004014de  6a01             push 1
        .text:0x004014e0  8bf0             mov esi,eax
        .text:0x004014e2  6800000010       push 0x10000000
        .text:0x004014e7  687c304000       push 0x0040307c
        .text:0x004014ec  89742474         mov dword [esp + 116],esi
        .text:0x004014f0  ffd7             call edi    ;kernel32.CreateFileA(0x0040307c,0x10000000,1,0,3,0,0)
        .text:0x004014f2  83f8ff           cmp eax,0xffffffff
        .text:0x004014f5  89442450         mov dword [esp + 80],eax
        .text:0x004014f9  6a00             push 0
        .text:0x004014fb  7506             jnz 0x00401503
        .text:0x004014fd  ff1530204000     call dword [0x00402030]    ;msvcrt.exit(0)
        .text:0x00401503  loc_00401503: [1 XREFS]
        .text:0x00401503  6a00             push 0
        .text:0x00401505  6a00             push 0
        .text:0x00401507  6a04             push 4
        .text:0x00401509  6a00             push 0
        .text:0x0040150b  50               push eax
        .text:0x0040150c  ffd3             call ebx    ;kernel32.CreateFileMappingA(kernel32.CreateFileA(0x0040307c,0x10000000,1,0,3,0,0),0,4,0,0,0)
        .text:0x0040150e  83f8ff           cmp eax,0xffffffff
        .text:0x00401511  6a00             push 0
        .text:0x00401513  7506             jnz 0x0040151b
        .text:0x00401515  ff1530204000     call dword [0x00402030]    ;msvcrt.exit(0)
        .text:0x0040151b  loc_0040151b: [1 XREFS]
        .text:0x0040151b  6a00             push 0
        .text:0x0040151d  6a00             push 0
        .text:0x0040151f  681f000f00       push 0x000f001f
        .text:0x00401524  50               push eax
        .text:0x00401525  ffd5             call ebp    ;kernel32.MapViewOfFile(kernel32.CreateFileMappingA(<0x004014f0>,0,4,0,0,0),0x000f001f,0,0,0)
        .text:0x00401527  8be8             mov ebp,eax
        .text:0x00401529  85ed             test ebp,ebp
        .text:0x0040152b  896c245c         mov dword [esp + 92],ebp
        .text:0x0040152f  7507             jnz 0x00401538
        .text:0x00401531  50               push eax
        .text:0x00401532  ff1530204000     call dword [0x00402030]    ;msvcrt.exit(<0x00401525>)
        .text:0x00401538  loc_00401538: [1 XREFS]
        .text:0x00401538  8b7e3c           mov edi,dword [esi + 60]
        .text:0x0040153b  56               push esi
        .text:0x0040153c  03fe             add edi,esi
        .text:0x0040153e  57               push edi
        .text:0x0040153f  897c2440         mov dword [esp + 64],edi
        .text:0x00401543  8b4778           mov eax,dword [edi + 120]
        .text:0x00401546  50               push eax
        .text:0x00401547  e8f4faffff       call 0x00401040    ;sub_00401040(0x61616161,0xa2bb7170,kernel32.MapViewOfFile(<0x004014c3>,4,0,0,0))
        .text:0x0040154c  8b753c           mov esi,dword [ebp + 60]
        .text:0x0040154f  55               push ebp
        .text:0x00401550  03f5             add esi,ebp
        .text:0x00401552  8bd8             mov ebx,eax
        .text:0x00401554  56               push esi
        .text:0x00401555  895c2438         mov dword [esp + 56],ebx
        .text:0x00401559  8b4e78           mov ecx,dword [esi + 120]
        .text:0x0040155c  51               push ecx
        .text:0x0040155d  e8defaffff       call 0x00401040    ;sub_00401040(0x61616161,0xa2bbd170,kernel32.MapViewOfFile(<0x0040150c>,0x000f001f,0,0,0))
        .text:0x00401562  8b542470         mov edx,dword [esp + 112]
        .text:0x00401566  8be8             mov ebp,eax
        .text:0x00401568  8b431c           mov eax,dword [ebx + 28]
        .text:0x0040156b  52               push edx
        .text:0x0040156c  57               push edi
        .text:0x0040156d  50               push eax
        .text:0x0040156e  e8cdfaffff       call 0x00401040    ;sub_00401040(0x61616161,0xa2bb7170,<0x004014d4>)
        .text:0x00401573  8b4c247c         mov ecx,dword [esp + 124]
        .text:0x00401577  8b5324           mov edx,dword [ebx + 36]
        .text:0x0040157a  51               push ecx
        .text:0x0040157b  57               push edi
        .text:0x0040157c  52               push edx
        .text:0x0040157d  8944244c         mov dword [esp + 76],eax
        .text:0x00401581  e8bafaffff       call 0x00401040    ;sub_00401040(0x61616161,0xa2bb7170,<0x004014d4>)
        .text:0x00401586  8b4b20           mov ecx,dword [ebx + 32]
        .text:0x00401589  89442464         mov dword [esp + 100],eax
        .text:0x0040158d  8b842488000000   mov eax,dword [esp + 136]
        .text:0x00401594  50               push eax
        .text:0x00401595  57               push edi
        .text:0x00401596  51               push ecx
        .text:0x00401597  e8a4faffff       call 0x00401040    ;sub_00401040(0x61616161,0xa2bb7170,<0x004014d4>)
        .text:0x0040159c  8b942498000000   mov edx,dword [esp + 152]
        .text:0x004015a3  8b7e7c           mov edi,dword [esi + 124]
        .text:0x004015a6  8944246c         mov dword [esp + 108],eax
        .text:0x004015aa  8b4678           mov eax,dword [esi + 120]
        .text:0x004015ad  52               push edx
        .text:0x004015ae  56               push esi
        .text:0x004015af  50               push eax
        .text:0x004015b0  e8bbfaffff       call 0x00401070    ;sub_00401070(0x61616161,0xa2bbd170,<0x00401525>)
        .text:0x004015b5  8bcf             mov ecx,edi
        .text:0x004015b7  8bf3             mov esi,ebx
        .text:0x004015b9  8bd1             mov edx,ecx
        .text:0x004015bb  8bfd             mov edi,ebp
        .text:0x004015bd  c1e902           shr ecx,2
        .text:0x004015c0  f3a5             rep: movsd 
        .text:0x004015c2  8bca             mov ecx,edx
        .text:0x004015c4  83c448           add esp,72
        .text:0x004015c7  83e103           and ecx,3
        .text:0x004015ca  8944243c         mov dword [esp + 60],eax
        .text:0x004015ce  f3a4             rep: movsb 
        .text:0x004015d0  8b4b14           mov ecx,dword [ebx + 20]
        .text:0x004015d3  894d14           mov dword [ebp + 20],ecx
        .text:0x004015d6  8b5318           mov edx,dword [ebx + 24]
        .text:0x004015d9  8d5d28           lea ebx,dword [ebp + 40]
        .text:0x004015dc  895518           mov dword [ebp + 24],edx
        .text:0x004015df  c1e104           shl ecx,4
        .text:0x004015e2  8d1403           lea edx,dword [ebx + eax]
        .text:0x004015e5  89550c           mov dword [ebp + 12],edx
        .text:0x004015e8  8b3510304000     mov esi,dword [0x00403010]
        .text:0x004015ee  8bd3             mov edx,ebx
        .text:0x004015f0  83c310           add ebx,16
        .text:0x004015f3  895c2420         mov dword [esp + 32],ebx
        .text:0x004015f7  8932             mov dword [edx],esi
        .text:0x004015f9  8b3514304000     mov esi,dword [0x00403014]
        .text:0x004015ff  897204           mov dword [edx + 4],esi
        .text:0x00401602  8b3518304000     mov esi,dword [0x00403018]
        .text:0x00401608  897208           mov dword [edx + 8],esi
        .text:0x0040160b  8b351c304000     mov esi,dword [0x0040301c]
        .text:0x00401611  89720c           mov dword [edx + 12],esi
        .text:0x00401614  8b5514           mov edx,dword [ebp + 20]
        .text:0x00401617  8d3493           lea esi,dword [ebx + edx * 4]
        .text:0x0040161a  8d3cd3           lea edi,dword [ebx + edx * 8]
        .text:0x0040161d  89742448         mov dword [esp + 72],esi
        .text:0x00401621  897c2444         mov dword [esp + 68],edi
        .text:0x00401625  8d1403           lea edx,dword [ebx + eax]
        .text:0x00401628  03d9             add ebx,ecx
        .text:0x0040162a  89551c           mov dword [ebp + 28],edx
        .text:0x0040162d  8d1406           lea edx,dword [esi + eax]
        .text:0x00401630  03c7             add eax,edi
        .text:0x00401632  895524           mov dword [ebp + 36],edx
        .text:0x00401635  894520           mov dword [ebp + 32],eax
        .text:0x00401638  8b442424         mov eax,dword [esp + 36]
        .text:0x0040163c  33c9             xor ecx,ecx
        .text:0x0040163e  33d2             xor edx,edx
        .text:0x00401640  8b6814           mov ebp,dword [eax + 20]
        .text:0x00401643  894c245c         mov dword [esp + 92],ecx
        .text:0x00401647  85ed             test ebp,ebp
        .text:0x00401649  8954242c         mov dword [esp + 44],edx
        .text:0x0040164d  0f8681010000     jbe 0x004017d4
        .text:0x00401653  loc_00401653: [1 XREFS]
        .text:0x00401653  8b6c241c         mov ebp,dword [esp + 28]
        .text:0x00401657  837d0000         cmp dword [ebp],0
        .text:0x0040165b  0f8458010000     jz 0x004017b9
        .text:0x00401661  8b6818           mov ebp,dword [eax + 24]
        .text:0x00401664  c744242800000000 mov dword [esp + 40],0
        .text:0x0040166c  85ed             test ebp,ebp
        .text:0x0040166e  0f8645010000     jbe 0x004017b9
        .text:0x00401674  8b6c2420         mov ebp,dword [esp + 32]
        .text:0x00401678  8d6c8d00         lea ebp,dword [ebp + ecx * 4]
        .text:0x0040167c  8d0c4e           lea ecx,dword [esi + ecx * 2]
        .text:0x0040167f  8b742420         mov esi,dword [esp + 32]
        .text:0x00401683  894c2410         mov dword [esp + 16],ecx
        .text:0x00401687  8b4c2430         mov ecx,dword [esp + 48]
        .text:0x0040168b  894c2418         mov dword [esp + 24],ecx
        .text:0x0040168f  8b4c2434         mov ecx,dword [esp + 52]
        .text:0x00401693  894c2414         mov dword [esp + 20],ecx
        .text:0x00401697  8bcf             mov ecx,edi
        .text:0x00401699  2bce             sub ecx,esi
        .text:0x0040169b  894c2440         mov dword [esp + 64],ecx
        .text:0x0040169f  loc_0040169f: [1 XREFS]
        .text:0x0040169f  8b742414         mov esi,dword [esp + 20]
        .text:0x004016a3  33c9             xor ecx,ecx
        .text:0x004016a5  668b0e           mov cx,word [esi]
        .text:0x004016a8  3bca             cmp ecx,edx
        .text:0x004016aa  0f85d3000000     jnz 0x00401783
        .text:0x004016b0  8b542458         mov edx,dword [esp + 88]
        .text:0x004016b4  8b4c2418         mov ecx,dword [esp + 24]
        .text:0x004016b8  8b442438         mov eax,dword [esp + 56]
        .text:0x004016bc  52               push edx
        .text:0x004016bd  8b11             mov edx,dword [ecx]
        .text:0x004016bf  50               push eax
        .text:0x004016c0  52               push edx
        .text:0x004016c1  e87af9ffff       call 0x00401040    ;sub_00401040(0x61616161,0xa2bb7170,<0x004014d4>)
        .text:0x004016c6  8bd0             mov edx,eax
        .text:0x004016c8  83c9ff           or ecx,0xffffffff
        .text:0x004016cb  8bfa             mov edi,edx
        .text:0x004016cd  33c0             xor eax,eax
        .text:0x004016cf  83c40c           add esp,12
        .text:0x004016d2  8bf2             mov esi,edx
        .text:0x004016d4  f2ae             repnz: scasb 
        .text:0x004016d6  f7d1             not ecx
        .text:0x004016d8  8bc1             mov eax,ecx
        .text:0x004016da  8bfb             mov edi,ebx
        .text:0x004016dc  c1e902           shr ecx,2
        .text:0x004016df  f3a5             rep: movsd 
        .text:0x004016e1  8bc8             mov ecx,eax
        .text:0x004016e3  8b442410         mov eax,dword [esp + 16]
        .text:0x004016e7  83e103           and ecx,3
        .text:0x004016ea  f3a4             rep: movsb 
        .text:0x004016ec  668b4c245c       mov cx,word [esp + 92]
        .text:0x004016f1  8b74243c         mov esi,dword [esp + 60]
        .text:0x004016f5  668908           mov word [eax],cx
        .text:0x004016f8  8b442440         mov eax,dword [esp + 64]
        .text:0x004016fc  8d0c33           lea ecx,dword [ebx + esi]
        .text:0x004016ff  8bfa             mov edi,edx
        .text:0x00401701  890c28           mov dword [eax + ebp],ecx
        .text:0x00401704  83c9ff           or ecx,0xffffffff
        .text:0x00401707  33c0             xor eax,eax
        .text:0x00401709  f2ae             repnz: scasb 
        .text:0x0040170b  f7d1             not ecx
        .text:0x0040170d  49               dec ecx
        .text:0x0040170e  8bfa             mov edi,edx
        .text:0x00401710  8d5c0b01         lea ebx,dword [ebx + ecx + 1]
        .text:0x00401714  8bc3             mov eax,ebx
        .text:0x00401716  8d0c33           lea ecx,dword [ebx + esi]
        .text:0x00401719  83c309           add ebx,9
        .text:0x0040171c  894d00           mov dword [ebp],ecx
        .text:0x0040171f  8b0d70304000     mov ecx,dword [0x00403070]
        .text:0x00401725  8908             mov dword [eax],ecx
        .text:0x00401727  8b0d74304000     mov ecx,dword [0x00403074]
        .text:0x0040172d  8bf2             mov esi,edx
        .text:0x0040172f  894804           mov dword [eax + 4],ecx
        .text:0x00401732  8a0d78304000     mov cl,byte [0x00403078]
        .text:0x00401738  884808           mov byte [eax + 8],cl
        .text:0x0040173b  83c9ff           or ecx,0xffffffff
        .text:0x0040173e  33c0             xor eax,eax
        .text:0x00401740  f2ae             repnz: scasb 
        .text:0x00401742  f7d1             not ecx
        .text:0x00401744  8bc1             mov eax,ecx
        .text:0x00401746  8bfb             mov edi,ebx
        .text:0x00401748  c1e902           shr ecx,2
        .text:0x0040174b  f3a5             rep: movsd 
        .text:0x0040174d  8bc8             mov ecx,eax
        .text:0x0040174f  33c0             xor eax,eax
        .text:0x00401751  83e103           and ecx,3
        .text:0x00401754  f3a4             rep: movsb 
        .text:0x00401756  8bfa             mov edi,edx
        .text:0x00401758  83c9ff           or ecx,0xffffffff
        .text:0x0040175b  f2ae             repnz: scasb 
        .text:0x0040175d  8b54245c         mov edx,dword [esp + 92]
        .text:0x00401761  8b442424         mov eax,dword [esp + 36]
        .text:0x00401765  f7d1             not ecx
        .text:0x00401767  49               dec ecx
        .text:0x00401768  42               inc edx
        .text:0x00401769  8954245c         mov dword [esp + 92],edx
        .text:0x0040176d  8b54242c         mov edx,dword [esp + 44]
        .text:0x00401771  8d5c0b01         lea ebx,dword [ebx + ecx + 1]
        .text:0x00401775  8b4c2410         mov ecx,dword [esp + 16]
        .text:0x00401779  83c102           add ecx,2
        .text:0x0040177c  83c504           add ebp,4
        .text:0x0040177f  894c2410         mov dword [esp + 16],ecx
        .text:0x00401783  loc_00401783: [1 XREFS]
        .text:0x00401783  8b742414         mov esi,dword [esp + 20]
        .text:0x00401787  8b4c2428         mov ecx,dword [esp + 40]
        .text:0x0040178b  8b7c2418         mov edi,dword [esp + 24]
        .text:0x0040178f  83c602           add esi,2
        .text:0x00401792  89742414         mov dword [esp + 20],esi
        .text:0x00401796  8b7018           mov esi,dword [eax + 24]
        .text:0x00401799  41               inc ecx
        .text:0x0040179a  83c704           add edi,4
        .text:0x0040179d  3bce             cmp ecx,esi
        .text:0x0040179f  894c2428         mov dword [esp + 40],ecx
        .text:0x004017a3  897c2418         mov dword [esp + 24],edi
        .text:0x004017a7  0f82f2feffff     jc 0x0040169f
        .text:0x004017ad  8b4c245c         mov ecx,dword [esp + 92]
        .text:0x004017b1  8b7c2444         mov edi,dword [esp + 68]
        .text:0x004017b5  8b742448         mov esi,dword [esp + 72]
        .text:0x004017b9  loc_004017b9: [2 XREFS]
        .text:0x004017b9  8b6c241c         mov ebp,dword [esp + 28]
        .text:0x004017bd  42               inc edx
        .text:0x004017be  83c504           add ebp,4
        .text:0x004017c1  8954242c         mov dword [esp + 44],edx
        .text:0x004017c5  896c241c         mov dword [esp + 28],ebp
        .text:0x004017c9  8b6814           mov ebp,dword [eax + 20]
        .text:0x004017cc  3bd5             cmp edx,ebp
        .text:0x004017ce  0f827ffeffff     jc 0x00401653
        .text:0x004017d4  loc_004017d4: [1 XREFS]
        .text:0x004017d4  8b4c244c         mov ecx,dword [esp + 76]
        .text:0x004017d8  8b3500204000     mov esi,dword [0x00402000]
        .text:0x004017de  51               push ecx
        .text:0x004017df  ffd6             call esi    ;kernel32.CloseHandle(<0x004014ac>)
        .text:0x004017e1  8b542450         mov edx,dword [esp + 80]
        .text:0x004017e5  52               push edx
        .text:0x004017e6  ffd6             call esi    ;kernel32.CloseHandle(<0x004014f0>)
        .text:0x004017e8  6a00             push 0
        .text:0x004017ea  684c304000       push 0x0040304c
        .text:0x004017ef  687c304000       push 0x0040307c
        .text:0x004017f4  ff1524204000     call dword [0x00402024]    ;kernel32.CopyFileA(0x0040307c,0x0040304c,0)
        .text:0x004017fa  85c0             test eax,eax
        .text:0x004017fc  6a00             push 0
        .text:0x004017fe  7506             jnz 0x00401806
        .text:0x00401800  ff1530204000     call dword [0x00402030]    ;msvcrt.exit(0)
        .text:0x00401806  loc_00401806: [1 XREFS]
        .text:0x00401806  6844304000       push 0x00403044
        .text:0x0040180b  e8d0f9ffff       call 0x004011e0    ;sub_004011e0(0x00403044,0)
        .text:0x00401810  83c408           add esp,8
        .text:0x00401813  loc_00401813: [2 XREFS]
        .text:0x00401813  5f               pop edi
        .text:0x00401814  5e               pop esi
        .text:0x00401815  5d               pop ebp
        .text:0x00401816  33c0             xor eax,eax
        .text:0x00401818  5b               pop ebx
        .text:0x00401819  83c444           add esp,68
        .text:0x0040181c  c3               ret 
        */
        $c0 = { 8B 44 24 ?? 83 EC 44 83 F8 02 53 55 56 57 0F 85 ?? ?? ?? ?? 8B 44 24 ?? BE B0 30 40 00 8B 40 ?? 8A 10 8A 1E 8A CA 3A D3 75 ?? 84 C9 74 ?? 8A 50 ?? 8A 5E ?? 8A CA 3A D3 75 ?? 83 C0 02 83 C6 02 84 C9 75 ?? 33 C0 EB ?? 1B C0 83 D8 FF 85 C0 0F 85 ?? ?? ?? ?? 8B 3D ?? ?? ?? ?? 50 50 6A 03 50 6A 01 68 00 00 00 80 68 8C 30 40 00 FF D7 8B 1D ?? ?? ?? ?? 6A 00 6A 00 6A 00 6A 02 6A 00 50 89 44 24 ?? FF D3 8B 2D ?? ?? ?? ?? 6A 00 6A 00 6A 00 6A 04 50 FF D5 6A 00 6A 00 6A 03 6A 00 6A 01 8B F0 68 00 00 00 10 68 7C 30 40 00 89 74 24 ?? FF D7 83 F8 FF 89 44 24 ?? 6A 00 75 ?? FF 15 ?? ?? ?? ?? 6A 00 6A 00 6A 04 6A 00 50 FF D3 83 F8 FF 6A 00 75 ?? FF 15 ?? ?? ?? ?? 6A 00 6A 00 68 1F 00 0F 00 50 FF D5 8B E8 85 ED 89 6C 24 ?? 75 ?? 50 FF 15 ?? ?? ?? ?? 8B 7E ?? 56 03 FE 57 89 7C 24 ?? 8B 47 ?? 50 E8 ?? ?? ?? ?? 8B 75 ?? 55 03 F5 8B D8 56 89 5C 24 ?? 8B 4E ?? 51 E8 ?? ?? ?? ?? 8B 54 24 ?? 8B E8 8B 43 ?? 52 57 50 E8 ?? ?? ?? ?? 8B 4C 24 ?? 8B 53 ?? 51 57 52 89 44 24 ?? E8 ?? ?? ?? ?? 8B 4B ?? 89 44 24 ?? 8B 84 24 ?? ?? ?? ?? 50 57 51 E8 ?? ?? ?? ?? 8B 94 24 ?? ?? ?? ?? 8B 7E ?? 89 44 24 ?? 8B 46 ?? 52 56 50 E8 ?? ?? ?? ?? 8B CF 8B F3 8B D1 8B FD C1 E9 02 F3 A5 8B CA 83 C4 48 83 E1 03 89 44 24 ?? F3 A4 8B 4B ?? 89 4D ?? 8B 53 ?? 8D 5D ?? 89 55 ?? C1 E1 04 8D 14 03 89 55 ?? 8B 35 ?? ?? ?? ?? 8B D3 83 C3 10 89 5C 24 ?? 89 32 8B 35 ?? ?? ?? ?? 89 72 ?? 8B 35 ?? ?? ?? ?? 89 72 ?? 8B 35 ?? ?? ?? ?? 89 72 ?? 8B 55 ?? 8D 34 93 8D 3C D3 89 74 24 ?? 89 7C 24 ?? 8D 14 03 03 D9 89 55 ?? 8D 14 06 03 C7 89 55 ?? 89 45 ?? 8B 44 24 ?? 33 C9 33 D2 8B 68 ?? 89 4C 24 ?? 85 ED 89 54 24 ?? 0F 86 ?? ?? ?? ?? 8B 6C 24 ?? 83 7D ?? 00 0F 84 ?? ?? ?? ?? 8B 68 ?? C7 44 24 ?? 00 00 00 00 85 ED 0F 86 ?? ?? ?? ?? 8B 6C 24 ?? 8D 6C 8D ?? 8D 0C 4E 8B 74 24 ?? 89 4C 24 ?? 8B 4C 24 ?? 89 4C 24 ?? 8B 4C 24 ?? 89 4C 24 ?? 8B CF 2B CE 89 4C 24 ?? 8B 74 24 ?? 33 C9 66 8B 0E 3B CA 0F 85 ?? ?? ?? ?? 8B 54 24 ?? 8B 4C 24 ?? 8B 44 24 ?? 52 8B 11 50 52 E8 ?? ?? ?? ?? 8B D0 83 C9 FF 8B FA 33 C0 83 C4 0C 8B F2 F2 AE F7 D1 8B C1 8B FB C1 E9 02 F3 A5 8B C8 8B 44 24 ?? 83 E1 03 F3 A4 66 8B 4C 24 ?? 8B 74 24 ?? 66 89 08 8B 44 24 ?? 8D 0C 33 8B FA 89 0C 28 83 C9 FF 33 C0 F2 AE F7 D1 49 8B FA 8D 5C 0B ?? 8B C3 8D 0C 33 83 C3 09 89 4D ?? 8B 0D ?? ?? ?? ?? 89 08 8B 0D ?? ?? ?? ?? 8B F2 89 48 ?? 8A 0D ?? ?? ?? ?? 88 48 ?? 83 C9 FF 33 C0 F2 AE F7 D1 8B C1 8B FB C1 E9 02 F3 A5 8B C8 33 C0 83 E1 03 F3 A4 8B FA 83 C9 FF F2 AE 8B 54 24 ?? 8B 44 24 ?? F7 D1 49 42 89 54 24 ?? 8B 54 24 ?? 8D 5C 0B ?? 8B 4C 24 ?? 83 C1 02 83 C5 04 89 4C 24 ?? 8B 74 24 ?? 8B 4C 24 ?? 8B 7C 24 ?? 83 C6 02 89 74 24 ?? 8B 70 ?? 41 83 C7 04 3B CE 89 4C 24 ?? 89 7C 24 ?? 0F 82 ?? ?? ?? ?? 8B 4C 24 ?? 8B 7C 24 ?? 8B 74 24 ?? 8B 6C 24 ?? 42 83 C5 04 89 54 24 ?? 89 6C 24 ?? 8B 68 ?? 3B D5 0F 82 ?? ?? ?? ?? 8B 4C 24 ?? 8B 35 ?? ?? ?? ?? 51 FF D6 8B 54 24 ?? 52 FF D6 6A 00 68 4C 30 40 00 68 7C 30 40 00 FF 15 ?? ?? ?? ?? 85 C0 6A 00 75 ?? FF 15 ?? ?? ?? ?? 68 44 30 40 00 E8 ?? ?? ?? ?? 83 C4 08 5F 5E 5D 33 C0 5B 83 C4 44 C3 }
        /*
function at 0x004011e0@bb7425b82141a1c0f7d60e5106676bb1 with 2 features:
          - enumerate files on Windows
          - enumerate files recursively
        .text:0x004011e0  
        .text:0x004011e0  FUNC: int cdecl sub_004011e0( int arg0, int arg1, ) [4 XREFS] 
        .text:0x004011e0  
        .text:0x004011e0  Stack Variables: (offset from initial top of stack)
        .text:0x004011e0             8: int arg1
        .text:0x004011e0             4: int arg0
        .text:0x004011e0          -275: int local275
        .text:0x004011e0          -276: int local276
        .text:0x004011e0          -281: int local281
        .text:0x004011e0          -320: int local320
        .text:0x004011e0          -324: int local324
        .text:0x004011e0  
        .text:0x004011e0  8b442408         mov eax,dword [esp + 8]
        .text:0x004011e4  81ec44010000     sub esp,324
        .text:0x004011ea  83f807           cmp eax,7
        .text:0x004011ed  53               push ebx
        .text:0x004011ee  55               push ebp
        .text:0x004011ef  56               push esi
        .text:0x004011f0  57               push edi
        .text:0x004011f1  0f8f3d020000     jg 0x00401434
        .text:0x004011f7  8bac2458010000   mov ebp,dword [esp + 344]
        .text:0x004011fe  8d442414         lea eax,dword [esp + 20]
        .text:0x00401202  50               push eax
        .text:0x00401203  55               push ebp
        .text:0x00401204  ff1520204000     call dword [0x00402020]    ;kernel32.FindFirstFileA(arg0,local320)
        .text:0x0040120a  8bf0             mov esi,eax
        .text:0x0040120c  89742410         mov dword [esp + 16],esi
        .text:0x00401210  loc_00401210: [1 XREFS]
        .text:0x00401210  83feff           cmp esi,0xffffffff
        .text:0x00401213  0f8413020000     jz 0x0040142c
        .text:0x00401219  f644241410       test byte [esp + 20],16
        .text:0x0040121e  0f8438010000     jz 0x0040135c
        .text:0x00401224  be40304000       mov esi,0x00403040
        .text:0x00401229  8d442440         lea eax,dword [esp + 64]
        .text:0x0040122d  loc_0040122d: [1 XREFS]
        .text:0x0040122d  8a10             mov dl,byte [eax]
        .text:0x0040122f  8a1e             mov bl,byte [esi]
        .text:0x00401231  8aca             mov cl,dl
        .text:0x00401233  3ad3             cmp dl,bl
        .text:0x00401235  751e             jnz 0x00401255
        .text:0x00401237  84c9             test cl,cl
        .text:0x00401239  7416             jz 0x00401251
        .text:0x0040123b  8a5001           mov dl,byte [eax + 1]
        .text:0x0040123e  8a5e01           mov bl,byte [esi + 1]
        .text:0x00401241  8aca             mov cl,dl
        .text:0x00401243  3ad3             cmp dl,bl
        .text:0x00401245  750e             jnz 0x00401255
        .text:0x00401247  83c002           add eax,2
        .text:0x0040124a  83c602           add esi,2
        .text:0x0040124d  84c9             test cl,cl
        .text:0x0040124f  75dc             jnz 0x0040122d
        .text:0x00401251  loc_00401251: [1 XREFS]
        .text:0x00401251  33c0             xor eax,eax
        .text:0x00401253  eb05             jmp 0x0040125a
        .text:0x00401255  loc_00401255: [2 XREFS]
        .text:0x00401255  1bc0             sbb eax,eax
        .text:0x00401257  83d8ff           sbb eax,0xffffffff
        .text:0x0040125a  loc_0040125a: [1 XREFS]
        .text:0x0040125a  85c0             test eax,eax
        .text:0x0040125c  0f84fa000000     jz 0x0040135c
        .text:0x00401262  be3c304000       mov esi,0x0040303c
        .text:0x00401267  8d442440         lea eax,dword [esp + 64]
        .text:0x0040126b  loc_0040126b: [1 XREFS]
        .text:0x0040126b  8a10             mov dl,byte [eax]
        .text:0x0040126d  8a1e             mov bl,byte [esi]
        .text:0x0040126f  8aca             mov cl,dl
        .text:0x00401271  3ad3             cmp dl,bl
        .text:0x00401273  751e             jnz 0x00401293
        .text:0x00401275  84c9             test cl,cl
        .text:0x00401277  7416             jz 0x0040128f
        .text:0x00401279  8a5001           mov dl,byte [eax + 1]
        .text:0x0040127c  8a5e01           mov bl,byte [esi + 1]
        .text:0x0040127f  8aca             mov cl,dl
        .text:0x00401281  3ad3             cmp dl,bl
        .text:0x00401283  750e             jnz 0x00401293
        .text:0x00401285  83c002           add eax,2
        .text:0x00401288  83c602           add esi,2
        .text:0x0040128b  84c9             test cl,cl
        .text:0x0040128d  75dc             jnz 0x0040126b
        .text:0x0040128f  loc_0040128f: [1 XREFS]
        .text:0x0040128f  33c0             xor eax,eax
        .text:0x00401291  eb05             jmp 0x00401298
        .text:0x00401293  loc_00401293: [2 XREFS]
        .text:0x00401293  1bc0             sbb eax,eax
        .text:0x00401295  83d8ff           sbb eax,0xffffffff
        .text:0x00401298  loc_00401298: [1 XREFS]
        .text:0x00401298  85c0             test eax,eax
        .text:0x0040129a  0f84bc000000     jz 0x0040135c
        .text:0x004012a0  8d7c2440         lea edi,dword [esp + 64]
        .text:0x004012a4  83c9ff           or ecx,0xffffffff
        .text:0x004012a7  33c0             xor eax,eax
        .text:0x004012a9  f2ae             repnz: scasb 
        .text:0x004012ab  f7d1             not ecx
        .text:0x004012ad  49               dec ecx
        .text:0x004012ae  8bfd             mov edi,ebp
        .text:0x004012b0  8bd1             mov edx,ecx
        .text:0x004012b2  83c9ff           or ecx,0xffffffff
        .text:0x004012b5  f2ae             repnz: scasb 
        .text:0x004012b7  f7d1             not ecx
        .text:0x004012b9  49               dec ecx
        .text:0x004012ba  8d445106         lea eax,dword [ecx + edx * 2 + 6]
        .text:0x004012be  50               push eax
        .text:0x004012bf  ff152c204000     call dword [0x0040202c]    ;msvcrt.malloc(3)
        .text:0x004012c5  8bd0             mov edx,eax
        .text:0x004012c7  83c9ff           or ecx,0xffffffff
        .text:0x004012ca  8bfd             mov edi,ebp
        .text:0x004012cc  33c0             xor eax,eax
        .text:0x004012ce  f2ae             repnz: scasb 
        .text:0x004012d0  f7d1             not ecx
        .text:0x004012d2  2bf9             sub edi,ecx
        .text:0x004012d4  8bc1             mov eax,ecx
        .text:0x004012d6  8bf7             mov esi,edi
        .text:0x004012d8  c1e902           shr ecx,2
        .text:0x004012db  8bfa             mov edi,edx
        .text:0x004012dd  f3a5             rep: movsd 
        .text:0x004012df  8bc8             mov ecx,eax
        .text:0x004012e1  33c0             xor eax,eax
        .text:0x004012e3  83e103           and ecx,3
        .text:0x004012e6  f3a4             rep: movsb 
        .text:0x004012e8  83c9ff           or ecx,0xffffffff
        .text:0x004012eb  8bfd             mov edi,ebp
        .text:0x004012ed  f2ae             repnz: scasb 
        .text:0x004012ef  f7d1             not ecx
        .text:0x004012f1  49               dec ecx
        .text:0x004012f2  8d7c2444         lea edi,dword [esp + 68]
        .text:0x004012f6  884411ff         mov byte [ecx + edx + -1],al
        .text:0x004012fa  83c9ff           or ecx,0xffffffff
        .text:0x004012fd  f2ae             repnz: scasb 
        .text:0x004012ff  f7d1             not ecx
        .text:0x00401301  2bf9             sub edi,ecx
        .text:0x00401303  8bf7             mov esi,edi
        .text:0x00401305  8bd9             mov ebx,ecx
        .text:0x00401307  8bfa             mov edi,edx
        .text:0x00401309  83c9ff           or ecx,0xffffffff
        .text:0x0040130c  f2ae             repnz: scasb 
        .text:0x0040130e  8bcb             mov ecx,ebx
        .text:0x00401310  4f               dec edi
        .text:0x00401311  c1e902           shr ecx,2
        .text:0x00401314  f3a5             rep: movsd 
        .text:0x00401316  8bcb             mov ecx,ebx
        .text:0x00401318  83e103           and ecx,3
        .text:0x0040131b  f3a4             rep: movsb 
        .text:0x0040131d  bf38304000       mov edi,0x00403038
        .text:0x00401322  83c9ff           or ecx,0xffffffff
        .text:0x00401325  f2ae             repnz: scasb 
        .text:0x00401327  f7d1             not ecx
        .text:0x00401329  2bf9             sub edi,ecx
        .text:0x0040132b  8bf7             mov esi,edi
        .text:0x0040132d  8bd9             mov ebx,ecx
        .text:0x0040132f  8bfa             mov edi,edx
        .text:0x00401331  83c9ff           or ecx,0xffffffff
        .text:0x00401334  f2ae             repnz: scasb 
        .text:0x00401336  8bcb             mov ecx,ebx
        .text:0x00401338  4f               dec edi
        .text:0x00401339  c1e902           shr ecx,2
        .text:0x0040133c  f3a5             rep: movsd 
        .text:0x0040133e  8bcb             mov ecx,ebx
        .text:0x00401340  83e103           and ecx,3
        .text:0x00401343  f3a4             rep: movsb 
        .text:0x00401345  8b8c2460010000   mov ecx,dword [esp + 352]
        .text:0x0040134c  41               inc ecx
        .text:0x0040134d  51               push ecx
        .text:0x0040134e  52               push edx
        .text:0x0040134f  e88cfeffff       call 0x004011e0    ;sub_004011e0()
        .text:0x00401354  83c40c           add esp,12
        .text:0x00401357  e9b7000000       jmp 0x00401413
        .text:0x0040135c  loc_0040135c: [3 XREFS]
        .text:0x0040135c  8d7c2440         lea edi,dword [esp + 64]
        .text:0x00401360  83c9ff           or ecx,0xffffffff
        .text:0x00401363  33c0             xor eax,eax
        .text:0x00401365  f2ae             repnz: scasb 
        .text:0x00401367  f7d1             not ecx
        .text:0x00401369  49               dec ecx
        .text:0x0040136a  8bfd             mov edi,ebp
        .text:0x0040136c  8d5c0c3c         lea ebx,dword [esp + ecx + 60]
        .text:0x00401370  83c9ff           or ecx,0xffffffff
        .text:0x00401373  f2ae             repnz: scasb 
        .text:0x00401375  f7d1             not ecx
        .text:0x00401377  49               dec ecx
        .text:0x00401378  8d7c2440         lea edi,dword [esp + 64]
        .text:0x0040137c  8bd1             mov edx,ecx
        .text:0x0040137e  83c9ff           or ecx,0xffffffff
        .text:0x00401381  f2ae             repnz: scasb 
        .text:0x00401383  f7d1             not ecx
        .text:0x00401385  49               dec ecx
        .text:0x00401386  8d440a01         lea eax,dword [edx + ecx + 1]
        .text:0x0040138a  50               push eax
        .text:0x0040138b  ff152c204000     call dword [0x0040202c]    ;msvcrt.malloc(0xffffffff)
        .text:0x00401391  8b94245c010000   mov edx,dword [esp + 348]
        .text:0x00401398  8be8             mov ebp,eax
        .text:0x0040139a  8bfa             mov edi,edx
        .text:0x0040139c  83c9ff           or ecx,0xffffffff
        .text:0x0040139f  33c0             xor eax,eax
        .text:0x004013a1  6830304000       push 0x00403030
        .text:0x004013a6  f2ae             repnz: scasb 
        .text:0x004013a8  f7d1             not ecx
        .text:0x004013aa  2bf9             sub edi,ecx
        .text:0x004013ac  53               push ebx
        .text:0x004013ad  8bc1             mov eax,ecx
        .text:0x004013af  8bf7             mov esi,edi
        .text:0x004013b1  8bfd             mov edi,ebp
        .text:0x004013b3  c1e902           shr ecx,2
        .text:0x004013b6  f3a5             rep: movsd 
        .text:0x004013b8  8bc8             mov ecx,eax
        .text:0x004013ba  33c0             xor eax,eax
        .text:0x004013bc  83e103           and ecx,3
        .text:0x004013bf  f3a4             rep: movsb 
        .text:0x004013c1  8bfa             mov edi,edx
        .text:0x004013c3  83c9ff           or ecx,0xffffffff
        .text:0x004013c6  f2ae             repnz: scasb 
        .text:0x004013c8  f7d1             not ecx
        .text:0x004013ca  49               dec ecx
        .text:0x004013cb  8d7c244c         lea edi,dword [esp + 76]
        .text:0x004013cf  884429ff         mov byte [ecx + ebp + -1],al
        .text:0x004013d3  83c9ff           or ecx,0xffffffff
        .text:0x004013d6  f2ae             repnz: scasb 
        .text:0x004013d8  f7d1             not ecx
        .text:0x004013da  2bf9             sub edi,ecx
        .text:0x004013dc  8bf7             mov esi,edi
        .text:0x004013de  8bd1             mov edx,ecx
        .text:0x004013e0  8bfd             mov edi,ebp
        .text:0x004013e2  83c9ff           or ecx,0xffffffff
        .text:0x004013e5  f2ae             repnz: scasb 
        .text:0x004013e7  8bca             mov ecx,edx
        .text:0x004013e9  4f               dec edi
        .text:0x004013ea  c1e902           shr ecx,2
        .text:0x004013ed  f3a5             rep: movsd 
        .text:0x004013ef  8bca             mov ecx,edx
        .text:0x004013f1  83e103           and ecx,3
        .text:0x004013f4  f3a4             rep: movsb 
        .text:0x004013f6  ff1564204000     call dword [0x00402064]    ;msvcrt._stricmp(local281,0x00403030)
        .text:0x004013fc  83c40c           add esp,12
        .text:0x004013ff  85c0             test eax,eax
        .text:0x00401401  7509             jnz 0x0040140c
        .text:0x00401403  55               push ebp
        .text:0x00401404  e897fcffff       call 0x004010a0    ;sub_004010a0(msvcrt.malloc(0xffffffff))
        .text:0x00401409  83c404           add esp,4
        .text:0x0040140c  loc_0040140c: [1 XREFS]
        .text:0x0040140c  8bac2458010000   mov ebp,dword [esp + 344]
        .text:0x00401413  loc_00401413: [1 XREFS]
        .text:0x00401413  8b742410         mov esi,dword [esp + 16]
        .text:0x00401417  8d442414         lea eax,dword [esp + 20]
        .text:0x0040141b  50               push eax
        .text:0x0040141c  56               push esi
        .text:0x0040141d  ff151c204000     call dword [0x0040201c]    ;kernel32.FindNextFileA(kernel32.FindFirstFileA(arg0,local320),local320)
        .text:0x00401423  85c0             test eax,eax
        .text:0x00401425  740d             jz 0x00401434
        .text:0x00401427  e9e4fdffff       jmp 0x00401210
        .text:0x0040142c  loc_0040142c: [1 XREFS]
        .text:0x0040142c  6aff             push 0xffffffff
        .text:0x0040142e  ff1518204000     call dword [0x00402018]    ;kernel32.FindClose(0xffffffff)
        .text:0x00401434  loc_00401434: [2 XREFS]
        .text:0x00401434  5f               pop edi
        .text:0x00401435  5e               pop esi
        .text:0x00401436  5d               pop ebp
        .text:0x00401437  5b               pop ebx
        .text:0x00401438  81c444010000     add esp,324
        .text:0x0040143e  c3               ret 
        */
        $c1 = { 8B 44 24 ?? 81 EC 44 01 00 00 83 F8 07 53 55 56 57 0F 8F ?? ?? ?? ?? 8B AC 24 ?? ?? ?? ?? 8D 44 24 ?? 50 55 FF 15 ?? ?? ?? ?? 8B F0 89 74 24 ?? 83 FE FF 0F 84 ?? ?? ?? ?? F6 44 24 ?? 10 0F 84 ?? ?? ?? ?? BE 40 30 40 00 8D 44 24 ?? 8A 10 8A 1E 8A CA 3A D3 75 ?? 84 C9 74 ?? 8A 50 ?? 8A 5E ?? 8A CA 3A D3 75 ?? 83 C0 02 83 C6 02 84 C9 75 ?? 33 C0 EB ?? 1B C0 83 D8 FF 85 C0 0F 84 ?? ?? ?? ?? BE 3C 30 40 00 8D 44 24 ?? 8A 10 8A 1E 8A CA 3A D3 75 ?? 84 C9 74 ?? 8A 50 ?? 8A 5E ?? 8A CA 3A D3 75 ?? 83 C0 02 83 C6 02 84 C9 75 ?? 33 C0 EB ?? 1B C0 83 D8 FF 85 C0 0F 84 ?? ?? ?? ?? 8D 7C 24 ?? 83 C9 FF 33 C0 F2 AE F7 D1 49 8B FD 8B D1 83 C9 FF F2 AE F7 D1 49 8D 44 51 ?? 50 FF 15 ?? ?? ?? ?? 8B D0 83 C9 FF 8B FD 33 C0 F2 AE F7 D1 2B F9 8B C1 8B F7 C1 E9 02 8B FA F3 A5 8B C8 33 C0 83 E1 03 F3 A4 83 C9 FF 8B FD F2 AE F7 D1 49 8D 7C 24 ?? 88 44 11 ?? 83 C9 FF F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF F2 AE 8B CB 4F C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 BF 38 30 40 00 83 C9 FF F2 AE F7 D1 2B F9 8B F7 8B D9 8B FA 83 C9 FF F2 AE 8B CB 4F C1 E9 02 F3 A5 8B CB 83 E1 03 F3 A4 8B 8C 24 ?? ?? ?? ?? 41 51 52 E8 ?? ?? ?? ?? 83 C4 0C E9 ?? ?? ?? ?? 8D 7C 24 ?? 83 C9 FF 33 C0 F2 AE F7 D1 49 8B FD 8D 5C 0C ?? 83 C9 FF F2 AE F7 D1 49 8D 7C 24 ?? 8B D1 83 C9 FF F2 AE F7 D1 49 8D 44 0A ?? 50 FF 15 ?? ?? ?? ?? 8B 94 24 ?? ?? ?? ?? 8B E8 8B FA 83 C9 FF 33 C0 68 30 30 40 00 F2 AE F7 D1 2B F9 53 8B C1 8B F7 8B FD C1 E9 02 F3 A5 8B C8 33 C0 83 E1 03 F3 A4 8B FA 83 C9 FF F2 AE F7 D1 49 8D 7C 24 ?? 88 44 29 ?? 83 C9 FF F2 AE F7 D1 2B F9 8B F7 8B D1 8B FD 83 C9 FF F2 AE 8B CA 4F C1 E9 02 F3 A5 8B CA 83 E1 03 F3 A4 FF 15 ?? ?? ?? ?? 83 C4 0C 85 C0 75 ?? 55 E8 ?? ?? ?? ?? 83 C4 04 8B AC 24 ?? ?? ?? ?? 8B 74 24 ?? 8D 44 24 ?? 50 56 FF 15 ?? ?? ?? ?? 85 C0 74 ?? E9 ?? ?? ?? ?? 6A FF FF 15 ?? ?? ?? ?? 5F 5E 5D 5B 81 C4 44 01 00 00 C3 }
        /*
function at 0x004010a0@bb7425b82141a1c0f7d60e5106676bb1 with 1 features:
          - read file via mapping
        .text:0x004010a0  
        .text:0x004010a0  FUNC: int cdecl sub_004010a0( int arg0, ) [2 XREFS] 
        .text:0x004010a0  
        .text:0x004010a0  Stack Variables: (offset from initial top of stack)
        .text:0x004010a0             4: int arg0
        .text:0x004010a0            -4: int local4
        .text:0x004010a0            -8: int local8
        .text:0x004010a0           -12: int local12
        .text:0x004010a0  
        .text:0x004010a0  83ec0c           sub esp,12
        .text:0x004010a3  53               push ebx
        .text:0x004010a4  8b442414         mov eax,dword [esp + 20]
        .text:0x004010a8  55               push ebp
        .text:0x004010a9  56               push esi
        .text:0x004010aa  57               push edi
        .text:0x004010ab  6a00             push 0
        .text:0x004010ad  6a00             push 0
        .text:0x004010af  6a03             push 3
        .text:0x004010b1  6a00             push 0
        .text:0x004010b3  6a01             push 1
        .text:0x004010b5  6800000010       push 0x10000000
        .text:0x004010ba  50               push eax
        .text:0x004010bb  ff1514204000     call dword [0x00402014]    ;kernel32.CreateFileA(arg0,0x10000000,1,0,3,0,0)
        .text:0x004010c1  6a00             push 0
        .text:0x004010c3  6a00             push 0
        .text:0x004010c5  6a00             push 0
        .text:0x004010c7  6a04             push 4
        .text:0x004010c9  6a00             push 0
        .text:0x004010cb  50               push eax
        .text:0x004010cc  89442430         mov dword [esp + 48],eax
        .text:0x004010d0  ff1510204000     call dword [0x00402010]    ;kernel32.CreateFileMappingA(kernel32.CreateFileA(arg0,0x10000000,1,0,3,0,0),0,4,0,0,0)
        .text:0x004010d6  6a00             push 0
        .text:0x004010d8  6a00             push 0
        .text:0x004010da  6a00             push 0
        .text:0x004010dc  681f000f00       push 0x000f001f
        .text:0x004010e1  50               push eax
        .text:0x004010e2  89442428         mov dword [esp + 40],eax
        .text:0x004010e6  ff150c204000     call dword [0x0040200c]    ;kernel32.MapViewOfFile(kernel32.CreateFileMappingA(<0x004010bb>,0,4,0,0,0),0x000f001f,0,0,0)
        .text:0x004010ec  8bf0             mov esi,eax
        .text:0x004010ee  85f6             test esi,esi
        .text:0x004010f0  89742410         mov dword [esp + 16],esi
        .text:0x004010f4  0f84db000000     jz 0x004011d5
        .text:0x004010fa  8b6e3c           mov ebp,dword [esi + 60]
        .text:0x004010fd  8b1d08204000     mov ebx,dword [0x00402008]
        .text:0x00401103  03ee             add ebp,esi
        .text:0x00401105  6a04             push 4
        .text:0x00401107  55               push ebp
        .text:0x00401108  ffd3             call ebx    ;kernel32.IsBadReadPtr(0xa2bb7170,4)
        .text:0x0040110a  85c0             test eax,eax
        .text:0x0040110c  0f85c3000000     jnz 0x004011d5
        .text:0x00401112  817d0050450000   cmp dword [ebp],0x00004550
        .text:0x00401119  0f85b6000000     jnz 0x004011d5
        .text:0x0040111f  8b8d80000000     mov ecx,dword [ebp + 128]
        .text:0x00401125  56               push esi
        .text:0x00401126  55               push ebp
        .text:0x00401127  51               push ecx
        .text:0x00401128  e813ffffff       call 0x00401040    ;sub_00401040(0x61616161,0xa2bb7170,kernel32.MapViewOfFile(<0x004010d0>,0x000f001f,0,0,0))
        .text:0x0040112d  83c40c           add esp,12
        .text:0x00401130  8bf8             mov edi,eax
        .text:0x00401132  6a14             push 20
        .text:0x00401134  57               push edi
        .text:0x00401135  ffd3             call ebx    ;kernel32.IsBadReadPtr(sub_00401040(0x61616161,0xa2bb7170,<0x004010e6>),20)
        .text:0x00401137  85c0             test eax,eax
        .text:0x00401139  0f8596000000     jnz 0x004011d5
        .text:0x0040113f  83c70c           add edi,12
        .text:0x00401142  loc_00401142: [1 XREFS]
        .text:0x00401142  8b47f8           mov eax,dword [edi - 8]
        .text:0x00401145  897c2420         mov dword [esp + 32],edi
        .text:0x00401149  85c0             test eax,eax
        .text:0x0040114b  7505             jnz 0x00401152
        .text:0x0040114d  833f00           cmp dword [edi],0
        .text:0x00401150  745a             jz 0x004011ac
        .text:0x00401152  loc_00401152: [1 XREFS]
        .text:0x00401152  8b17             mov edx,dword [edi]
        .text:0x00401154  56               push esi
        .text:0x00401155  55               push ebp
        .text:0x00401156  52               push edx
        .text:0x00401157  e8e4feffff       call 0x00401040    ;sub_00401040(0x61616161,0xa2bb7170,<0x004010e6>)
        .text:0x0040115c  83c40c           add esp,12
        .text:0x0040115f  8bd8             mov ebx,eax
        .text:0x00401161  6a14             push 20
        .text:0x00401163  53               push ebx
        .text:0x00401164  ff1508204000     call dword [0x00402008]    ;kernel32.IsBadReadPtr(sub_00401040(0x61616161,0xa2bb7170,<0x004010e6>),20)
        .text:0x0040116a  85c0             test eax,eax
        .text:0x0040116c  7567             jnz 0x004011d5
        .text:0x0040116e  6820304000       push 0x00403020
        .text:0x00401173  53               push ebx
        .text:0x00401174  ff1564204000     call dword [0x00402064]    ;msvcrt._stricmp(<0x00401157>,0x00403020)
        .text:0x0040117a  83c408           add esp,8
        .text:0x0040117d  85c0             test eax,eax
        .text:0x0040117f  7526             jnz 0x004011a7
        .text:0x00401181  8bfb             mov edi,ebx
        .text:0x00401183  83c9ff           or ecx,0xffffffff
        .text:0x00401186  f2ae             repnz: scasb 
        .text:0x00401188  f7d1             not ecx
        .text:0x0040118a  8bc1             mov eax,ecx
        .text:0x0040118c  be10304000       mov esi,0x00403010
        .text:0x00401191  8bfb             mov edi,ebx
        .text:0x00401193  c1e902           shr ecx,2
        .text:0x00401196  f3a5             rep: movsd 
        .text:0x00401198  8bc8             mov ecx,eax
        .text:0x0040119a  83e103           and ecx,3
        .text:0x0040119d  f3a4             rep: movsb 
        .text:0x0040119f  8b742410         mov esi,dword [esp + 16]
        .text:0x004011a3  8b7c2420         mov edi,dword [esp + 32]
        .text:0x004011a7  loc_004011a7: [1 XREFS]
        .text:0x004011a7  83c714           add edi,20
        .text:0x004011aa  eb96             jmp 0x00401142
        .text:0x004011ac  loc_004011ac: [1 XREFS]
        .text:0x004011ac  81c5d0000000     add ebp,208
        .text:0x004011b2  33c9             xor ecx,ecx
        .text:0x004011b4  56               push esi
        .text:0x004011b5  894d00           mov dword [ebp],ecx
        .text:0x004011b8  894d04           mov dword [ebp + 4],ecx
        .text:0x004011bb  ff1504204000     call dword [0x00402004]    ;kernel32.UnmapViewOfFile(<0x004010e6>)
        .text:0x004011c1  8b542414         mov edx,dword [esp + 20]
        .text:0x004011c5  8b3500204000     mov esi,dword [0x00402000]
        .text:0x004011cb  52               push edx
        .text:0x004011cc  ffd6             call esi    ;kernel32.CloseHandle(<0x004010d0>)
        .text:0x004011ce  8b442418         mov eax,dword [esp + 24]
        .text:0x004011d2  50               push eax
        .text:0x004011d3  ffd6             call esi    ;kernel32.CloseHandle(<0x004010bb>)
        .text:0x004011d5  loc_004011d5: [5 XREFS]
        .text:0x004011d5  5f               pop edi
        .text:0x004011d6  5e               pop esi
        .text:0x004011d7  5d               pop ebp
        .text:0x004011d8  5b               pop ebx
        .text:0x004011d9  83c40c           add esp,12
        .text:0x004011dc  c3               ret 
        */
        $c2 = { 83 EC 0C 53 8B 44 24 ?? 55 56 57 6A 00 6A 00 6A 03 6A 00 6A 01 68 00 00 00 10 50 FF 15 ?? ?? ?? ?? 6A 00 6A 00 6A 00 6A 04 6A 00 50 89 44 24 ?? FF 15 ?? ?? ?? ?? 6A 00 6A 00 6A 00 68 1F 00 0F 00 50 89 44 24 ?? FF 15 ?? ?? ?? ?? 8B F0 85 F6 89 74 24 ?? 0F 84 ?? ?? ?? ?? 8B 6E ?? 8B 1D ?? ?? ?? ?? 03 EE 6A 04 55 FF D3 85 C0 0F 85 ?? ?? ?? ?? 81 7D ?? 50 45 00 00 0F 85 ?? ?? ?? ?? 8B 8D ?? ?? ?? ?? 56 55 51 E8 ?? ?? ?? ?? 83 C4 0C 8B F8 6A 14 57 FF D3 85 C0 0F 85 ?? ?? ?? ?? 83 C7 0C 8B 47 ?? 89 7C 24 ?? 85 C0 75 ?? 83 3F 00 74 ?? 8B 17 56 55 52 E8 ?? ?? ?? ?? 83 C4 0C 8B D8 6A 14 53 FF 15 ?? ?? ?? ?? 85 C0 75 ?? 68 20 30 40 00 53 FF 15 ?? ?? ?? ?? 83 C4 08 85 C0 75 ?? 8B FB 83 C9 FF F2 AE F7 D1 8B C1 BE 10 30 40 00 8B FB C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 74 24 ?? 8B 7C 24 ?? 83 C7 14 EB ?? 81 C5 D0 00 00 00 33 C9 56 89 4D ?? 89 4D ?? FF 15 ?? ?? ?? ?? 8B 54 24 ?? 8B 35 ?? ?? ?? ?? 52 FF D6 8B 44 24 ?? 50 FF D6 5F 5E 5D 5B 83 C4 0C C3 }
        /*
function at 0x00401000@bb7425b82141a1c0f7d60e5106676bb1 with 1 features:
          - enumerate PE sections
        .text:0x00401000  Segment: .text (4096 bytes)
        .text:0x00401000  
        .text:0x00401000  FUNC: int cdecl sub_00401000( int arg0, int arg1, ) [4 XREFS] 
        .text:0x00401000  
        .text:0x00401000  Stack Variables: (offset from initial top of stack)
        .text:0x00401000             8: int arg1
        .text:0x00401000             4: int arg0
        .text:0x00401000  
        .text:0x00401000  8b542408         mov edx,dword [esp + 8]
        .text:0x00401004  33c0             xor eax,eax
        .text:0x00401006  33c9             xor ecx,ecx
        .text:0x00401008  53               push ebx
        .text:0x00401009  668b4214         mov ax,word [edx + 20]
        .text:0x0040100d  668b4a06         mov cx,word [edx + 6]
        .text:0x00401011  56               push esi
        .text:0x00401012  33f6             xor esi,esi
        .text:0x00401014  85c9             test ecx,ecx
        .text:0x00401016  57               push edi
        .text:0x00401017  8d441018         lea eax,dword [eax + edx + 24]
        .text:0x0040101b  7e1c             jle 0x00401039
        .text:0x0040101d  8b7c2410         mov edi,dword [esp + 16]
        .text:0x00401021  loc_00401021: [1 XREFS]
        .text:0x00401021  8b500c           mov edx,dword [eax + 12]
        .text:0x00401024  3bfa             cmp edi,edx
        .text:0x00401026  7209             jc 0x00401031
        .text:0x00401028  8b5808           mov ebx,dword [eax + 8]
        .text:0x0040102b  03da             add ebx,edx
        .text:0x0040102d  3bfb             cmp edi,ebx
        .text:0x0040102f  720a             jc 0x0040103b
        .text:0x00401031  loc_00401031: [1 XREFS]
        .text:0x00401031  46               inc esi
        .text:0x00401032  83c028           add eax,40
        .text:0x00401035  3bf1             cmp esi,ecx
        .text:0x00401037  7ce8             jl 0x00401021
        .text:0x00401039  loc_00401039: [1 XREFS]
        .text:0x00401039  33c0             xor eax,eax
        .text:0x0040103b  loc_0040103b: [1 XREFS]
        .text:0x0040103b  5f               pop edi
        .text:0x0040103c  5e               pop esi
        .text:0x0040103d  5b               pop ebx
        .text:0x0040103e  c3               ret 
        */
        $c3 = { 8B 54 24 ?? 33 C0 33 C9 53 66 8B 42 ?? 66 8B 4A ?? 56 33 F6 85 C9 57 8D 44 10 ?? 7E ?? 8B 7C 24 ?? 8B 50 ?? 3B FA 72 ?? 8B 58 ?? 03 DA 3B FB 72 ?? 46 83 C0 28 3B F1 7C ?? 33 C0 5F 5E 5B C3 }
    condition:
        all of them
}

