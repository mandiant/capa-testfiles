rule super_rule_1c444
{
    meta:
        author = "CAPA Matches"
        date_created = "2023-08-10"
        date_modified = "2023-08-10"
        description = ""
        md5 = "1c444ebeba24dcba8628b7dfe5fec7c6"
    strings:
        /*
function Reqss.Reqss::<OK>b__4d 0x0600006d@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - save image in .NET
        133F    02                  ldarg.0        
        1340    7b a8 00 00 04      ldfld          _temp_image_
        1345    02                  ldarg.0        
        1346    7b 9e 00 00 04      ldfld          _temp_dir1
        134B    28 63 00 00 0a      call           System.Drawing.Imaging.ImageFormat::get_Jpeg
        1350    6f 64 00 00 0a      callvirt       System.Drawing.Image::Save
        1355    2a                  ret            
        */
        $c0 = { 02 7B ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 2A }
        /*
function Screenss.ScreenCapture::CaptureWindow 0x06000073@1c444ebeba24dcba8628b7dfe5fec7c6 with 2 features:
          - capture screenshot
          - unmanaged call
        1F74    03                  ldarg.1        
        1F75    28 7d 00 00 06      call           GetWindowDC
        1F7A    0a                  stloc.0        
        1F7B    12 01               ldloca.s       local(0x0001)
        1F7D    fe 15 0a 00 00 02   initobj        .RECT
        1F83    03                  ldarg.1        
        1F84    12 01               ldloca.s       local(0x0001)
        1F86    28 7f 00 00 06      call           GetWindowRect
        1F8B    26                  pop            
        1F8C    12 01               ldloca.s       local(0x0001)
        1F8E    7b 7b 00 00 04      ldfld          right
        1F93    12 01               ldloca.s       local(0x0001)
        1F95    7b 79 00 00 04      ldfld          left
        1F9A    59                  sub            
        1F9B    0c                  stloc.2        
        1F9C    12 01               ldloca.s       local(0x0001)
        1F9E    7b 7c 00 00 04      ldfld          bottom
        1FA3    12 01               ldloca.s       local(0x0001)
        1FA5    7b 7a 00 00 04      ldfld          top
        1FAA    59                  sub            
        1FAB    0d                  stloc.3        
        1FAC    06                  ldloc.0        
        1FAD    28 77 00 00 06      call           CreateCompatibleDC
        1FB2    13 04               stloc.s        local(0x0004)
        1FB4    06                  ldloc.0        
        1FB5    08                  ldloc.2        
        1FB6    09                  ldloc.3        
        1FB7    28 76 00 00 06      call           CreateCompatibleBitmap
        1FBC    13 05               stloc.s        local(0x0005)
        1FBE    11 04               ldloc.s        local(0x0004)
        1FC0    11 05               ldloc.s        local(0x0005)
        1FC2    28 7a 00 00 06      call           SelectObject
        1FC7    13 06               stloc.s        local(0x0006)
        1FC9    11 04               ldloc.s        local(0x0004)
        1FCB    16                  ldc.i4.0       
        1FCC    16                  ldc.i4.0       
        1FCD    08                  ldloc.2        
        1FCE    09                  ldloc.3        
        1FCF    06                  ldloc.0        
        1FD0    16                  ldc.i4.0       
        1FD1    16                  ldc.i4.0       
        1FD2    20 20 00 cc 00      ldc.i4         0xcc0020
        1FD7    28 75 00 00 06      call           BitBlt
        1FDC    26                  pop            
        1FDD    11 04               ldloc.s        local(0x0004)
        1FDF    11 06               ldloc.s        local(0x0006)
        1FE1    28 7a 00 00 06      call           SelectObject
        1FE6    26                  pop            
        1FE7    11 04               ldloc.s        local(0x0004)
        1FE9    28 78 00 00 06      call           DeleteDC
        1FEE    26                  pop            
        1FEF    03                  ldarg.1        
        1FF0    06                  ldloc.0        
        1FF1    28 7e 00 00 06      call           ReleaseDC
        1FF6    26                  pop            
        1FF7    11 05               ldloc.s        local(0x0005)
        1FF9    28 65 00 00 0a      call           System.Drawing.Image::FromHbitmap
        1FFE    13 07               stloc.s        local(0x0007)
        2000    11 05               ldloc.s        local(0x0005)
        2002    28 79 00 00 06      call           DeleteObject
        2007    26                  pop            
        2008    11 07               ldloc.s        local(0x0007)
        200A    2a                  ret            
        */
        $c1 = { 03 28 ?? ?? ?? ?? 0A 12 ?? FE 15 ?? ?? ?? ?? 03 12 ?? 28 ?? ?? ?? ?? 26 12 ?? 7B ?? ?? ?? ?? 12 ?? 7B ?? ?? ?? ?? 59 0C 12 ?? 7B ?? ?? ?? ?? 12 ?? 7B ?? ?? ?? ?? 59 0D 06 28 ?? ?? ?? ?? 13 ?? 06 08 09 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 16 16 08 09 06 16 16 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 26 11 ?? 11 ?? 28 ?? ?? ?? ?? 26 11 ?? 28 ?? ?? ?? ?? 26 03 06 28 ?? ?? ?? ?? 26 11 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 28 ?? ?? ?? ?? 26 11 ?? 2A }
        /*
function Uploadss.Uploadss::MultiPart 0x06000096@1c444ebeba24dcba8628b7dfe5fec7c6 with 7 features:
          - create HTTP request
          - get file size
          - receive HTTP response
          - send HTTP request
          - send data
          - send request in .NET
          - set web proxy in .NET
        2AA8    72 01 00 00 70      ldstr          ""
        2AAD    0a                  stloc.0        
        2AAE    03                  ldarg.1        
        2AAF    28 97 00 00 0a      call           System.Net.WebRequest::Create
        2AB4    74 58 00 00 01      castclass      System.Net.HttpWebRequest
        2AB9    0b                  stloc.1        
        2ABA    07                  ldloc.1        
        2ABB    1c                  ldc.i4.6       
        2ABC    73 98 00 00 0a      newobj         System.Net.Cache.RequestCachePolicy::.ctor
        2AC1    6f 99 00 00 0a      callvirt       System.Net.WebRequest::set_CachePolicy
        2AC6    07                  ldloc.1        
        2AC7    14                  ldnull         
        2AC8    6f 9a 00 00 0a      callvirt       System.Net.WebRequest::set_Proxy
        2ACD    07                  ldloc.1        
        2ACE    19                  ldc.i4.3       
        2ACF    6f 9b 00 00 0a      callvirt       System.Net.HttpWebRequest::set_AutomaticDecompression
        2AD4    07                  ldloc.1        
        2AD5    20 30 75 00 00      ldc.i4         0x7530
        2ADA    6f 9c 00 00 0a      callvirt       System.Net.WebRequest::set_Timeout
        2ADF    07                  ldloc.1        
        2AE0    28 9d 00 00 0a      call           System.Text.Encoding::get_Default
        2AE5    1a                  ldc.i4.4       
        2AE6    8d 3d 00 00 01      newarr         System.Byte
        2AEB    25                  dup            
        2AEC    d0 b1 00 00 04      ldtoken        $$method0x600002a-1
        2AF1    28 9e 00 00 0a      call           System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray
        2AF6    6f 48 00 00 0a      callvirt       System.Text.Encoding::GetString
        2AFB    6f 9f 00 00 0a      callvirt       System.Net.WebRequest::set_Method
        2B00    28 a0 00 00 0a      call           System.DateTime::get_UtcNow
        2B05    13 1e               stloc.s        local(0x001E)
        2B07    12 1e               ldloca.s       local(0x001E)
        2B09    20 b2 07 00 00      ldc.i4         0x7b2
        2B0E    17                  ldc.i4.1       
        2B0F    17                  ldc.i4.1       
        2B10    73 a1 00 00 0a      newobj         System.DateTime::.ctor
        2B15    28 a2 00 00 0a      call           System.DateTime::Subtract
        2B1A    13 1f               stloc.s        local(0x001F)
        2B1C    12 1f               ldloca.s       local(0x001F)
        2B1E    28 a3 00 00 0a      call           System.TimeSpan::get_TotalMilliseconds
        2B23    6a                  conv.i8        
        2B24    0c                  stloc.2        
        2B25    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        2B2A    1f 14               ldc.i4.s       0x14
        2B2C    8d 3d 00 00 01      newarr         System.Byte
        2B31    25                  dup            
        2B32    d0 b2 00 00 04      ldtoken        $$method0x600002a-2
        2B37    28 9e 00 00 0a      call           System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray
        2B3C    6f 48 00 00 0a      callvirt       System.Text.Encoding::GetString
        2B41    0d                  stloc.3        
        2B42    09                  ldloc.3        
        2B43    08                  ldloc.2        
        2B44    8c 31 00 00 01      box            System.Int64
        2B49    28 52 00 00 0a      call           System.String::Concat
        2B4E    13 04               stloc.s        local(0x0004)
        2B50    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        2B55    18                  ldc.i4.2       
        2B56    8d 3d 00 00 01      newarr         System.Byte
        2B5B    13 20               stloc.s        local(0x0020)
        2B5D    11 20               ldloc.s        local(0x0020)
        2B5F    16                  ldc.i4.0       
        2B60    1f 0d               ldc.i4.s       0xd
        2B62    9c                  stelem.i1      
        2B63    11 20               ldloc.s        local(0x0020)
        2B65    17                  ldc.i4.1       
        2B66    1f 0a               ldc.i4.s       0xa
        2B68    9c                  stelem.i1      
        2B69    11 20               ldloc.s        local(0x0020)
        2B6B    6f 48 00 00 0a      callvirt       System.Text.Encoding::GetString
        2B70    26                  pop            
        2B71    07                  ldloc.1        
        2B72    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        2B77    1f 21               ldc.i4.s       0x21
        2B79    8d 3d 00 00 01      newarr         System.Byte
        2B7E    25                  dup            
        2B7F    d0 b3 00 00 04      ldtoken        $$method0x600002a-3
        2B84    28 9e 00 00 0a      call           System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray
        2B89    6f 48 00 00 0a      callvirt       System.Text.Encoding::GetString
        2B8E    11 04               ldloc.s        local(0x0004)
        2B90    28 a4 00 00 0a      call           System.String::Format
        2B95    6f a5 00 00 0a      callvirt       System.Net.WebRequest::set_ContentType
        2B9A    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        2B9F    18                  ldc.i4.2       
        2BA0    8d 3d 00 00 01      newarr         System.Byte
        2BA5    13 21               stloc.s        local(0x0021)
        2BA7    11 21               ldloc.s        local(0x0021)
        2BA9    16                  ldc.i4.0       
        2BAA    1f 2d               ldc.i4.s       0x2d
        2BAC    9c                  stelem.i1      
        2BAD    11 21               ldloc.s        local(0x0021)
        2BAF    17                  ldc.i4.1       
        2BB0    1f 2d               ldc.i4.s       0x2d
        2BB2    9c                  stelem.i1      
        2BB3    11 21               ldloc.s        local(0x0021)
        2BB5    6f 48 00 00 0a      callvirt       System.Text.Encoding::GetString
        2BBA    11 04               ldloc.s        local(0x0004)
        2BBC    28 50 00 00 0a      call           System.String::Concat
        2BC1    13 04               stloc.s        local(0x0004)
        2BC3    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        2BC8    11 04               ldloc.s        local(0x0004)
        2BCA    6f 2a 00 00 0a      callvirt       System.Text.Encoding::GetBytes
        2BCF    13 05               stloc.s        local(0x0005)
        2BD1    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        2BD6    1f 2e               ldc.i4.s       0x2e
        2BD8    8d 3d 00 00 01      newarr         System.Byte
        2BDD    25                  dup            
        2BDE    d0 b4 00 00 04      ldtoken        $$method0x600002a-4
        2BE3    28 9e 00 00 0a      call           System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray
        2BE8    6f 48 00 00 0a      callvirt       System.Text.Encoding::GetString
        2BED    13 06               stloc.s        local(0x0006)
        2BEF    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        2BF4    1f 51               ldc.i4.s       0x51
        2BF6    8d 3d 00 00 01      newarr         System.Byte
        2BFB    25                  dup            
        2BFC    d0 b5 00 00 04      ldtoken        $$method0x600002a-5
        2C01    28 9e 00 00 0a      call           System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray
        2C06    6f 48 00 00 0a      callvirt       System.Text.Encoding::GetString
        2C0B    13 07               stloc.s        local(0x0007)
        2C0D    16                  ldc.i4.0       
        2C0E    6a                  conv.i8        
        2C0F    13 08               stloc.s        local(0x0008)
        2C11    11 08               ldloc.s        local(0x0008)
        2C13    11 05               ldloc.s        local(0x0005)
        2C15    8e                  ldlen          
        2C16    69                  conv.i4        
        2C17    6a                  conv.i8        
        2C18    58                  add            
        2C19    13 08               stloc.s        local(0x0008)
        2C1B    04                  ldarg.2        
        2C1C    6f a6 00 00 0a      callvirt       GetEnumerator
        2C21    13 22               stloc.s        local(0x0022)
        2C23    2b 5a               br.s           0x2c7f
        2C25    12 22               ldloca.s       local(0x0022)
        2C27    28 a7 00 00 0a      call           get_Current
        2C2C    13 09               stloc.s        local(0x0009)
        2C2E    11 06               ldloc.s        local(0x0006)
        2C30    11 09               ldloc.s        local(0x0009)
        2C32    7b a9 00 00 04      ldfld          name
        2C37    28 a4 00 00 0a      call           System.String::Format
        2C3C    11 09               ldloc.s        local(0x0009)
        2C3E    7b aa 00 00 04      ldfld          value
        2C43    28 a8 00 00 0a      call           System.Uri::EscapeDataString
        2C48    28 50 00 00 0a      call           System.String::Concat
        2C4D    13 0a               stloc.s        local(0x000A)
        2C4F    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        2C54    11 0a               ldloc.s        local(0x000A)
        2C56    6f 2a 00 00 0a      callvirt       System.Text.Encoding::GetBytes
        2C5B    13 0b               stloc.s        local(0x000B)
        2C5D    11 08               ldloc.s        local(0x0008)
        2C5F    18                  ldc.i4.2       
        2C60    6a                  conv.i8        
        2C61    58                  add            
        2C62    13 08               stloc.s        local(0x0008)
        2C64    11 08               ldloc.s        local(0x0008)
        2C66    11 0b               ldloc.s        local(0x000B)
        2C68    8e                  ldlen          
        2C69    69                  conv.i4        
        2C6A    6a                  conv.i8        
        2C6B    58                  add            
        2C6C    13 08               stloc.s        local(0x0008)
        2C6E    11 08               ldloc.s        local(0x0008)
        2C70    18                  ldc.i4.2       
        2C71    6a                  conv.i8        
        2C72    58                  add            
        2C73    13 08               stloc.s        local(0x0008)
        2C75    11 08               ldloc.s        local(0x0008)
        2C77    11 05               ldloc.s        local(0x0005)
        2C79    8e                  ldlen          
        2C7A    69                  conv.i4        
        2C7B    6a                  conv.i8        
        2C7C    58                  add            
        2C7D    13 08               stloc.s        local(0x0008)
        2C7F    12 22               ldloca.s       local(0x0022)
        2C81    28 a9 00 00 0a      call           MoveNext
        2C86    2d 9d               brtrue.s       0x2c25
        2C88    de 0e               leave.s        0x2c98
        2C8A    12 22               ldloca.s       local(0x0022)
        2C8C    fe 16 07 00 00 1b   constrained.   [CLR_METADATA_TABLE_TYPESPEC]
        0x7032     0x0   Signature_BlobIndex:           5CF     
        2C92    6f 2f 00 00 0a      callvirt       System.IDisposable::Dispose
        2C97    dc                  endfinally     
        2C98    05                  ldarg.3        
        2C99    6f aa 00 00 0a      callvirt       GetEnumerator
        2C9E    13 23               stloc.s        local(0x0023)
        2CA0    2b 76               br.s           0x2d18
        2CA2    12 23               ldloca.s       local(0x0023)
        2CA4    28 ab 00 00 0a      call           get_Current
        2CA9    13 0c               stloc.s        local(0x000C)
        2CAB    11 07               ldloc.s        local(0x0007)
        2CAD    11 0c               ldloc.s        local(0x000C)
        2CAF    7b ab 00 00 04      ldfld          name
        2CB4    11 0c               ldloc.s        local(0x000C)
        2CB6    7b ac 00 00 04      ldfld          filepath
        2CBB    28 ac 00 00 0a      call           System.IO.Path::GetFileName
        2CC0    11 0c               ldloc.s        local(0x000C)
        2CC2    7b ad 00 00 04      ldfld          contenttype
        2CC7    28 ad 00 00 0a      call           System.String::Format
        2CCC    13 0d               stloc.s        local(0x000D)
        2CCE    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        2CD3    11 0d               ldloc.s        local(0x000D)
        2CD5    6f 2a 00 00 0a      callvirt       System.Text.Encoding::GetBytes
        2CDA    13 0e               stloc.s        local(0x000E)
        2CDC    11 08               ldloc.s        local(0x0008)
        2CDE    18                  ldc.i4.2       
        2CDF    6a                  conv.i8        
        2CE0    58                  add            
        2CE1    13 08               stloc.s        local(0x0008)
        2CE3    11 08               ldloc.s        local(0x0008)
        2CE5    11 0e               ldloc.s        local(0x000E)
        2CE7    8e                  ldlen          
        2CE8    69                  conv.i4        
        2CE9    6a                  conv.i8        
        2CEA    58                  add            
        2CEB    13 08               stloc.s        local(0x0008)
        2CED    11 0c               ldloc.s        local(0x000C)
        2CEF    7b ac 00 00 04      ldfld          filepath
        2CF4    73 24 00 00 0a      newobj         System.IO.FileInfo::.ctor
        2CF9    13 0f               stloc.s        local(0x000F)
        2CFB    11 08               ldloc.s        local(0x0008)
        2CFD    11 0f               ldloc.s        local(0x000F)
        2CFF    6f 4f 00 00 0a      callvirt       System.IO.FileInfo::get_Length
        2D04    58                  add            
        2D05    13 08               stloc.s        local(0x0008)
        2D07    11 08               ldloc.s        local(0x0008)
        2D09    18                  ldc.i4.2       
        2D0A    6a                  conv.i8        
        2D0B    58                  add            
        2D0C    13 08               stloc.s        local(0x0008)
        2D0E    11 08               ldloc.s        local(0x0008)
        2D10    11 05               ldloc.s        local(0x0005)
        2D12    8e                  ldlen          
        2D13    69                  conv.i4        
        2D14    6a                  conv.i8        
        2D15    58                  add            
        2D16    13 08               stloc.s        local(0x0008)
        2D18    12 23               ldloca.s       local(0x0023)
        2D1A    28 ae 00 00 0a      call           MoveNext
        2D1F    2d 81               brtrue.s       0x2ca2
        2D21    de 0e               leave.s        0x2d31
        2D23    12 23               ldloca.s       local(0x0023)
        2D25    fe 16 08 00 00 1b   constrained.   [CLR_METADATA_TABLE_TYPESPEC]
        0x7034     0x0   Signature_BlobIndex:           5DC     
        2D2B    6f 2f 00 00 0a      callvirt       System.IDisposable::Dispose
        2D30    dc                  endfinally     
        2D31    11 08               ldloc.s        local(0x0008)
        2D33    18                  ldc.i4.2       
        2D34    6a                  conv.i8        
        2D35    58                  add            
        2D36    13 08               stloc.s        local(0x0008)
        2D38    11 08               ldloc.s        local(0x0008)
        2D3A    18                  ldc.i4.2       
        2D3B    6a                  conv.i8        
        2D3C    58                  add            
        2D3D    13 08               stloc.s        local(0x0008)
        2D3F    07                  ldloc.1        
        2D40    11 08               ldloc.s        local(0x0008)
        2D42    6f af 00 00 0a      callvirt       System.Net.WebRequest::set_ContentLength
        2D47    07                  ldloc.1        
        2D48    6f b0 00 00 0a      callvirt       System.Net.WebRequest::GetRequestStream
        2D4D    13 10               stloc.s        local(0x0010)
        2D4F    11 10               ldloc.s        local(0x0010)
        2D51    11 05               ldloc.s        local(0x0005)
        2D53    16                  ldc.i4.0       
        2D54    11 05               ldloc.s        local(0x0005)
        2D56    8e                  ldlen          
        2D57    69                  conv.i4        
        2D58    6f 89 00 00 0a      callvirt       System.IO.Stream::Write
        2D5D    04                  ldarg.2        
        2D5E    6f a6 00 00 0a      callvirt       GetEnumerator
        2D63    13 24               stloc.s        local(0x0024)
        2D65    38 92 00 00 00      br             0x2dfc
        2D6A    12 24               ldloca.s       local(0x0024)
        2D6C    28 a7 00 00 0a      call           get_Current
        2D71    13 11               stloc.s        local(0x0011)
        2D73    11 06               ldloc.s        local(0x0006)
        2D75    11 11               ldloc.s        local(0x0011)
        2D77    7b a9 00 00 04      ldfld          name
        2D7C    28 a4 00 00 0a      call           System.String::Format
        2D81    11 11               ldloc.s        local(0x0011)
        2D83    7b aa 00 00 04      ldfld          value
        2D88    28 a8 00 00 0a      call           System.Uri::EscapeDataString
        2D8D    28 50 00 00 0a      call           System.String::Concat
        2D92    13 12               stloc.s        local(0x0012)
        2D94    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        2D99    11 12               ldloc.s        local(0x0012)
        2D9B    6f 2a 00 00 0a      callvirt       System.Text.Encoding::GetBytes
        2DA0    13 13               stloc.s        local(0x0013)
        2DA2    11 10               ldloc.s        local(0x0010)
        2DA4    18                  ldc.i4.2       
        2DA5    8d 3d 00 00 01      newarr         System.Byte
        2DAA    13 25               stloc.s        local(0x0025)
        2DAC    11 25               ldloc.s        local(0x0025)
        2DAE    16                  ldc.i4.0       
        2DAF    1f 0d               ldc.i4.s       0xd
        2DB1    9c                  stelem.i1      
        2DB2    11 25               ldloc.s        local(0x0025)
        2DB4    17                  ldc.i4.1       
        2DB5    1f 0a               ldc.i4.s       0xa
        2DB7    9c                  stelem.i1      
        2DB8    11 25               ldloc.s        local(0x0025)
        2DBA    16                  ldc.i4.0       
        2DBB    18                  ldc.i4.2       
        2DBC    6f 89 00 00 0a      callvirt       System.IO.Stream::Write
        2DC1    11 10               ldloc.s        local(0x0010)
        2DC3    11 13               ldloc.s        local(0x0013)
        2DC5    16                  ldc.i4.0       
        2DC6    11 13               ldloc.s        local(0x0013)
        2DC8    8e                  ldlen          
        2DC9    69                  conv.i4        
        2DCA    6f 89 00 00 0a      callvirt       System.IO.Stream::Write
        2DCF    11 10               ldloc.s        local(0x0010)
        2DD1    18                  ldc.i4.2       
        2DD2    8d 3d 00 00 01      newarr         System.Byte
        2DD7    13 26               stloc.s        local(0x0026)
        2DD9    11 26               ldloc.s        local(0x0026)
        2DDB    16                  ldc.i4.0       
        2DDC    1f 0d               ldc.i4.s       0xd
        2DDE    9c                  stelem.i1      
        2DDF    11 26               ldloc.s        local(0x0026)
        2DE1    17                  ldc.i4.1       
        2DE2    1f 0a               ldc.i4.s       0xa
        2DE4    9c                  stelem.i1      
        2DE5    11 26               ldloc.s        local(0x0026)
        2DE7    16                  ldc.i4.0       
        2DE8    18                  ldc.i4.2       
        2DE9    6f 89 00 00 0a      callvirt       System.IO.Stream::Write
        2DEE    11 10               ldloc.s        local(0x0010)
        2DF0    11 05               ldloc.s        local(0x0005)
        2DF2    16                  ldc.i4.0       
        2DF3    11 05               ldloc.s        local(0x0005)
        2DF5    8e                  ldlen          
        2DF6    69                  conv.i4        
        2DF7    6f 89 00 00 0a      callvirt       System.IO.Stream::Write
        2DFC    12 24               ldloca.s       local(0x0024)
        2DFE    28 a9 00 00 0a      call           MoveNext
        2E03    3a 62 ff ff ff      brtrue         0x2d6a
        2E08    de 0e               leave.s        0x2e18
        2E0A    12 24               ldloca.s       local(0x0024)
        2E0C    fe 16 07 00 00 1b   constrained.   [CLR_METADATA_TABLE_TYPESPEC]
        0x7032     0x0   Signature_BlobIndex:           5CF     
        2E12    6f 2f 00 00 0a      callvirt       System.IDisposable::Dispose
        2E17    dc                  endfinally     
        2E18    05                  ldarg.3        
        2E19    6f aa 00 00 0a      callvirt       GetEnumerator
        2E1E    13 27               stloc.s        local(0x0027)
        2E20    38 ea 00 00 00      br             0x2f0f
        2E25    12 27               ldloca.s       local(0x0027)
        2E27    28 ab 00 00 0a      call           get_Current
        2E2C    13 14               stloc.s        local(0x0014)
        2E2E    11 07               ldloc.s        local(0x0007)
        2E30    11 14               ldloc.s        local(0x0014)
        2E32    7b ab 00 00 04      ldfld          name
        2E37    11 14               ldloc.s        local(0x0014)
        2E39    7b ac 00 00 04      ldfld          filepath
        2E3E    28 ac 00 00 0a      call           System.IO.Path::GetFileName
        2E43    11 14               ldloc.s        local(0x0014)
        2E45    7b ad 00 00 04      ldfld          contenttype
        2E4A    28 ad 00 00 0a      call           System.String::Format
        2E4F    13 15               stloc.s        local(0x0015)
        2E51    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        2E56    11 15               ldloc.s        local(0x0015)
        2E58    6f 2a 00 00 0a      callvirt       System.Text.Encoding::GetBytes
        2E5D    13 16               stloc.s        local(0x0016)
        2E5F    11 10               ldloc.s        local(0x0010)
        2E61    18                  ldc.i4.2       
        2E62    8d 3d 00 00 01      newarr         System.Byte
        2E67    13 28               stloc.s        local(0x0028)
        2E69    11 28               ldloc.s        local(0x0028)
        2E6B    16                  ldc.i4.0       
        2E6C    1f 0d               ldc.i4.s       0xd
        2E6E    9c                  stelem.i1      
        2E6F    11 28               ldloc.s        local(0x0028)
        2E71    17                  ldc.i4.1       
        2E72    1f 0a               ldc.i4.s       0xa
        2E74    9c                  stelem.i1      
        2E75    11 28               ldloc.s        local(0x0028)
        2E77    16                  ldc.i4.0       
        2E78    18                  ldc.i4.2       
        2E79    6f 89 00 00 0a      callvirt       System.IO.Stream::Write
        2E7E    11 10               ldloc.s        local(0x0010)
        2E80    11 16               ldloc.s        local(0x0016)
        2E82    16                  ldc.i4.0       
        2E83    11 16               ldloc.s        local(0x0016)
        2E85    8e                  ldlen          
        2E86    69                  conv.i4        
        2E87    6f 89 00 00 0a      callvirt       System.IO.Stream::Write
        2E8C    11 14               ldloc.s        local(0x0014)
        2E8E    7b ac 00 00 04      ldfld          filepath
        2E93    19                  ldc.i4.3       
        2E94    17                  ldc.i4.1       
        2E95    73 b1 00 00 0a      newobj         System.IO.FileStream::.ctor
        2E9A    13 17               stloc.s        local(0x0017)
        2E9C    20 00 00 10 00      ldc.i4         0x100000
        2EA1    8d 3d 00 00 01      newarr         System.Byte
        2EA6    13 18               stloc.s        local(0x0018)
        2EA8    11 17               ldloc.s        local(0x0017)
        2EAA    11 18               ldloc.s        local(0x0018)
        2EAC    16                  ldc.i4.0       
        2EAD    11 18               ldloc.s        local(0x0018)
        2EAF    8e                  ldlen          
        2EB0    69                  conv.i4        
        2EB1    6f 84 00 00 0a      callvirt       System.IO.Stream::Read
        2EB6    13 19               stloc.s        local(0x0019)
        2EB8    2b 1c               br.s           0x2ed6
        2EBA    11 10               ldloc.s        local(0x0010)
        2EBC    11 18               ldloc.s        local(0x0018)
        2EBE    16                  ldc.i4.0       
        2EBF    11 19               ldloc.s        local(0x0019)
        2EC1    6f 89 00 00 0a      callvirt       System.IO.Stream::Write
        2EC6    11 17               ldloc.s        local(0x0017)
        2EC8    11 18               ldloc.s        local(0x0018)
        2ECA    16                  ldc.i4.0       
        2ECB    11 18               ldloc.s        local(0x0018)
        2ECD    8e                  ldlen          
        2ECE    69                  conv.i4        
        2ECF    6f 84 00 00 0a      callvirt       System.IO.Stream::Read
        2ED4    13 19               stloc.s        local(0x0019)
        2ED6    11 19               ldloc.s        local(0x0019)
        2ED8    16                  ldc.i4.0       
        2ED9    30 df               bgt.s          0x2eba
        2EDB    11 17               ldloc.s        local(0x0017)
        2EDD    6f b2 00 00 0a      callvirt       System.IO.Stream::Close
        2EE2    11 10               ldloc.s        local(0x0010)
        2EE4    18                  ldc.i4.2       
        2EE5    8d 3d 00 00 01      newarr         System.Byte
        2EEA    13 29               stloc.s        local(0x0029)
        2EEC    11 29               ldloc.s        local(0x0029)
        2EEE    16                  ldc.i4.0       
        2EEF    1f 0d               ldc.i4.s       0xd
        2EF1    9c                  stelem.i1      
        2EF2    11 29               ldloc.s        local(0x0029)
        2EF4    17                  ldc.i4.1       
        2EF5    1f 0a               ldc.i4.s       0xa
        2EF7    9c                  stelem.i1      
        2EF8    11 29               ldloc.s        local(0x0029)
        2EFA    16                  ldc.i4.0       
        2EFB    18                  ldc.i4.2       
        2EFC    6f 89 00 00 0a      callvirt       System.IO.Stream::Write
        2F01    11 10               ldloc.s        local(0x0010)
        2F03    11 05               ldloc.s        local(0x0005)
        2F05    16                  ldc.i4.0       
        2F06    11 05               ldloc.s        local(0x0005)
        2F08    8e                  ldlen          
        2F09    69                  conv.i4        
        2F0A    6f 89 00 00 0a      callvirt       System.IO.Stream::Write
        2F0F    12 27               ldloca.s       local(0x0027)
        2F11    28 ae 00 00 0a      call           MoveNext
        2F16    3a 0a ff ff ff      brtrue         0x2e25
        2F1B    de 0e               leave.s        0x2f2b
        2F1D    12 27               ldloca.s       local(0x0027)
        2F1F    fe 16 08 00 00 1b   constrained.   [CLR_METADATA_TABLE_TYPESPEC]
        0x7034     0x0   Signature_BlobIndex:           5DC     
        2F25    6f 2f 00 00 0a      callvirt       System.IDisposable::Dispose
        2F2A    dc                  endfinally     
        2F2B    11 10               ldloc.s        local(0x0010)
        2F2D    18                  ldc.i4.2       
        2F2E    8d 3d 00 00 01      newarr         System.Byte
        2F33    13 2a               stloc.s        local(0x002A)
        2F35    11 2a               ldloc.s        local(0x002A)
        2F37    16                  ldc.i4.0       
        2F38    1f 2d               ldc.i4.s       0x2d
        2F3A    9c                  stelem.i1      
        2F3B    11 2a               ldloc.s        local(0x002A)
        2F3D    17                  ldc.i4.1       
        2F3E    1f 2d               ldc.i4.s       0x2d
        2F40    9c                  stelem.i1      
        2F41    11 2a               ldloc.s        local(0x002A)
        2F43    16                  ldc.i4.0       
        2F44    18                  ldc.i4.2       
        2F45    6f 89 00 00 0a      callvirt       System.IO.Stream::Write
        2F4A    11 10               ldloc.s        local(0x0010)
        2F4C    18                  ldc.i4.2       
        2F4D    8d 3d 00 00 01      newarr         System.Byte
        2F52    13 2b               stloc.s        local(0x002B)
        2F54    11 2b               ldloc.s        local(0x002B)
        2F56    16                  ldc.i4.0       
        2F57    1f 0d               ldc.i4.s       0xd
        2F59    9c                  stelem.i1      
        2F5A    11 2b               ldloc.s        local(0x002B)
        2F5C    17                  ldc.i4.1       
        2F5D    1f 0a               ldc.i4.s       0xa
        2F5F    9c                  stelem.i1      
        2F60    11 2b               ldloc.s        local(0x002B)
        2F62    16                  ldc.i4.0       
        2F63    18                  ldc.i4.2       
        2F64    6f 89 00 00 0a      callvirt       System.IO.Stream::Write
        2F69    11 10               ldloc.s        local(0x0010)
        2F6B    6f 8a 00 00 0a      callvirt       System.IO.Stream::Flush
        2F70    11 10               ldloc.s        local(0x0010)
        2F72    6f b2 00 00 0a      callvirt       System.IO.Stream::Close
        2F77    07                  ldloc.1        
        2F78    6f b3 00 00 0a      callvirt       System.Net.WebRequest::GetResponse
        2F7D    74 67 00 00 01      castclass      System.Net.HttpWebResponse
        2F82    13 1a               stloc.s        local(0x001A)
        2F84    11 1a               ldloc.s        local(0x001A)
        2F86    6f b4 00 00 0a      callvirt       System.Net.WebResponse::GetResponseStream
        2F8B    13 1b               stloc.s        local(0x001B)
        2F8D    11 1b               ldloc.s        local(0x001B)
        2F8F    73 b5 00 00 0a      newobj         System.IO.StreamReader::.ctor
        2F94    13 1c               stloc.s        local(0x001C)
        2F96    11 1c               ldloc.s        local(0x001C)
        2F98    6f b6 00 00 0a      callvirt       System.IO.TextReader::ReadToEnd
        2F9D    0a                  stloc.0        
        2F9E    11 1c               ldloc.s        local(0x001C)
        2FA0    6f b7 00 00 0a      callvirt       System.IO.TextReader::Close
        2FA5    11 1b               ldloc.s        local(0x001B)
        2FA7    6f b2 00 00 0a      callvirt       System.IO.Stream::Close
        2FAC    11 1a               ldloc.s        local(0x001A)
        2FAE    6f b8 00 00 0a      callvirt       System.Net.WebResponse::Close
        2FB3    de 18               leave.s        0x2fcd
        2FB5    13 1d               stloc.s        local(0x001D)
        2FB7    11 1d               ldloc.s        local(0x001D)
        2FB9    6f b9 00 00 0a      callvirt       System.Net.WebException::get_Response
        2FBE    6f b8 00 00 0a      callvirt       System.Net.WebResponse::Close
        2FC3    de 03               leave.s        0x2fc8
        2FC5    26                  pop            
        2FC6    de 00               leave.s        0x2fc8
        2FC8    de 03               leave.s        0x2fcd
        2FCA    26                  pop            
        2FCB    de 00               leave.s        0x2fcd
        2FCD    06                  ldloc.0        
        2FCE    2a                  ret            
        */
        $c2 = { 72 ?? ?? ?? ?? 0A 03 28 ?? ?? ?? ?? 74 ?? ?? ?? ?? 0B 07 1C 73 ?? ?? ?? ?? 6F ?? ?? ?? ?? 07 14 6F ?? ?? ?? ?? 07 19 6F ?? ?? ?? ?? 07 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 07 28 ?? ?? ?? ?? 1A 8D ?? ?? ?? ?? 25 D0 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 12 ?? 20 ?? ?? ?? ?? 17 17 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 12 ?? 28 ?? ?? ?? ?? 6A 0C 28 ?? ?? ?? ?? 1F ?? 8D ?? ?? ?? ?? 25 D0 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 0D 09 08 8C ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 28 ?? ?? ?? ?? 18 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 1F ?? 9C 11 ?? 17 1F ?? 9C 11 ?? 6F ?? ?? ?? ?? 26 07 28 ?? ?? ?? ?? 1F ?? 8D ?? ?? ?? ?? 25 D0 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 18 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 1F ?? 9C 11 ?? 17 1F ?? 9C 11 ?? 6F ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 13 ?? 28 ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 28 ?? ?? ?? ?? 1F ?? 8D ?? ?? ?? ?? 25 D0 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ?? 28 ?? ?? ?? ?? 1F ?? 8D ?? ?? ?? ?? 25 D0 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 13 ?? 16 6A 13 ?? 11 ?? 11 ?? 8E 69 6A 58 13 ?? 04 6F ?? ?? ?? ?? 13 ?? 2B ?? 12 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 11 ?? 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 28 ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 18 6A 58 13 ?? 11 ?? 11 ?? 8E 69 6A 58 13 ?? 11 ?? 18 6A 58 13 ?? 11 ?? 11 ?? 8E 69 6A 58 13 ?? 12 ?? 28 ?? ?? ?? ?? 2D ?? DE ?? 12 ?? FE 16 ?? ?? ?? ?? 6F ?? ?? ?? ?? DC 05 6F ?? ?? ?? ?? 13 ?? 2B ?? 12 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 7B ?? ?? ?? ?? 11 ?? 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 11 ?? 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 28 ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 18 6A 58 13 ?? 11 ?? 11 ?? 8E 69 6A 58 13 ?? 11 ?? 7B ?? ?? ?? ?? 73 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 6F ?? ?? ?? ?? 58 13 ?? 11 ?? 18 6A 58 13 ?? 11 ?? 11 ?? 8E 69 6A 58 13 ?? 12 ?? 28 ?? ?? ?? ?? 2D ?? DE ?? 12 ?? FE 16 ?? ?? ?? ?? 6F ?? ?? ?? ?? DC 11 ?? 18 6A 58 13 ?? 11 ?? 18 6A 58 13 ?? 07 11 ?? 6F ?? ?? ?? ?? 07 6F ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 04 6F ?? ?? ?? ?? 13 ?? 38 ?? ?? ?? ?? 12 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 11 ?? 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 28 ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 18 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 1F ?? 9C 11 ?? 17 1F ?? 9C 11 ?? 16 18 6F ?? ?? ?? ?? 11 ?? 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 11 ?? 18 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 1F ?? 9C 11 ?? 17 1F ?? 9C 11 ?? 16 18 6F ?? ?? ?? ?? 11 ?? 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 12 ?? 28 ?? ?? ?? ?? 3A ?? ?? ?? ?? DE ?? 12 ?? FE 16 ?? ?? ?? ?? 6F ?? ?? ?? ?? DC 05 6F ?? ?? ?? ?? 13 ?? 38 ?? ?? ?? ?? 12 ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 7B ?? ?? ?? ?? 11 ?? 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 11 ?? 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 28 ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 18 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 1F ?? 9C 11 ?? 17 1F ?? 9C 11 ?? 16 18 6F ?? ?? ?? ?? 11 ?? 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 11 ?? 7B ?? ?? ?? ?? 19 17 73 ?? ?? ?? ?? 13 ?? 20 ?? ?? ?? ?? 8D ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 13 ?? 2B ?? 11 ?? 11 ?? 16 11 ?? 6F ?? ?? ?? ?? 11 ?? 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 13 ?? 11 ?? 16 30 ?? 11 ?? 6F ?? ?? ?? ?? 11 ?? 18 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 1F ?? 9C 11 ?? 17 1F ?? 9C 11 ?? 16 18 6F ?? ?? ?? ?? 11 ?? 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 12 ?? 28 ?? ?? ?? ?? 3A ?? ?? ?? ?? DE ?? 12 ?? FE 16 ?? ?? ?? ?? 6F ?? ?? ?? ?? DC 11 ?? 18 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 1F ?? 9C 11 ?? 17 1F ?? 9C 11 ?? 16 18 6F ?? ?? ?? ?? 11 ?? 18 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 1F ?? 9C 11 ?? 17 1F ?? 9C 11 ?? 16 18 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 07 6F ?? ?? ?? ?? 74 ?? ?? ?? ?? 13 ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 73 ?? ?? ?? ?? 13 ?? 11 ?? 6F ?? ?? ?? ?? 0A 11 ?? 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? DE ?? 13 ?? 11 ?? 6F ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 26 DE ?? DE ?? 26 DE ?? 06 2A }
        /*
function WebDL.WebDL::_down1 0x0600009b@1c444ebeba24dcba8628b7dfe5fec7c6 with 6 features:
          - check if file exists
          - create HTTP request
          - manipulate console buffer
          - receive HTTP response
          - send HTTP request
          - send data
        3144    72 01 00 00 70      ldstr          ""
        3149    0a                  stloc.0        
        314A    02                  ldarg.0        
        314B    04                  ldarg.2        
        314C    28 99 00 00 06      call           _getName
        3151    0b                  stloc.1        
        3152    07                  ldloc.1        
        3153    72 01 00 00 70      ldstr          ""
        3158    28 bd 00 00 0a      call           System.String::op_Equality
        315D    2c 08               brfalse.s      0x3167
        315F    06                  ldloc.0        
        3160    13 0a               stloc.s        local(0x000A)
        3162    dd c3 00 00 00      leave          0x322a
        3167    03                  ldarg.1        
        3168    07                  ldloc.1        
        3169    28 60 00 00 0a      call           System.IO.Path::Combine
        316E    0c                  stloc.2        
        316F    08                  ldloc.2        
        3170    28 be 00 00 0a      call           System.Console::WriteLine
        3175    17                  ldc.i4.1       
        3176    0d                  stloc.3        
        3177    2b 1c               br.s           0x3195
        3179    03                  ldarg.1        
        317A    09                  ldloc.3        
        317B    8c 32 00 00 01      box            System.Int32
        3180    72 13 02 00 70      ldstr          "_"
        3185    07                  ldloc.1        
        3186    28 28 00 00 0a      call           System.String::Concat
        318B    28 60 00 00 0a      call           System.IO.Path::Combine
        3190    0c                  stloc.2        
        3191    09                  ldloc.3        
        3192    17                  ldc.i4.1       
        3193    58                  add            
        3194    0d                  stloc.3        
        3195    08                  ldloc.2        
        3196    28 bf 00 00 0a      call           System.IO.File::Exists
        319B    2d dc               brtrue.s       0x3179
        319D    08                  ldloc.2        
        319E    28 c0 00 00 0a      call           System.IO.File::OpenWrite
        31A3    13 04               stloc.s        local(0x0004)
        31A5    20 00 00 10 00      ldc.i4         0x100000
        31AA    8d 3d 00 00 01      newarr         System.Byte
        31AF    13 05               stloc.s        local(0x0005)
        31B1    04                  ldarg.2        
        31B2    28 97 00 00 0a      call           System.Net.WebRequest::Create
        31B7    75 58 00 00 01      isinst         System.Net.HttpWebRequest
        31BC    13 06               stloc.s        local(0x0006)
        31BE    11 06               ldloc.s        local(0x0006)
        31C0    6f b3 00 00 0a      callvirt       System.Net.WebRequest::GetResponse
        31C5    75 67 00 00 01      isinst         System.Net.HttpWebResponse
        31CA    13 07               stloc.s        local(0x0007)
        31CC    11 07               ldloc.s        local(0x0007)
        31CE    6f b4 00 00 0a      callvirt       System.Net.WebResponse::GetResponseStream
        31D3    13 08               stloc.s        local(0x0008)
        31D5    11 08               ldloc.s        local(0x0008)
        31D7    11 05               ldloc.s        local(0x0005)
        31D9    16                  ldc.i4.0       
        31DA    11 05               ldloc.s        local(0x0005)
        31DC    8e                  ldlen          
        31DD    69                  conv.i4        
        31DE    6f 84 00 00 0a      callvirt       System.IO.Stream::Read
        31E3    13 09               stloc.s        local(0x0009)
        31E5    2b 1c               br.s           0x3203
        31E7    11 04               ldloc.s        local(0x0004)
        31E9    11 05               ldloc.s        local(0x0005)
        31EB    16                  ldc.i4.0       
        31EC    11 09               ldloc.s        local(0x0009)
        31EE    6f 89 00 00 0a      callvirt       System.IO.Stream::Write
        31F3    11 08               ldloc.s        local(0x0008)
        31F5    11 05               ldloc.s        local(0x0005)
        31F7    16                  ldc.i4.0       
        31F8    11 05               ldloc.s        local(0x0005)
        31FA    8e                  ldlen          
        31FB    69                  conv.i4        
        31FC    6f 84 00 00 0a      callvirt       System.IO.Stream::Read
        3201    13 09               stloc.s        local(0x0009)
        3203    11 09               ldloc.s        local(0x0009)
        3205    16                  ldc.i4.0       
        3206    30 df               bgt.s          0x31e7
        3208    11 08               ldloc.s        local(0x0008)
        320A    6f b2 00 00 0a      callvirt       System.IO.Stream::Close
        320F    11 07               ldloc.s        local(0x0007)
        3211    6f b8 00 00 0a      callvirt       System.Net.WebResponse::Close
        3216    11 04               ldloc.s        local(0x0004)
        3218    6f b2 00 00 0a      callvirt       System.IO.Stream::Close
        321D    72 17 02 00 70      ldstr          "OK"
        3222    0a                  stloc.0        
        3223    de 03               leave.s        0x3228
        3225    26                  pop            
        3226    de 00               leave.s        0x3228
        3228    06                  ldloc.0        
        3229    2a                  ret            
        322A    11 0a               ldloc.s        local(0x000A)
        322C    2a                  ret            
        */
        $c3 = { 72 ?? ?? ?? ?? 0A 02 04 28 ?? ?? ?? ?? 0B 07 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 06 13 ?? DD ?? ?? ?? ?? 03 07 28 ?? ?? ?? ?? 0C 08 28 ?? ?? ?? ?? 17 0D 2B ?? 03 09 8C ?? ?? ?? ?? 72 ?? ?? ?? ?? 07 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0C 09 17 58 0D 08 28 ?? ?? ?? ?? 2D ?? 08 28 ?? ?? ?? ?? 13 ?? 20 ?? ?? ?? ?? 8D ?? ?? ?? ?? 13 ?? 04 28 ?? ?? ?? ?? 75 ?? ?? ?? ?? 13 ?? 11 ?? 6F ?? ?? ?? ?? 75 ?? ?? ?? ?? 13 ?? 11 ?? 6F ?? ?? ?? ?? 13 ?? 11 ?? 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 13 ?? 2B ?? 11 ?? 11 ?? 16 11 ?? 6F ?? ?? ?? ?? 11 ?? 11 ?? 16 11 ?? 8E 69 6F ?? ?? ?? ?? 13 ?? 11 ?? 16 30 ?? 11 ?? 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 11 ?? 6F ?? ?? ?? ?? 72 ?? ?? ?? ?? 0A DE ?? 26 DE ?? 06 2A 11 ?? 2A }
        /*
function Sockets.MySocket::<.ctor>b__0 0x0600008a@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - act as TCP client
        2394    20 f4 01 00 00      ldc.i4         0x1f4
        2399    28 6a 00 00 0a      call           System.Threading.Thread::Sleep
        239E    20 00 00 a0 00      ldc.i4         0xa00000
        23A3    8d 3d 00 00 01      newarr         System.Byte
        23A8    0a                  stloc.0        
        23A9    38 11 01 00 00      br             0x24bf
        23AE    02                  ldarg.0        
        23AF    7b 8a 00 00 04      ldfld          _tcpClient
        23B4    3a 9d 00 00 00      brtrue         0x2456
        23B9    02                  ldarg.0        
        23BA    73 7d 00 00 0a      newobj         System.Net.Sockets.TcpClient::.ctor
        23BF    7d 8a 00 00 04      stfld          _tcpClient
        23C4    02                  ldarg.0        
        23C5    7b 8a 00 00 04      ldfld          _tcpClient
        23CA    20 00 00 a0 00      ldc.i4         0xa00000
        23CF    6f 7e 00 00 0a      callvirt       System.Net.Sockets.TcpClient::set_SendBufferSize
        23D4    02                  ldarg.0        
        23D5    7b 8a 00 00 04      ldfld          _tcpClient
        23DA    20 00 00 a0 00      ldc.i4         0xa00000
        23DF    6f 7f 00 00 0a      callvirt       System.Net.Sockets.TcpClient::set_ReceiveBufferSize
        23E4    02                  ldarg.0        
        23E5    7b 8a 00 00 04      ldfld          _tcpClient
        23EA    02                  ldarg.0        
        23EB    7b 8e 00 00 04      ldfld          __host
        23F0    02                  ldarg.0        
        23F1    7b 8f 00 00 04      ldfld          __port
        23F6    6f 80 00 00 0a      callvirt       System.Net.Sockets.TcpClient::Connect
        23FB    02                  ldarg.0        
        23FC    02                  ldarg.0        
        23FD    7b 8a 00 00 04      ldfld          _tcpClient
        2402    6f 81 00 00 0a      callvirt       System.Net.Sockets.TcpClient::GetStream
        2407    7d 8b 00 00 04      stfld          _networkStream
        240C    02                  ldarg.0        
        240D    17                  ldc.i4.1       
        240E    7d 89 00 00 04      stfld          isConnected
        2413    02                  ldarg.0        
        2414    7b 90 00 00 04      ldfld          onConnected
        2419    2c 11               brfalse.s      0x242c
        241B    02                  ldarg.0        
        241C    7b 90 00 00 04      ldfld          onConnected
        2421    02                  ldarg.0        
        2422    7b 89 00 00 04      ldfld          isConnected
        2427    6f 82 00 00 0a      callvirt       Invoke
        242C    de 28               leave.s        0x2456
        242E    26                  pop            
        242F    02                  ldarg.0        
        2430    16                  ldc.i4.0       
        2431    7d 89 00 00 04      stfld          isConnected
        2436    02                  ldarg.0        
        2437    14                  ldnull         
        2438    7d 8a 00 00 04      stfld          _tcpClient
        243D    02                  ldarg.0        
        243E    14                  ldnull         
        243F    7d 8b 00 00 04      stfld          _networkStream
        2444    28 83 00 00 0a      call           System.GC::Collect
        2449    02                  ldarg.0        
        244A    7b 88 00 00 04      ldfld          reConnectionDelay
        244F    28 6a 00 00 0a      call           System.Threading.Thread::Sleep
        2454    de 00               leave.s        0x2456
        2456    02                  ldarg.0        
        2457    7b 8b 00 00 04      ldfld          _networkStream
        245C    2c 37               brfalse.s      0x2495
        245E    02                  ldarg.0        
        245F    7b 8b 00 00 04      ldfld          _networkStream
        2464    06                  ldloc.0        
        2465    16                  ldc.i4.0       
        2466    06                  ldloc.0        
        2467    8e                  ldlen          
        2468    69                  conv.i4        
        2469    6f 84 00 00 0a      callvirt       System.IO.Stream::Read
        246E    0b                  stloc.1        
        246F    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        2474    06                  ldloc.0        
        2475    16                  ldc.i4.0       
        2476    07                  ldloc.1        
        2477    6f 85 00 00 0a      callvirt       System.Text.Encoding::GetString
        247C    0c                  stloc.2        
        247D    07                  ldloc.1        
        247E    16                  ldc.i4.0       
        247F    31 14               ble.s          0x2495
        2481    02                  ldarg.0        
        2482    7b 91 00 00 04      ldfld          onData
        2487    2c 0c               brfalse.s      0x2495
        2489    02                  ldarg.0        
        248A    7b 91 00 00 04      ldfld          onData
        248F    08                  ldloc.2        
        2490    6f 6c 00 00 0a      callvirt       Invoke
        2495    de 21               leave.s        0x24b8
        2497    26                  pop            
        2498    02                  ldarg.0        
        2499    14                  ldnull         
        249A    7d 8a 00 00 04      stfld          _tcpClient
        249F    02                  ldarg.0        
        24A0    14                  ldnull         
        24A1    7d 8b 00 00 04      stfld          _networkStream
        24A6    28 83 00 00 0a      call           System.GC::Collect
        24AB    02                  ldarg.0        
        24AC    7b 88 00 00 04      ldfld          reConnectionDelay
        24B1    28 6a 00 00 0a      call           System.Threading.Thread::Sleep
        24B6    de 00               leave.s        0x24b8
        24B8    1f 0a               ldc.i4.s       0xa
        24BA    28 6a 00 00 0a      call           System.Threading.Thread::Sleep
        24BF    02                  ldarg.0        
        24C0    7b 8d 00 00 04      ldfld          _isRunning
        24C5    3a e4 fe ff ff      brtrue         0x23ae
        24CA    2a                  ret            
        */
        $c4 = { 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 20 ?? ?? ?? ?? 8D ?? ?? ?? ?? 0A 38 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 3A ?? ?? ?? ?? 02 73 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 20 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 17 7D ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 2C ?? 02 7B ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? DE ?? 26 02 16 7D ?? ?? ?? ?? 02 14 7D ?? ?? ?? ?? 02 14 7D ?? ?? ?? ?? 28 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? DE ?? 02 7B ?? ?? ?? ?? 2C ?? 02 7B ?? ?? ?? ?? 06 16 06 8E 69 6F ?? ?? ?? ?? 0B 28 ?? ?? ?? ?? 06 16 07 6F ?? ?? ?? ?? 0C 07 16 31 ?? 02 7B ?? ?? ?? ?? 2C ?? 02 7B ?? ?? ?? ?? 08 6F ?? ?? ?? ?? DE ?? 26 02 14 7D ?? ?? ?? ?? 02 14 7D ?? ?? ?? ?? 28 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? DE ?? 1F ?? 28 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 3A ?? ?? ?? ?? 2A }
        /*
function Reqss.Reqss::<OK>b__1 0x06000023@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - decode data using Base64 in .NET
        07FA    02                  ldarg.0        
        07FB    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        0800    02                  ldarg.0        
        0801    7b 9d 00 00 04      ldfld          _text1
        0806    28 47 00 00 0a      call           System.Convert::FromBase64String
        080B    6f 48 00 00 0a      callvirt       System.Text.Encoding::GetString
        0810    7d 9d 00 00 04      stfld          _text1
        0815    2a                  ret            
        */
        $c5 = { 02 28 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 7D ?? ?? ?? ?? 2A }
        /*
function test_A1.Form1::<Form1_Load>b__14 0x0600001b@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - encode data using Base64
        04D8    02                  ldarg.0        
        04D9    7b 23 00 00 04      ldfld          mySocket
        04DE    17                  ldc.i4.1       
        04DF    8c 32 00 00 01      box            System.Int32
        04E4    72 23 00 00 70      ldstr          "|"
        04E9    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        04EE    7e 22 00 00 04      ldsfld         _TOKEN_
        04F3    72 23 00 00 70      ldstr          "|"
        04F8    16                  ldc.i4.0       
        04F9    8c 32 00 00 01      box            System.Int32
        04FE    28 28 00 00 0a      call           System.String::Concat
        0503    6f 2a 00 00 0a      callvirt       System.Text.Encoding::GetBytes
        0508    28 2b 00 00 0a      call           System.Convert::ToBase64String
        050D    28 28 00 00 0a      call           System.String::Concat
        0512    6f 88 00 00 06      callvirt       Send
        0517    26                  pop            
        0518    2a                  ret            
        */
        $c6 = { 02 7B ?? ?? ?? ?? 17 8C ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 16 8C ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 26 2A }
        /*
function Reqss.Reqss::<OK>b__6 0x06000028@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - encode data using Base64
        0884    02                  ldarg.0        
        0885    1c                  ldc.i4.6       
        0886    8d 01 00 00 01      newarr         System.Object
        088B    0a                  stloc.0        
        088C    06                  ldloc.0        
        088D    16                  ldc.i4.0       
        088E    20 a0 86 01 00      ldc.i4         0x186a0
        0893    8c 32 00 00 01      box            System.Int32
        0898    a2                  stelem.ref     
        0899    06                  ldloc.0        
        089A    17                  ldc.i4.1       
        089B    72 23 00 00 70      ldstr          "|"
        08A0    a2                  stelem.ref     
        08A1    06                  ldloc.0        
        08A2    18                  ldc.i4.2       
        08A3    02                  ldarg.0        
        08A4    7b 98 00 00 04      ldfld          _adm_token
        08A9    a2                  stelem.ref     
        08AA    06                  ldloc.0        
        08AB    19                  ldc.i4.3       
        08AC    72 23 00 00 70      ldstr          "|"
        08B1    a2                  stelem.ref     
        08B2    06                  ldloc.0        
        08B3    1a                  ldc.i4.4       
        08B4    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        08B9    02                  ldarg.0        
        08BA    7b 9e 00 00 04      ldfld          _temp_dir1
        08BF    6f 2a 00 00 0a      callvirt       System.Text.Encoding::GetBytes
        08C4    28 2b 00 00 0a      call           System.Convert::ToBase64String
        08C9    a2                  stelem.ref     
        08CA    06                  ldloc.0        
        08CB    1b                  ldc.i4.5       
        08CC    72 23 00 00 70      ldstr          "|"
        08D1    a2                  stelem.ref     
        08D2    06                  ldloc.0        
        08D3    28 49 00 00 0a      call           System.String::Concat
        08D8    7d 97 00 00 04      stfld          _socket_res
        08DD    2a                  ret            
        */
        $c7 = { 02 1C 8D ?? ?? ?? ?? 0A 06 16 20 ?? ?? ?? ?? 8C ?? ?? ?? ?? A2 06 17 72 ?? ?? ?? ?? A2 06 18 02 7B ?? ?? ?? ?? A2 06 19 72 ?? ?? ?? ?? A2 06 1A 28 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? A2 06 1B 72 ?? ?? ?? ?? A2 06 28 ?? ?? ?? ?? 7D ?? ?? ?? ?? 2A }
        /*
function Reqss.Reqss::<OK>b__a 0x0600002c@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - encode data using Base64
        09B4    02                  ldarg.0        
        09B5    25                  dup            
        09B6    7b 97 00 00 04      ldfld          _socket_res
        09BB    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        09C0    02                  ldarg.0        
        09C1    7b a1 00 00 04      ldfld          _res2
        09C6    6f 2a 00 00 0a      callvirt       System.Text.Encoding::GetBytes
        09CB    28 2b 00 00 0a      call           System.Convert::ToBase64String
        09D0    28 50 00 00 0a      call           System.String::Concat
        09D5    7d 97 00 00 04      stfld          _socket_res
        09DA    2a                  ret            
        */
        $c8 = { 02 25 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 7D ?? ?? ?? ?? 2A }
        /*
function <>c__DisplayClassa1::<OK>b__33 0x060000a0@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - encode data using Base64
        0F20    1b                  ldc.i4.5       
        0F21    8d 01 00 00 01      newarr         System.Object
        0F26    0b                  stloc.1        
        0F27    07                  ldloc.1        
        0F28    16                  ldc.i4.0       
        0F29    20 50 34 03 00      ldc.i4         0x33450
        0F2E    8c 32 00 00 01      box            System.Int32
        0F33    a2                  stelem.ref     
        0F34    07                  ldloc.1        
        0F35    17                  ldc.i4.1       
        0F36    72 23 00 00 70      ldstr          "|"
        0F3B    a2                  stelem.ref     
        0F3C    07                  ldloc.1        
        0F3D    18                  ldc.i4.2       
        0F3E    7e 28 00 00 04      ldsfld         _1_shll_
        0F43    7b 87 00 00 04      ldfld          _adm_token
        0F48    a2                  stelem.ref     
        0F49    07                  ldloc.1        
        0F4A    19                  ldc.i4.3       
        0F4B    72 23 00 00 70      ldstr          "|"
        0F50    a2                  stelem.ref     
        0F51    07                  ldloc.1        
        0F52    1a                  ldc.i4.4       
        0F53    28 29 00 00 0a      call           System.Text.Encoding::get_UTF8
        0F58    03                  ldarg.1        
        0F59    6f 2a 00 00 0a      callvirt       System.Text.Encoding::GetBytes
        0F5E    28 2b 00 00 0a      call           System.Convert::ToBase64String
        0F63    a2                  stelem.ref     
        0F64    07                  ldloc.1        
        0F65    28 49 00 00 0a      call           System.String::Concat
        0F6A    0a                  stloc.0        
        0F6B    06                  ldloc.0        
        0F6C    72 01 00 00 70      ldstr          ""
        0F71    28 2c 00 00 0a      call           System.String::op_Inequality
        0F76    2c 0d               brfalse.s      0xf85
        0F78    02                  ldarg.0        
        0F79    7b b0 00 00 04      ldfld          mySocket
        0F7E    06                  ldloc.0        
        0F7F    6f 88 00 00 06      callvirt       Send
        0F84    26                  pop            
        0F85    2a                  ret            
        */
        $c9 = { 1B 8D ?? ?? ?? ?? 0B 07 16 20 ?? ?? ?? ?? 8C ?? ?? ?? ?? A2 07 17 72 ?? ?? ?? ?? A2 07 18 7E ?? ?? ?? ?? 7B ?? ?? ?? ?? A2 07 19 72 ?? ?? ?? ?? A2 07 1A 28 ?? ?? ?? ?? 03 6F ?? ?? ?? ?? 28 ?? ?? ?? ?? A2 07 28 ?? ?? ?? ?? 0A 06 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2C ?? 02 7B ?? ?? ?? ?? 06 6F ?? ?? ?? ?? 26 2A }
        /*
function Funcss.Funcs::CreateMD5 0x0600001d@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - hash data with MD5
        071C    28 3a 00 00 0a      call           System.Security.Cryptography.MD5::Create
        0721    0a                  stloc.0        
        0722    28 3b 00 00 0a      call           System.Text.Encoding::get_ASCII
        0727    02                  ldarg.0        
        0728    6f 2a 00 00 0a      callvirt       System.Text.Encoding::GetBytes
        072D    0b                  stloc.1        
        072E    06                  ldloc.0        
        072F    07                  ldloc.1        
        0730    6f 3c 00 00 0a      callvirt       System.Security.Cryptography.HashAlgorithm::ComputeHash
        0735    0c                  stloc.2        
        0736    73 3d 00 00 0a      newobj         System.Text.StringBuilder::.ctor
        073B    0d                  stloc.3        
        073C    16                  ldc.i4.0       
        073D    13 04               stloc.s        local(0x0004)
        073F    2b 1f               br.s           0x760
        0741    09                  ldloc.3        
        0742    08                  ldloc.2        
        0743    11 04               ldloc.s        local(0x0004)
        0745    8f 3d 00 00 01      ldelema        System.Byte
        074A    72 33 00 00 70      ldstr          "x2"
        074F    28 3e 00 00 0a      call           System.Byte::ToString
        0754    6f 3f 00 00 0a      callvirt       System.Text.StringBuilder::Append
        0759    26                  pop            
        075A    11 04               ldloc.s        local(0x0004)
        075C    17                  ldc.i4.1       
        075D    58                  add            
        075E    13 04               stloc.s        local(0x0004)
        0760    11 04               ldloc.s        local(0x0004)
        0762    08                  ldloc.2        
        0763    8e                  ldlen          
        0764    69                  conv.i4        
        0765    32 da               blt.s          0x741
        0767    09                  ldloc.3        
        0768    6f 40 00 00 0a      callvirt       System.Object::ToString
        076D    13 05               stloc.s        local(0x0005)
        076F    de 0a               leave.s        0x77b
        0771    06                  ldloc.0        
        0772    2c 06               brfalse.s      0x77a
        0774    06                  ldloc.0        
        0775    6f 2f 00 00 0a      callvirt       System.IDisposable::Dispose
        077A    dc                  endfinally     
        077B    11 05               ldloc.s        local(0x0005)
        077D    2a                  ret            
        */
        $c10 = { 28 ?? ?? ?? ?? 0A 28 ?? ?? ?? ?? 02 6F ?? ?? ?? ?? 0B 06 07 6F ?? ?? ?? ?? 0C 73 ?? ?? ?? ?? 0D 16 13 ?? 2B ?? 09 08 11 ?? 8F ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 6F ?? ?? ?? ?? 26 11 ?? 17 58 13 ?? 11 ?? 08 8E 69 32 ?? 09 6F ?? ?? ?? ?? 13 ?? DE ?? 06 2C ?? 06 6F ?? ?? ?? ?? DC 11 ?? 2A }
        /*
function Reqss.Reqss::<OK>b__49 0x06000069@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - get common file path
        12C3    02                  ldarg.0        
        12C4    1f 1a               ldc.i4.s       0x1a
        12C6    28 5f 00 00 0a      call           System.Environment::GetFolderPath
        12CB    7d 9e 00 00 04      stfld          _temp_dir1
        12D0    2a                  ret            
        */
        $c11 = { 02 1F ?? 28 ?? ?? ?? ?? 7D ?? ?? ?? ?? 2A }
        /*
function Reqss.Reqss::<OK>b__18 0x0600003a@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - create directory
        0BC4    02                  ldarg.0        
        0BC5    7b 9e 00 00 04      ldfld          _temp_dir1
        0BCA    28 54 00 00 0a      call           System.IO.Directory::CreateDirectory
        0BCF    26                  pop            
        0BD0    de 03               leave.s        0xbd5
        0BD2    26                  pop            
        0BD3    de 00               leave.s        0xbd5
        0BD5    2a                  ret            
        */
        $c12 = { 02 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 26 DE ?? 26 DE ?? 2A }
        /*
function Reqss.Reqss::<OK>b__4b 0x0600006b@1c444ebeba24dcba8628b7dfe5fec7c6 with 2 features:
          - check if directory exists
          - create directory
        12EA    02                  ldarg.0        
        12EB    7b 9e 00 00 04      ldfld          _temp_dir1
        12F0    28 61 00 00 0a      call           System.IO.Directory::Exists
        12F5    2d 0c               brtrue.s       0x1303
        12F7    02                  ldarg.0        
        12F8    7b 9e 00 00 04      ldfld          _temp_dir1
        12FD    28 54 00 00 0a      call           System.IO.Directory::CreateDirectory
        1302    26                  pop            
        1303    2a                  ret            
        */
        $c13 = { 02 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 2D ?? 02 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 26 2A }
        /*
function Reqss.Reqss::<OK>b__13 0x06000035@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - delete directory
        0B0B    02                  ldarg.0        
        0B0C    7b 9e 00 00 04      ldfld          _temp_dir1
        0B11    17                  ldc.i4.1       
        0B12    28 53 00 00 0a      call           System.IO.Directory::Delete
        0B17    2a                  ret            
        */
        $c14 = { 02 7B ?? ?? ?? ?? 17 28 ?? ?? ?? ?? 2A }
        /*
function Reqss.Reqss::<OK>b__e 0x06000030@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - delete file
        0A5F    02                  ldarg.0        
        0A60    7b 9e 00 00 04      ldfld          _temp_dir1
        0A65    28 51 00 00 0a      call           System.IO.File::Delete
        0A6A    2a                  ret            
        */
        $c15 = { 02 7B ?? ?? ?? ?? 28 ?? ?? ?? ?? 2A }
        /*
function Reqss.Reqss::<OK>b__8 0x0600002a@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - enumerate files on Windows
        0900    02                  ldarg.0        
        0901    7b a0 00 00 04      ldfld          dir1
        0906    6f 4b 00 00 0a      callvirt       System.IO.DirectoryInfo::GetDirectories
        090B    0b                  stloc.1        
        090C    16                  ldc.i4.0       
        090D    0c                  stloc.2        
        090E    2b 24               br.s           0x934
        0910    07                  ldloc.1        
        0911    08                  ldloc.2        
        0912    9a                  ldelem.ref     
        0913    0a                  stloc.0        
        0914    02                  ldarg.0        
        0915    25                  dup            
        0916    7b a1 00 00 04      ldfld          _res2
        091B    06                  ldloc.0        
        091C    6f 4c 00 00 0a      callvirt       System.IO.FileSystemInfo::get_Name
        0921    72 39 00 00 70      ldstr          ":d:0|"
        0926    28 4d 00 00 0a      call           System.String::Concat
        092B    7d a1 00 00 04      stfld          _res2
        0930    08                  ldloc.2        
        0931    17                  ldc.i4.1       
        0932    58                  add            
        0933    0c                  stloc.2        
        0934    08                  ldloc.2        
        0935    07                  ldloc.1        
        0936    8e                  ldlen          
        0937    69                  conv.i4        
        0938    32 d6               blt.s          0x910
        093A    2a                  ret            
        */
        $c16 = { 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 0B 16 0C 2B ?? 07 08 9A 0A 02 25 7B ?? ?? ?? ?? 06 6F ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 7D ?? ?? ?? ?? 08 17 58 0C 08 07 8E 69 32 ?? 2A }
        /*
function Reqss.Reqss::<OK>b__9 0x0600002b@1c444ebeba24dcba8628b7dfe5fec7c6 with 2 features:
          - enumerate files on Windows
          - get file size
        0948    02                  ldarg.0        
        0949    7b a0 00 00 04      ldfld          dir1
        094E    6f 4e 00 00 0a      callvirt       System.IO.DirectoryInfo::GetFiles
        0953    0b                  stloc.1        
        0954    16                  ldc.i4.0       
        0955    0c                  stloc.2        
        0956    2b 54               br.s           0x9ac
        0958    07                  ldloc.1        
        0959    08                  ldloc.2        
        095A    9a                  ldelem.ref     
        095B    0a                  stloc.0        
        095C    02                  ldarg.0        
        095D    25                  dup            
        095E    7b a1 00 00 04      ldfld          _res2
        0963    0d                  stloc.3        
        0964    1b                  ldc.i4.5       
        0965    8d 01 00 00 01      newarr         System.Object
        096A    13 04               stloc.s        local(0x0004)
        096C    11 04               ldloc.s        local(0x0004)
        096E    16                  ldc.i4.0       
        096F    09                  ldloc.3        
        0970    a2                  stelem.ref     
        0971    11 04               ldloc.s        local(0x0004)
        0973    17                  ldc.i4.1       
        0974    06                  ldloc.0        
        0975    6f 4c 00 00 0a      callvirt       System.IO.FileSystemInfo::get_Name
        097A    a2                  stelem.ref     
        097B    11 04               ldloc.s        local(0x0004)
        097D    18                  ldc.i4.2       
        097E    72 45 00 00 70      ldstr          ":f:"
        0983    a2                  stelem.ref     
        0984    11 04               ldloc.s        local(0x0004)
        0986    19                  ldc.i4.3       
        0987    06                  ldloc.0        
        0988    6f 4f 00 00 0a      callvirt       System.IO.FileInfo::get_Length
        098D    8c 31 00 00 01      box            System.Int64
        0992    a2                  stelem.ref     
        0993    11 04               ldloc.s        local(0x0004)
        0995    1a                  ldc.i4.4       
        0996    72 23 00 00 70      ldstr          "|"
        099B    a2                  stelem.ref     
        099C    11 04               ldloc.s        local(0x0004)
        099E    28 49 00 00 0a      call           System.String::Concat
        09A3    7d a1 00 00 04      stfld          _res2
        09A8    08                  ldloc.2        
        09A9    17                  ldc.i4.1       
        09AA    58                  add            
        09AB    0c                  stloc.2        
        09AC    08                  ldloc.2        
        09AD    07                  ldloc.1        
        09AE    8e                  ldlen          
        09AF    69                  conv.i4        
        09B0    32 a6               blt.s          0x958
        09B2    2a                  ret            
        */
        $c17 = { 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 0B 16 0C 2B ?? 07 08 9A 0A 02 25 7B ?? ?? ?? ?? 0D 1B 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 09 A2 11 ?? 17 06 6F ?? ?? ?? ?? A2 11 ?? 18 72 ?? ?? ?? ?? A2 11 ?? 19 06 6F ?? ?? ?? ?? 8C ?? ?? ?? ?? A2 11 ?? 1A 72 ?? ?? ?? ?? A2 11 ?? 28 ?? ?? ?? ?? 7D ?? ?? ?? ?? 08 17 58 0C 08 07 8E 69 32 ?? 2A }
        /*
function Shll.ShellEx::ctor 0x06000081@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - create a process with modified I/O handles and window
        21F0    14                  ldnull         
        21F1    0a                  stloc.0        
        21F2    14                  ldnull         
        21F3    0b                  stloc.1        
        21F4    14                  ldnull         
        21F5    0c                  stloc.2        
        21F6    02                  ldarg.0        
        21F7    72 01 00 00 70      ldstr          ""
        21FC    7d 83 00 00 04      stfld          _lastLineOut
        2201    02                  ldarg.0        
        2202    72 01 00 00 70      ldstr          ""
        2207    7d 87 00 00 04      stfld          _adm_token
        220C    02                  ldarg.0        
        220D    28 0f 00 00 0a      call           System.Object::.ctor
        2212    02                  ldarg.0        
        2213    17                  ldc.i4.1       
        2214    7d 81 00 00 04      stfld          __isRunning
        2219    02                  ldarg.0        
        221A    73 58 00 00 0a      newobj         System.Diagnostics.Process::.ctor
        221F    7d 7d 00 00 04      stfld          __ps
        2224    02                  ldarg.0        
        2225    73 55 00 00 0a      newobj         System.Diagnostics.ProcessStartInfo::.ctor
        222A    7d 7e 00 00 04      stfld          __psi
        222F    02                  ldarg.0        
        2230    7b 7e 00 00 04      ldfld          __psi
        2235    72 45 01 00 70      ldstr          "C:\Windows\System32\cmd.exe"
        223A    6f 56 00 00 0a      callvirt       System.Diagnostics.ProcessStartInfo::set_FileName
        223F    02                  ldarg.0        
        2240    7b 7e 00 00 04      ldfld          __psi
        2245    17                  ldc.i4.1       
        2246    6f 6d 00 00 0a      callvirt       System.Diagnostics.ProcessStartInfo::set_RedirectStandardInput
        224B    02                  ldarg.0        
        224C    7b 7e 00 00 04      ldfld          __psi
        2251    17                  ldc.i4.1       
        2252    6f 6e 00 00 0a      callvirt       System.Diagnostics.ProcessStartInfo::set_RedirectStandardOutput
        2257    02                  ldarg.0        
        2258    7b 7e 00 00 04      ldfld          __psi
        225D    17                  ldc.i4.1       
        225E    6f 6f 00 00 0a      callvirt       System.Diagnostics.ProcessStartInfo::set_RedirectStandardError
        2263    02                  ldarg.0        
        2264    7b 7e 00 00 04      ldfld          __psi
        2269    16                  ldc.i4.0       
        226A    6f 70 00 00 0a      callvirt       System.Diagnostics.ProcessStartInfo::set_UseShellExecute
        226F    02                  ldarg.0        
        2270    7b 7e 00 00 04      ldfld          __psi
        2275    17                  ldc.i4.1       
        2276    6f 71 00 00 0a      callvirt       System.Diagnostics.ProcessStartInfo::set_CreateNoWindow
        227B    02                  ldarg.0        
        227C    7b 7e 00 00 04      ldfld          __psi
        2281    72 4d 00 00 70      ldstr          "C:\"
        2286    6f 57 00 00 0a      callvirt       System.Diagnostics.ProcessStartInfo::set_WorkingDirectory
        228B    02                  ldarg.0        
        228C    7b 7d 00 00 04      ldfld          __ps
        2291    02                  ldarg.0        
        2292    7b 7e 00 00 04      ldfld          __psi
        2297    6f 59 00 00 0a      callvirt       System.Diagnostics.Process::set_StartInfo
        229C    02                  ldarg.0        
        229D    7b 7d 00 00 04      ldfld          __ps
        22A2    6f 5a 00 00 0a      callvirt       System.Diagnostics.Process::Start
        22A7    26                  pop            
        22A8    02                  ldarg.0        
        22A9    06                  ldloc.0        
        22AA    2d 0d               brtrue.s       0x22b9
        22AC    02                  ldarg.0        
        22AD    fe 06 84 00 00 06   ldftn          <.ctor>b__0
        22B3    73 72 00 00 0a      newobj         System.Threading.ParameterizedThreadStart::.ctor
        22B8    0a                  stloc.0        
        22B9    06                  ldloc.0        
        22BA    73 73 00 00 0a      newobj         System.Threading.Thread::.ctor
        22BF    7d 7f 00 00 04      stfld          __t1
        22C4    02                  ldarg.0        
        22C5    7b 7f 00 00 04      ldfld          __t1
        22CA    02                  ldarg.0        
        22CB    7b 7d 00 00 04      ldfld          __ps
        22D0    6f 74 00 00 0a      callvirt       System.Threading.Thread::Start
        22D5    02                  ldarg.0        
        22D6    07                  ldloc.1        
        22D7    2d 0d               brtrue.s       0x22e6
        22D9    02                  ldarg.0        
        22DA    fe 06 85 00 00 06   ldftn          <.ctor>b__1
        22E0    73 72 00 00 0a      newobj         System.Threading.ParameterizedThreadStart::.ctor
        22E5    0b                  stloc.1        
        22E6    07                  ldloc.1        
        22E7    73 73 00 00 0a      newobj         System.Threading.Thread::.ctor
        22EC    7d 80 00 00 04      stfld          __t2
        22F1    02                  ldarg.0        
        22F2    7b 80 00 00 04      ldfld          __t2
        22F7    02                  ldarg.0        
        22F8    7b 7d 00 00 04      ldfld          __ps
        22FD    6f 74 00 00 0a      callvirt       System.Threading.Thread::Start
        2302    02                  ldarg.0        
        2303    73 75 00 00 0a      newobj         System.Timers.Timer::.ctor
        2308    7d 84 00 00 04      stfld          _timer
        230D    02                  ldarg.0        
        230E    7b 84 00 00 04      ldfld          _timer
        2313    23 00 00 00 00 00 40 59 40ldc.r8         101.0
        231C    6f 76 00 00 0a      callvirt       System.Timers.Timer::set_Interval
        2321    02                  ldarg.0        
        2322    7b 84 00 00 04      ldfld          _timer
        2327    08                  ldloc.2        
        2328    2d 0d               brtrue.s       0x2337
        232A    02                  ldarg.0        
        232B    fe 06 86 00 00 06   ldftn          <.ctor>b__2
        2331    73 77 00 00 0a      newobj         System.Timers.ElapsedEventHandler::.ctor
        2336    0c                  stloc.2        
        2337    08                  ldloc.2        
        2338    6f 78 00 00 0a      callvirt       System.Timers.Timer::add_Elapsed
        233D    02                  ldarg.0        
        233E    7b 84 00 00 04      ldfld          _timer
        2343    17                  ldc.i4.1       
        2344    6f 79 00 00 0a      callvirt       System.Timers.Timer::set_Enabled
        2349    2a                  ret            
        */
        $c18 = { 14 0A 14 0B 14 0C 02 72 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 72 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 28 ?? ?? ?? ?? 02 17 7D ?? ?? ?? ?? 02 73 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 73 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 17 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 17 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 17 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 16 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 17 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 26 02 06 2D ?? 02 FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 0A 06 73 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 07 2D ?? 02 FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 0B 07 73 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 73 ?? ?? ?? ?? 7D ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 23 ?? ?? ?? ?? ?? ?? ?? ?? 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 08 2D ?? 02 FE 06 ?? ?? ?? ?? 73 ?? ?? ?? ?? 0C 08 6F ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 17 6F ?? ?? ?? ?? 2A }
        /*
function Reqss.Reqss::<OK>b__42 0x06000062@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - query or enumerate registry key
        112B    02                  ldarg.0        
        112C    7e 5b 00 00 0a      ldsfld         Microsoft.Win32.Registry::LocalMachine
        1131    72 55 00 00 70      ldstr          "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        1136    6f 5c 00 00 0a      callvirt       Microsoft.Win32.RegistryKey::OpenSubKey
        113B    7d a6 00 00 04      stfld          _temp_key_
        1140    2a                  ret            
        */
        $c19 = { 02 7E ?? ?? ?? ?? 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? 7D ?? ?? ?? ?? 2A }
        /*
function Reqss.Reqss::<OK>b__43 0x06000063@1c444ebeba24dcba8628b7dfe5fec7c6 with 2 features:
          - query or enumerate registry key
          - query or enumerate registry value
        1150    02                  ldarg.0        
        1151    7b a6 00 00 04      ldfld          _temp_key_
        1156    6f 5d 00 00 0a      callvirt       Microsoft.Win32.RegistryKey::GetSubKeyNames
        115B    0c                  stloc.2        
        115C    16                  ldc.i4.0       
        115D    0d                  stloc.3        
        115E    38 a5 00 00 00      br             0x1208
        1163    08                  ldloc.2        
        1164    09                  ldloc.3        
        1165    9a                  ldelem.ref     
        1166    0a                  stloc.0        
        1167    02                  ldarg.0        
        1168    7b a6 00 00 04      ldfld          _temp_key_
        116D    06                  ldloc.0        
        116E    6f 5c 00 00 0a      callvirt       Microsoft.Win32.RegistryKey::OpenSubKey
        1173    0b                  stloc.1        
        1174    02                  ldarg.0        
        1175    25                  dup            
        1176    7b a1 00 00 04      ldfld          _res2
        117B    13 04               stloc.s        local(0x0004)
        117D    1f 09               ldc.i4.s       0x9
        117F    8d 01 00 00 01      newarr         System.Object
        1184    13 05               stloc.s        local(0x0005)
        1186    11 05               ldloc.s        local(0x0005)
        1188    16                  ldc.i4.0       
        1189    11 04               ldloc.s        local(0x0004)
        118B    a2                  stelem.ref     
        118C    11 05               ldloc.s        local(0x0005)
        118E    17                  ldc.i4.1       
        118F    07                  ldloc.1        
        1190    72 bd 00 00 70      ldstr          "DisplayName"
        1195    6f 5e 00 00 0a      callvirt       Microsoft.Win32.RegistryKey::GetValue
        119A    a2                  stelem.ref     
        119B    11 05               ldloc.s        local(0x0005)
        119D    18                  ldc.i4.2       
        119E    72 d5 00 00 70      ldstr          "_;;;"
        11A3    a2                  stelem.ref     
        11A4    11 05               ldloc.s        local(0x0005)
        11A6    19                  ldc.i4.3       
        11A7    07                  ldloc.1        
        11A8    72 df 00 00 70      ldstr          "DisplayVersion"
        11AD    6f 5e 00 00 0a      callvirt       Microsoft.Win32.RegistryKey::GetValue
        11B2    a2                  stelem.ref     
        11B3    11 05               ldloc.s        local(0x0005)
        11B5    1a                  ldc.i4.4       
        11B6    72 d5 00 00 70      ldstr          "_;;;"
        11BB    a2                  stelem.ref     
        11BC    11 05               ldloc.s        local(0x0005)
        11BE    1b                  ldc.i4.5       
        11BF    07                  ldloc.1        
        11C0    72 fd 00 00 70      ldstr          "InstallDate"
        11C5    6f 5e 00 00 0a      callvirt       Microsoft.Win32.RegistryKey::GetValue
        11CA    a2                  stelem.ref     
        11CB    11 05               ldloc.s        local(0x0005)
        11CD    1c                  ldc.i4.6       
        11CE    72 d5 00 00 70      ldstr          "_;;;"
        11D3    a2                  stelem.ref     
        11D4    11 05               ldloc.s        local(0x0005)
        11D6    1d                  ldc.i4.7       
        11D7    07                  ldloc.1        
        11D8    72 15 01 00 70      ldstr          "Publisher"
        11DD    6f 5e 00 00 0a      callvirt       Microsoft.Win32.RegistryKey::GetValue
        11E2    a2                  stelem.ref     
        11E3    11 05               ldloc.s        local(0x0005)
        11E5    1e                  ldc.i4.8       
        11E6    72 29 01 00 70      ldstr          "_|"
        11EB    a2                  stelem.ref     
        11EC    11 05               ldloc.s        local(0x0005)
        11EE    28 49 00 00 0a      call           System.String::Concat
        11F3    7d a1 00 00 04      stfld          _res2
        11F8    de 0a               leave.s        0x1204
        11FA    07                  ldloc.1        
        11FB    2c 06               brfalse.s      0x1203
        11FD    07                  ldloc.1        
        11FE    6f 2f 00 00 0a      callvirt       System.IDisposable::Dispose
        1203    dc                  endfinally     
        1204    09                  ldloc.3        
        1205    17                  ldc.i4.1       
        1206    58                  add            
        1207    0d                  stloc.3        
        1208    09                  ldloc.3        
        1209    08                  ldloc.2        
        120A    8e                  ldlen          
        120B    69                  conv.i4        
        120C    3f 52 ff ff ff      blt            0x1163
        1211    2a                  ret            
        */
        $c20 = { 02 7B ?? ?? ?? ?? 6F ?? ?? ?? ?? 0C 16 0D 38 ?? ?? ?? ?? 08 09 9A 0A 02 7B ?? ?? ?? ?? 06 6F ?? ?? ?? ?? 0B 02 25 7B ?? ?? ?? ?? 13 ?? 1F ?? 8D ?? ?? ?? ?? 13 ?? 11 ?? 16 11 ?? A2 11 ?? 17 07 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? A2 11 ?? 18 72 ?? ?? ?? ?? A2 11 ?? 19 07 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? A2 11 ?? 1A 72 ?? ?? ?? ?? A2 11 ?? 1B 07 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? A2 11 ?? 1C 72 ?? ?? ?? ?? A2 11 ?? 1D 07 72 ?? ?? ?? ?? 6F ?? ?? ?? ?? A2 11 ?? 1E 72 ?? ?? ?? ?? A2 11 ?? 28 ?? ?? ?? ?? 7D ?? ?? ?? ?? DE ?? 07 2C ?? 07 6F ?? ?? ?? ?? DC 09 17 58 0D 09 08 8E 69 3F ?? ?? ?? ?? 2A }
        /*
function Screenss.ScreenCapture::CaptureScreen 0x06000072@1c444ebeba24dcba8628b7dfe5fec7c6 with 1 features:
          - unmanaged call
        1F5A    02                  ldarg.0        
        1F5B    28 7c 00 00 06      call           GetDesktopWindow
        1F60    28 73 00 00 06      call           CaptureWindow
        1F65    2a                  ret            
        */
        $c21 = { 02 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 2A }
    condition:
        all of them
}

