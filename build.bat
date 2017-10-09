rem c-archive of 386 is not supported on Windows, on Linux 64bit, apt-get install g++-multilib first
go build -buildmode=c-archive .\main.go

rem gcc .\main.c .\main.a -o main.exe -lWinMM -lntdll -lWS2_32 -Wno-error=address -Wno-pointer-to-int-cast
rem .\main.exe

gcc .\main.c .\main.a -shared -pthread -o goflyway.dll -lWinMM -lntdll -lWS2_32 -Wno-error=address -Wno-pointer-to-int-cast