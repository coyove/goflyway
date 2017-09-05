taskkill /f /im goflyway.exe
del .\goflyway.exe
go build -gcflags -m -o goflyway.exe main.go 
start .\goflyway.exe %*