taskkill /f /im goflyway.exe
del .\goflyway.exe
go build -o goflyway.exe main.go 
start .\goflyway.exe %*