taskkill /f /im goflyway.exe
del .\goflyway.exe
go build -o goflyway.exe cmd\goflyway\main.go 
start .\goflyway.exe %*