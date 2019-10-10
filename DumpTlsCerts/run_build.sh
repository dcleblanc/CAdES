mkdir -p ../build/DumpTlsCerts
dotnet build -o ../build/DumpTlsCerts DumpTlsCerts.csproj
rm -rf obj