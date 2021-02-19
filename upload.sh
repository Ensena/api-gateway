go build -o api main.go
docker build -t ensena/api-gateway .
docker push ensena/api-gateway