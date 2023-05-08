run:
	go mod download && go run cmd/pdbot/main.go

test:
	curl -v -H "Content-Type: application/json; charset=utf-8" http://127.0.0.1:8080/at?name=ap
