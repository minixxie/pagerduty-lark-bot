package pdbot

func main() {
	pagerdutyBotServer := NewServer()
	pagerdutyBotServer.Run(":8080")
}
