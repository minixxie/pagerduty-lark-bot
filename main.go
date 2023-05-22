package main

func main() {
	pagerdutyBotServer := NewPagerdutyBotServer()
	pagerdutyBotServer.Run(":8080")
}
