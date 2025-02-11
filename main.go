package main

import (
	"gin-auth/config"
	"gin-auth/routes"
)

func main() {
	config.ConnectDatabase()
	r := routes.SetupRouter()
	r.Run(":8080")
}
