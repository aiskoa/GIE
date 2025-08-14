package main

import (
	"embed"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func handleCLIEncrypt() {
	if len(os.Args) < 6 {
		fmt.Println("Usage: gie encrypt <input_file> <password> <method> <level>")
		fmt.Println("Methods: AES-CTR")
		fmt.Println("Levels: Low, Normal, High")
		return
	}

	inputFile := os.Args[2]
	password := os.Args[3]
	method := os.Args[4]
	level := os.Args[5]

	app := NewApp()
	result := app.EncryptFile(inputFile, password, "", level, 0, method, false)

	if result == "success" {
		fmt.Println("Encryption completed successfully")
	} else {
		fmt.Printf("Encryption failed: %s\n", result)
	}
}

func main() {
	// Check for CLI mode
	if len(os.Args) > 1 && os.Args[1] == "encrypt" {
		handleCLIEncrypt()
		return
	}

	app := NewApp()

	err := wails.Run(&options.App{
		Title:  "GIE",
		Width:  520,
		Height: 820,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		OnStartup:        app.OnStartup,
		OnShutdown:       app.OnShutdown,
		Bind: []interface{}{
			app,
		},
		DragAndDrop: &options.DragAndDrop{
			EnableFileDrop: true,
		},
		MinWidth:   520,
		MinHeight:  820,
		MaxWidth:   520,
		MaxHeight:  820,
		Fullscreen: false,
	})

	if err != nil {
		println("Error:", err.Error())
	}
}
