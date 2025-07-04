package main

import (
    "embed"

    "github.com/wailsapp/wails/v2"
    "github.com/wailsapp/wails/v2/pkg/options"
    "github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
    // Crear instancia de tu app
    app := NewApp()

    // Configurar y ejecutar la aplicación
    err := wails.Run(&options.App{
        Title:  "GIE",
        Width:  520,
        Height: 780,
        AssetServer: &assetserver.Options{
            Assets: assets,
        },
        BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
        OnStartup:        app.startup,
        Bind: []interface{}{
            app,
        },
        DragAndDrop: &options.DragAndDrop{
            EnableFileDrop: true,
        },
        // 🔒 Método universal para tamaño fijo
        MinWidth:  520,
        MinHeight: 780,
        MaxWidth:  520,
        MaxHeight: 780,
        // Opcional: deshabilitar pantalla completa
        Fullscreen: false,
    })

    if err != nil {
        println("Error:", err.Error())
    }
}