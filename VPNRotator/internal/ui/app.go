package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
)

type App struct {
	FyneApp fyne.App
	Window  fyne.Window
}

func NewApp() *App {
	a := app.New()
	w := a.NewWindow("VPN Gate Auto-Rotator")
	w.Resize(fyne.NewSize(400, 300))

	return &App{
		FyneApp: a,
		Window:  w,
	}
}

func (a *App) Run() {
	a.Window.ShowAndRun()
}
