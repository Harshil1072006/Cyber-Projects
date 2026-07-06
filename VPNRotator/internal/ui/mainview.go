package ui

import (
	"strconv"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/widget"
)

type MainView struct {
	StatusBinding binding.String
	IsOnBinding   binding.Bool
	Interval      int // seconds

	onToggle func(isOn bool, interval time.Duration)
}

func NewMainView(onToggle func(isOn bool, interval time.Duration)) *MainView {
	return &MainView{
		StatusBinding: binding.NewString(),
		IsOnBinding:   binding.NewBool(),
		Interval:      30, // Default 30s
		onToggle:      onToggle,
	}
}

func (m *MainView) Build() fyne.CanvasObject {
	m.StatusBinding.Set("Status: Disconnected")

	statusLabel := widget.NewLabelWithData(m.StatusBinding)

	intervalEntry := widget.NewEntry()
	intervalEntry.SetText(strconv.Itoa(m.Interval))
	intervalEntry.OnChanged = func(s string) {
		val, err := strconv.Atoi(s)
		if err == nil && val > 0 {
			m.Interval = val
		}
	}

	toggleBtn := widget.NewCheckWithData("ON / OFF", m.IsOnBinding)
	m.IsOnBinding.AddListener(binding.NewDataListener(func() {
		val, _ := m.IsOnBinding.Get()
		m.onToggle(val, time.Duration(m.Interval)*time.Second)
	}))

	content := container.NewVBox(
		widget.NewLabel("VPN Gate Auto-Rotator"),
		toggleBtn,
		container.NewHBox(widget.NewLabel("Rotate every (seconds):"), intervalEntry),
		widget.NewSeparator(),
		statusLabel,
	)

	return content
}

func (m *MainView) UpdateStatus(status string) {
	m.StatusBinding.Set(status)
}
