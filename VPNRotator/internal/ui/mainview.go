package ui

import (
	"strconv"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"image/color"
)

// MainView holds all UI state and widgets.
type MainView struct {
	StatusBinding  binding.String
	IsOnBinding    binding.Bool
	IPBinding      binding.String
	LogBinding     binding.String
	Interval       int // seconds

	onToggle func(isOn bool, interval time.Duration)
}

func NewMainView(onToggle func(isOn bool, interval time.Duration)) *MainView {
	return &MainView{
		StatusBinding: binding.NewString(),
		IsOnBinding:   binding.NewBool(),
		IPBinding:     binding.NewString(),
		LogBinding:    binding.NewString(),
		Interval:      30,
		onToggle:      onToggle,
	}
}

func (m *MainView) Build() fyne.CanvasObject {
	m.StatusBinding.Set("⬤  Disconnected")
	m.IPBinding.Set("Public IP: —")
	m.LogBinding.Set("")

	// ── Title bar ──────────────────────────────────────────────────────────
	title := canvas.NewText("VPN Gate Rotator", color.White)
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.TextSize = 18

	subtitle := canvas.NewText("v1.1 — Auto-rotating anonymous VPN (Kill Switch enabled)", color.RGBA{R: 160, G: 160, B: 180, A: 255})
	subtitle.TextSize = 12

	titleBox := container.NewVBox(title, subtitle)

	// ── Status card ────────────────────────────────────────────────────────
	statusLabel := widget.NewLabelWithData(m.StatusBinding)
	statusLabel.Wrapping = fyne.TextWrapWord
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	ipLabel := widget.NewLabelWithData(m.IPBinding)
	ipLabel.TextStyle = fyne.TextStyle{Monospace: true}

	statusCard := container.NewVBox(
		statusLabel,
		ipLabel,
	)

	// ── Toggle ─────────────────────────────────────────────────────────────
	toggleBtn := widget.NewCheck("Enable VPN Rotation", func(on bool) {
		m.IsOnBinding.Set(on)
	})

	m.IsOnBinding.AddListener(binding.NewDataListener(func() {
		val, _ := m.IsOnBinding.Get()
		m.onToggle(val, time.Duration(m.Interval)*time.Second)
	}))

	// ── Interval control ───────────────────────────────────────────────────
	intervalEntry := widget.NewEntry()
	intervalEntry.SetText(strconv.Itoa(m.Interval))
	intervalEntry.OnChanged = func(s string) {
		val, err := strconv.Atoi(s)
		if err == nil && val >= 10 {
			m.Interval = val
		}
	}
	intervalEntry.SetPlaceHolder("seconds (min 10)")

	intervalRow := container.NewBorder(nil, nil,
		widget.NewLabel("Rotate every:"), widget.NewLabel("seconds"),
		intervalEntry,
	)

	// ── Log area ───────────────────────────────────────────────────────────
	logEntry := widget.NewLabelWithData(m.LogBinding)
	logEntry.Wrapping = fyne.TextWrapWord
	logEntry.TextStyle = fyne.TextStyle{Monospace: true}
	logScroll := container.NewVScroll(logEntry)
	logScroll.SetMinSize(fyne.NewSize(0, 80))

	logSection := container.NewVBox(
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Connection Log", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		logScroll,
	)

	// ── Admin warning ──────────────────────────────────────────────────────
	warningLabel := widget.NewLabelWithStyle(
		"⚠  Run as Administrator for VPN to work",
		fyne.TextAlignCenter,
		fyne.TextStyle{Italic: true},
	)

	// ── Layout ─────────────────────────────────────────────────────────────
	sep := widget.NewSeparator()

	content := container.NewVBox(
		titleBox,
		widget.NewSeparator(),
		statusCard,
		sep,
		toggleBtn,
		intervalRow,
		logSection,
		widget.NewSeparator(),
		warningLabel,
	)

	padded := container.NewPadded(content)
	_ = theme.ForegroundColor() // keep theme import live
	return padded
}

// UpdateStatus updates the status label text.
func (m *MainView) UpdateStatus(status string) {
	m.StatusBinding.Set(status)
}

// UpdateIP updates the displayed public IP.
func (m *MainView) UpdateIP(ip string) {
	if ip == "" {
		m.IPBinding.Set("Public IP: —")
	} else {
		m.IPBinding.Set("Public IP: " + ip)
	}
}

// AppendLog appends a line to the connection log area.
func (m *MainView) AppendLog(line string) {
	existing, _ := m.LogBinding.Get()
	if existing == "" {
		m.LogBinding.Set(line)
	} else {
		// Keep only last 10 lines
		lines := splitLines(existing)
		lines = append(lines, line)
		if len(lines) > 10 {
			lines = lines[len(lines)-10:]
		}
		m.LogBinding.Set(joinLines(lines))
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func joinLines(lines []string) string {
	result := ""
	for i, l := range lines {
		if i > 0 {
			result += "\n"
		}
		result += l
	}
	return result
}
