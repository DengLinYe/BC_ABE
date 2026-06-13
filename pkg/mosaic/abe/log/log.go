package log

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	mu          sync.Mutex
	file        *os.File
	currentDay  string
	logDir      string
	consoleOut  io.Writer = io.Discard
	configured  bool
)

// Configure 配置 mosaic 日志：默认仅写文件，不写控制台。
func Configure(dir, level string, console bool) {
	mu.Lock()
	defer mu.Unlock()

	logrus.SetFormatter(&logrus.TextFormatter{DisableColors: true, FullTimestamp: true})
	setLevel(level)
	logDir = dir
	if console {
		consoleOut = os.Stdout
	} else {
		consoleOut = io.Discard
	}
	configured = true
	refreshOutputLocked()
}

func setLevel(level string) {
	switch level {
	case "Trace", "trace":
		logrus.SetLevel(logrus.TraceLevel)
	case "Debug", "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "Warn", "warn", "warning":
		logrus.SetLevel(logrus.WarnLevel)
	case "Error", "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "Fatal", "fatal":
		logrus.SetLevel(logrus.FatalLevel)
	case "Panic", "panic":
		logrus.SetLevel(logrus.PanicLevel)
	default:
		logrus.SetLevel(logrus.InfoLevel)
	}
}

func refreshOutputLocked() {
	writers := make([]io.Writer, 0, 2)
	if consoleOut != nil && consoleOut != io.Discard {
		writers = append(writers, consoleOut)
	}
	if w, err := ensureFileLocked(time.Now()); err == nil && w != nil {
		writers = append(writers, w)
	}
	switch len(writers) {
	case 0:
		logrus.SetOutput(io.Discard)
	default:
		logrus.SetOutput(io.MultiWriter(writers...))
	}
}

func ensureFileLocked(now time.Time) (io.Writer, error) {
	if logDir == "" {
		return nil, nil
	}
	day := now.Format("2006-01-02")
	if file != nil && currentDay == day {
		return file, nil
	}
	if file != nil {
		_ = file.Close()
		file = nil
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(logDir, day+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	file = f
	currentDay = day
	return file, nil
}

func write(level logrus.Level, s string, f ...interface{}) {
	if !configured {
		logrus.SetOutput(io.Discard)
		configured = true
	}
	mu.Lock()
	if logDir != "" {
		if _, err := ensureFileLocked(time.Now()); err == nil {
			refreshOutputLocked()
		}
	}
	mu.Unlock()
	logrus.StandardLogger().Log(level, fmt.Sprintf(s, f...))
}

func Debug(s string, f ...interface{}) { write(logrus.DebugLevel, s, f...) }
func Info(s string, f ...interface{})  { write(logrus.InfoLevel, s, f...) }
func Error(s string, f ...interface{}) { write(logrus.ErrorLevel, s, f...) }

func Fatal(s string, f ...interface{}) {
	write(logrus.FatalLevel, s, f...)
	os.Exit(1)
}

func Panic(s string, f ...interface{}) {
	s_ := fmt.Sprintf(s, f...)
	write(logrus.PanicLevel, "%s", s_)
	panic(s_)
}
