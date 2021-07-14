package main

import "github.com/sirupsen/logrus"

type logrusWriter struct {
	logger logrus.FieldLogger
}

func (w *logrusWriter) Write(b []byte) (int, error) {
	n := len(b)
	if n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}

	w.logger.Warning(string(b))
	return n, nil
}
