package metrics

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

const (
	metricsNamespace = "chimera"

	metricsSubsystemHTTP = "http"
)

// Collector is metrics collector.
type Collector struct {
	Registry *prometheus.Registry

	httpResponseStatusCounters *prometheus.CounterVec
	httpRequestDuration        *prometheus.HistogramVec

	logger logrus.FieldLogger
}

// NewCollector creates new Collector and registers metrics.
func NewCollector(logger logrus.FieldLogger) *Collector {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
		Namespace: metricsNamespace,
	}))

	httpResponseStatusCounters := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystemHTTP,
			Name:      "response_status",
			Help:      "Status of HTTP response",
		},
		[]string{"status", "path", "method"},
	)
	registry.MustRegister(httpResponseStatusCounters)

	httpRequestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystemHTTP,
			Name:      "response_time_seconds",
			Help:      "Duration of HTTP requests",
		},
		[]string{"path", "method"},
	)
	registry.MustRegister(httpRequestDuration)

	return &Collector{
		Registry:                   registry,
		httpResponseStatusCounters: httpResponseStatusCounters,
		httpRequestDuration:        httpRequestDuration,
		logger:                     logger,
	}
}

// MetricsHandler returns Prometheus HTTP metrics API handler.
func (c *Collector) MetricsHandler() http.Handler {
	router := mux.NewRouter()
	router.Handle("/metrics", promhttp.InstrumentMetricHandler(c.Registry, promhttp.HandlerFor(c.Registry, promhttp.HandlerOpts{})))
	return router
}

// MetricsMiddleware returns middleware used for collecting metrics.
func (c *Collector) MetricsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		method := r.Method

		timer := prometheus.NewTimer(c.httpRequestDuration.WithLabelValues(path, method))

		rw := newStatusWriter(w)
		h.ServeHTTP(rw, r)

		c.httpResponseStatusCounters.WithLabelValues(strconv.Itoa(rw.status), path, method).Inc()

		timer.ObserveDuration()
	})
}

// statusWriter preserves status written in the response so that it can be recorded.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func newStatusWriter(base http.ResponseWriter) *statusWriter {
	return &statusWriter{
		ResponseWriter: base,
		status:         http.StatusOK,
	}
}

// WriteHeader records status code and calls base ResponseWriter.
func (r *statusWriter) WriteHeader(statusCode int) {
	r.status = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}
