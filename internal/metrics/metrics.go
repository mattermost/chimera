package metrics

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

const (
	metricsNamespace = "chimera"

	metricsSubsystemHTTP = "http"

	metricsSubsystemApp = "app"
)

// Collector is metrics collector.
type Collector struct {
	Registry *prometheus.Registry

	httpResponseStatusCounters *prometheus.CounterVec
	httpRequestDuration        *prometheus.HistogramVec

	authorizationRequestsCounters      *prometheus.CounterVec
	authorizationConfirmationsCounters *prometheus.CounterVec
	authorizationCancellationsCounters *prometheus.CounterVec
	generatedTokensCounters            *prometheus.CounterVec

	logger logrus.FieldLogger
}

// NewCollector creates new Collector and registers metrics.
func NewCollector(logger logrus.FieldLogger) *Collector {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewGoCollector())
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
		Namespace: metricsNamespace,
	}))

	// General HTTP metrics

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

	// Application specific metrics

	authorizationRequestsCounters := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystemApp,
			Name:      "authorization_request_count",
			Help:      "Count of successful authorization requests through Chimera",
		},
		[]string{"app"},
	)
	registry.MustRegister(authorizationRequestsCounters)

	authorizationConfirmationsCounters := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystemApp,
			Name:      "authorization_confirmations_count",
			Help:      "Count of successful authorization confirmations through Chimera",
		},
		[]string{"app"},
	)
	registry.MustRegister(authorizationConfirmationsCounters)

	authorizationCancellationsCounters := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystemApp,
			Name:      "authorization_cancellations_count",
			Help:      "Count of successful authorization cancellations through Chimera",
		},
		[]string{"app"},
	)
	registry.MustRegister(authorizationCancellationsCounters)

	generatedTokensCounters := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Subsystem: metricsSubsystemApp,
			Name:      "generated_tokens_count",
			Help:      "Count of OAuth access tokens successfully generated by Chimera",
		},
		[]string{"app"},
	)
	registry.MustRegister(generatedTokensCounters)

	return &Collector{
		Registry:                           registry,
		httpResponseStatusCounters:         httpResponseStatusCounters,
		httpRequestDuration:                httpRequestDuration,
		authorizationRequestsCounters:      authorizationRequestsCounters,
		authorizationConfirmationsCounters: authorizationConfirmationsCounters,
		authorizationCancellationsCounters: authorizationCancellationsCounters,
		generatedTokensCounters:            generatedTokensCounters,
		logger:                             logger,
	}
}

func (c *Collector) IncAuthorizationRequested(app string) {
	c.authorizationRequestsCounters.WithLabelValues(app).Inc()
}
func (c *Collector) IncAuthorizationConfirmed(app string) {
	c.authorizationConfirmationsCounters.WithLabelValues(app).Inc()
}
func (c *Collector) IncAuthorizationCanceled(app string) {
	c.authorizationCancellationsCounters.WithLabelValues(app).Inc()
}
func (c *Collector) IncGeneratedToken(app string) {
	c.generatedTokensCounters.WithLabelValues(app).Inc()
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
