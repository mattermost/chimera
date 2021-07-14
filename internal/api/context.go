package api

import (
	"net/http"

	"github.com/mattermost/chimera/internal/util"
	"github.com/sirupsen/logrus"
)

type Context struct {
	RequestID string
	Logger    logrus.FieldLogger
}

func (c *Context) Clone() *Context {
	return &Context{
		Logger: c.Logger,
	}
}

type CtxHandlerFunc func(c *Context, w http.ResponseWriter, r *http.Request)

type contextHandler struct {
	context *Context
	handler CtxHandlerFunc
}

func addCtx(ctx *Context, handler CtxHandlerFunc) http.Handler {
	return &contextHandler{handler: handler, context: ctx}
}

func (h contextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	context := h.context.Clone()
	context.RequestID = util.NewID()
	context.Logger = context.Logger.WithFields(logrus.Fields{
		"path":    r.URL.Path,
		"request": context.RequestID,
	})

	h.handler(context, w, r)
}
