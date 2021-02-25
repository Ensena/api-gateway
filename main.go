package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/Ensena/core/env-global"
	"github.com/Ensena/core/middleware"
	"github.com/devopsfaith/krakend/config"
	"github.com/devopsfaith/krakend/logging"
	"github.com/devopsfaith/krakend/proxy"
	"github.com/devopsfaith/krakend/router"
	"github.com/devopsfaith/krakend/router/gin"
	"github.com/elmalba/oauth2-server/jwt"
	ginHttp "github.com/gin-gonic/gin"
	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmgin"
	"go.elastic.co/apm/module/apmhttp"
)

var key string

func init() {
	key = env.Check("secretKey", "Missing Params secretKey")
}

func main() {
	port := flag.Int("p", 0, "Port of the service")
	logLevel := flag.String("l", "ERROR", "Logging level")
	debug := flag.Bool("d", false, "Enable the debug")
	configFile := flag.String("c", "./configuration.json", "Path to the configuration filename")
	flag.Parse()
	parser := config.NewParser()
	serviceConfig, err := parser.Parse(*configFile)
	if err != nil {
		log.Fatal("ERROR:", err.Error())
	}
	serviceConfig.Debug = serviceConfig.Debug || *debug
	if *port != 0 {
		serviceConfig.Port = *port
	}
	logger, _ := logging.NewLogger(*logLevel, os.Stdout, "[KRAKEND]")
	engine := ginHttp.New()
	engine.Use(apmgin.Middleware(engine))
	config := gin.Config{
		Engine:         engine,
		Middlewares:    []ginHttp.HandlerFunc{Authorization()},
		HandlerFactory: gin.EndpointHandler,
		ProxyFactory:   proxy.DefaultFactory(logger),
		Logger:         logger,
		RunServer:      router.RunServer,
	}
	routerFactory := gin.NewFactory(config)
	routerFactory.New().Run(serviceConfig)
}

func Authorization() ginHttp.HandlerFunc {
	return func(c *ginHttp.Context) {
		JWT := c.Request.Header.Get("Authorization")
		user, err := jwt.Decode(JWT, key)
		if err != nil {
			c.AbortWithStatus(403)
			return
		}

		tx := middleware.TX{}
		tx.UserID = user.ID
		tx.Email = user.Email
		middleware.SetTransaction(c.Request, &tx)

		a := apm.TransactionFromContext(c.Request.Context())
		// fmt.Println(a.EnsureParent(), a.TraceContext().Span)

		// u := uuid.New().String()
		// u = strings.ReplaceAll(u, "-", "")
		//var t apm.TraceID

		//		traceparent := fmt.Sprintf("%s%s", a.TraceContext().Span, a.EnsureParent())

		//var spanID apm.SpanID

		a.Context.SetUserEmail(tx.Email)
		a.Context.SetUserID(tx.UserID)
		if c.Request.Header.Get("Traceparent") == "" {

			var traceOptions apm.TraceOptions
			//copy(spanID[:], t[8:])
			traceContext := apm.TraceContext{
				Trace:   a.TraceContext().Trace,
				Span:    a.TraceContext().Span,
				Options: traceOptions.WithRecorded(true),
			}
			//	r.Header.Set(apmhttp.W3CTraceparentHeader)

			c.Request.Header.Set("Elastic-Apm-Traceparent", apmhttp.FormatTraceparentHeader(traceContext))
			c.Request.Header.Set("Traceparent", apmhttp.FormatTraceparentHeader(traceContext))
			c.Request.Header.Set("Tracestate", "es=s:1")
		} else {

			trace := c.Request.Header.Get("Traceparent")

			arrTrace := strings.Split(trace, "-")
			if len(arrTrace) >= 4 {
				trace = fmt.Sprintf("%s-%s-%s-%s", arrTrace[0], arrTrace[1], a.TraceContext().Span, arrTrace[3])

			}

			c.Request.Header.Set("Elastic-Apm-Traceparent", trace)
			c.Request.Header.Set("Traceparent", trace)
			c.Request.Header.Set("Tracestate", "es=s:1")

		}

	}
}
