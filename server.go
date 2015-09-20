package godoauth

import (
	//	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"log"
	"net"
	"net/http"
	//	"os"
	"time"
)

var clientTimeout time.Duration

type Server struct {
	Server   http.Server
	Listener net.Listener
	Handler  http.Handler
	closing  chan struct{}
	Config   *Configuration
}

// NewServer returns a new instance of Server built from a config.
func NewServer(c *Configuration) (*Server, error) {
	s := &Server{
		closing: make(chan struct{}),
	}
	s.Config = c

	s.Handler = s.getHandlers()

	//	if c.Log.File != "" {
	//		// BUG(dejan): Implement file handler
	//		s.Handler = handlers.CombinedLoggingHandler(os.Stdout, s.Handler)
	//	} else {
	//		s.Handler = handlers.CombinedLoggingHandler(os.Stdout, s.Handler)
	//	}

	// BUG(dejan) add TLS support
	l, err := net.Listen("tcp", c.Http.Addr)
	if err != nil {
		log.Panic("Server Listen Error: ", err)
	}
	s.Listener = l

	return s, nil
}

//serverPing is an health check handler, so we can use ELB/HA proxy health check
func serverPing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Pong\n"))
}

func (s *Server) getHandlers() http.Handler {
	clientTimeout, err := time.ParseDuration(s.Config.Http.Timeout)
	if err != nil {
		log.Fatal(err)
	}

	sharedClient := new(http.Client)
	sharedClient.Timeout = clientTimeout
	authHandler := &TokenAuthHandler{Client: sharedClient, Config: s.Config}

	router := mux.NewRouter()
	router.Handle("/auth", authHandler)
	router.HandleFunc("/server-ping/", serverPing)
	return router
}

//Start the Token Authentication server
func (s *Server) Start() {
	go func() {
		defer s.Listener.Close()
		s.Server = http.Server{Handler: s.Handler}
		if err := s.Server.Serve(s.Listener); err != nil {
			log.Panic("Server: ", err)
		}
	}()
}
