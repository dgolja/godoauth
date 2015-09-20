package godoauth

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

var clientTimeout time.Duration

type Server struct {
	Server   http.Server
	Listener net.Listener
	Handler  http.Handler
	// used for proper graceful closing TODO
	closing chan struct{}
	// main Auth config file
	Config *Configuration
}

// NewServer returns a new instance of Server built from a config.
func NewServer(c *Configuration) (*Server, error) {
	s := &Server{
		closing: make(chan struct{}),
	}
	s.Config = c

	s.Handler = s.getHandlers()

	// BUG(dejan) add support to write logs to a text file
	//	if c.Log.File != "" {
	//		// BUG(dejan): Implement file handler
	//		s.Handler = handlers.CombinedLoggingHandler(os.Stdout, s.Handler)
	//	} else {
	//		s.Handler = handlers.CombinedLoggingHandler(os.Stdout, s.Handler)
	//	}

	var (
		l   net.Listener
		err error
	)

	if s.Config.Http.Tls.Certificate != "" && s.Config.Http.Tls.Key != "" {
		cert, err := tls.LoadX509KeyPair(s.Config.Http.Tls.Certificate, s.Config.Http.Tls.Key)
		if err != nil {
			return nil, err
		}

		l, err = tls.Listen("tcp", c.Http.Addr, &tls.Config{
			Certificates: []tls.Certificate{cert},
		})
		if err != nil {
			log.Panic("Server Listen HTTPS Error: ", err)
		}
		log.Println("Listener on HTTPS:", l.Addr().String())
	} else {
		l, err = net.Listen("tcp", c.Http.Addr)
		if err != nil {
			log.Panic("Server Listen HTTP Error: ", err)
		}
		log.Println("Listener on HTTP:", l.Addr().String())
	}
	s.Listener = l
	return s, nil
}

//serverPing is an health check handler, so we can use ELB/HA proxy health check
func serverPing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{\"message\": \"Save the Whales !\"}\n\r"))
}

func (s *Server) getHandlers() http.Handler {
	clientTimeout, err := time.ParseDuration(s.Config.Http.Timeout)
	if err != nil {
		log.Fatal(err)
	}

	authHandler := &TokenAuthHandler{
		Client: &http.Client{
			Timeout: clientTimeout,
		},
		Config: s.Config,
	}

	router := mux.NewRouter()
	router.Handle("/auth", authHandler)
	router.HandleFunc("/server-ping", serverPing)
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
