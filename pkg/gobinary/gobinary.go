package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/calmdocs/appexit"
	"github.com/calmdocs/keyexchange"
	"github.com/calmdocs/pubsub"

	"github.com/gorilla/mux"
)

const (
	hostName    = "localhost"
	isSecure    = false
	path        = "/ws"
	sendRoom    = "0" // full websocket url is ws://localhost:8000/ws/1
	receiveRoom = "1" // full websocket url is ws://localhost:8000/ws/0
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Flag variables
	killPID := flag.Int("pid", 0, "source process identifier (pid)") // -pid=7423
	authToken := flag.String("token", "", "authentication token")
	port := flag.Int("port", 0, "port")

	flag.Parse()

	if port == nil || *port == 0 {
		fmt.Println("Exiting.  Please provide port (e.g. -port=8080))")
		os.Exit(0)
	}
	host := fmt.Sprintf("%s:%d", hostName, *port)

	if killPID == nil || *killPID == 0 {
		fmt.Println("Exiting.  Please run script with process id to monitor (e.g. -pid=1234)")
		os.Exit(0)
	}
	if authToken == nil || *authToken == "" {
		fmt.Println("Exiting.  Please provide authentication token (e.g. -token=abc123)")
		os.Exit(0)
	}

	// Exit when process with pid exits
	if killPID != nil && *killPID != 0 {
		fmt.Println("Exit when the process with the following pid exits:", *killPID)
		appexit.PID(ctx, cancel, killPID)
	}

	// Create keyexchangeStore and print public key to stdOut as PEM
	keyexchangeStore, err := keyexchange.New_Curve25519_SHA256_HKDF_AESGCM(
		*authToken,
	)
	if err != nil {
		panic(err)
	}
	pemString, err := keyexchangeStore.PublicKeyPEM()
	if err != nil {
		panic(err)
	}
	fmt.Println(pemString)

	// Create mux router
	r := mux.NewRouter().StrictSlash(true)

	// Start websockets server with integer channels
	s := pubsub.NewServer(ctx)
	r.HandleFunc(fmt.Sprintf("%s/{id:[0-9]+}", path), func(w http.ResponseWriter, r *http.Request) {

		// Local access only
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if ip != "127.0.0.1" {
			fmt.Println("remote access forbidden:", ip)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Get room
		id, ok := mux.Vars(r)["id"]
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Auth
		bearerToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearerToken != *authToken {
			fmt.Println("auth failure", bearerToken, authToken)
			http.Error(w, "id error", http.StatusForbidden)
			return
		}

		// Handle the websocket request
		err = s.HandlePubSub(id, w, r)
		if err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
	})

	// Create http server
	httpServer := http.Server{
		Handler: r,
		Addr:    host,
		//WriteTimeout: 15 * time.Second,
		//ReadTimeout:  15 * time.Second,
	}
	defer httpServer.Close()

	// Create websockets Status store
	store := NewStore(
		host,
		isSecure,
		*authToken,
		path,
		sendRoom,
		receiveRoom,
		keyexchangeStore,
		keyexchange.CurrentTimestamp(),
	)

	// Start websockets Status store
	go store.Start(ctx)

	// Request new entry to start
	go func() {
		<-time.After(time.Second)

		err := pubItem(
			ctx,
			host,
			*authToken,
			isSecure,
			path,
			receiveRoom,
			keyexchangeStore,
		)
		if err != nil {
			fmt.Println(err)
		}

	}()

	// Start http server
	err = httpServer.ListenAndServe()
	if err != nil {
		if !strings.Contains(err.Error(), "http: Server closed") {
			panic(err)
		}
	}
}

func pubItem(
	ctx context.Context,
	host string,
	token string,
	isSecure bool,
	path string,
	room string,
	keyexchangeStore *keyexchange.Store,
) (err error) {
	b, err := keyexchangeStore.EncodeJSONAndEncryptToJSON(
		&WSRequest{
			Type: "addItem",
			ID:   "",
			Data: "",
		},
		keyexchange.CurrentTimestampBytes(),
	)
	if err != nil {
		return err
	}
	return pubsub.PubWithBearerToken(
		ctx,
		host,
		token,
		isSecure,
		path,
		room,
		b,
	)
}

type Status struct {
	ID       int64
	Error    error
	Name     string
	Status   string
	Progress float64
}

type WSRequest struct {
	Type string
	ID   interface{}
	Data interface{}
}

type Store struct {
	sync.RWMutex

	m                map[int64]Status
	maxID            int64
	isUpdateRequired bool

	wsHost    string
	isSecure  bool
	authToken string
	wsPath    string

	sendRoom    string
	receiveRoom string

	keyexchangeStore        *keyexchange.Store
	additionalDataTimestamp int64
}

func NewStore(
	wsHost string,
	isSecure bool,
	authToken string,
	wsPath string,
	sendRoom string,
	receiveRoom string,
	keyexchangeStore *keyexchange.Store,
	additionalDataTimestamp int64,
) *Store {
	return &Store{
		m:                       make(map[int64]Status),
		maxID:                   0,
		isUpdateRequired:        true,
		wsHost:                  wsHost,
		isSecure:                isSecure,
		authToken:               authToken,
		wsPath:                  wsPath,
		sendRoom:                sendRoom,
		receiveRoom:             receiveRoom,
		keyexchangeStore:        keyexchangeStore,
		additionalDataTimestamp: additionalDataTimestamp,
	}
}

func (s *Store) Start(parentCtx context.Context) {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	s.startReceiveClient(ctx)
	s.startSendClient(ctx)
}

func (s *Store) startReceiveClient(ctx context.Context) {
	receiveClient := pubsub.NewClientWithBearerToken(
		s.wsHost,
		s.authToken,
		s.isSecure,
		s.wsPath,
		s.receiveRoom,
	)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			err := receiveClient.Start(ctx, func(message []byte) (err error) {

				// Unmarshal message
				var request WSRequest
				err = s.keyexchangeStore.UnmarshalJSONAndDecryptFromJSONWithADCheck(
					message,
					&request,
					func(additionalData []byte) (bool, error) {

						// Only process new messages
						ok, i, err := keyexchange.AuthTimestamp(additionalData, s.additionalDataTimestamp)
						if err != nil {
							return false, err
						}
						if !ok {
							return false, nil
						}
						s.additionalDataTimestamp = i
						return true, nil
					},
				)
				if err != nil {
					if errors.Is(err, keyexchange.ErrUnmarsal) {
						return nil
					}
					return err
				}

				// Handle message
				switch request.Type {

				case "addItem":
					s.newItem()

				case "deleteItem":
					itemString, ok := request.ID.(string)
					if !ok {
						return fmt.Errorf("request identifier is not a string: %v", request.ID)
					}
					itemID, err := strconv.ParseInt(itemString, 10, 64)
					if err != nil {
						return err
					}
					ok = s.deleteItem(itemID)
					if !ok {
						return fmt.Errorf("item to delete does not exist: %d", itemID)
					}
				default:
					fmt.Printf("unrecognised inbound ws message: %#v\n", request)
				}
				return nil
			})
			if err != nil {
				fmt.Println("websocket receiveClient err:", err.Error())
			}
		}
	}()
}

func (s *Store) startSendClient(ctx context.Context) {
	sendClient := pubsub.NewClientWithBearerToken(
		s.wsHost,
		s.authToken,
		s.isSecure,
		s.wsPath,
		s.sendRoom,
	)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			err := sendClient.Start(ctx, func(message []byte) (err error) {
				return nil
			})
			if err != nil {
				fmt.Println("websocket sendClient err:", err.Error())
			}
		}
	}()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	updateCount := int64(0)
	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:

			// Randomise all items (every 1.25 seconds)
			updateCount += 1
			if updateCount == 5 {
				updateCount = 0
				s.randomiseAllItems()
			}

			// Publish all items to websockets server (4 times per second)
			err := s.sendAllItems(sendClient)
			if err != nil {
				print(err)
			}
		}
	}
}

func (s *Store) newItem() {
	s.Lock()
	defer s.Unlock()

	s.isUpdateRequired = true
	s.maxID += 1
	s.m[s.maxID] = Status{
		ID:       s.maxID,
		Error:    nil,
		Name:     fmt.Sprintf("entry %d", s.maxID),
		Status:   fmt.Sprintf("%.2f %%", float64(0)*100),
		Progress: 0,
	}
}

func (s *Store) randomiseAllItems() {
	s.Lock()
	defer s.Unlock()

	s.isUpdateRequired = true
	for _, sg := range s.m {
		sg = sg

		newProgress := rand.Float64()
		sg.Progress = newProgress
		sg.Status = fmt.Sprintf("%.2f %%", newProgress*100)
		s.m[sg.ID] = sg
	}
}

func (s *Store) sendAllItems(cl *pubsub.Client) (err error) {
	s.Lock()
	defer s.Unlock()

	if !s.isUpdateRequired {
		return nil
	}
	s.isUpdateRequired = false
	v := []Status{}
	for _, sg := range s.m {
		v = append(v, sg)
	}
	b, err := s.keyexchangeStore.EncodeJSONAndEncryptToJSON(
		v,
		keyexchange.CurrentTimestampBytes(),
	)
	if err != nil {
		return err
	}
	return cl.WriteTextMessage(b)
}

func (s *Store) deleteItem(itemID int64) bool {
	s.Lock()
	defer s.Unlock()

	s.isUpdateRequired = true
	_, ok := s.m[itemID]
	if !ok {
		return false
	}
	delete(s.m, itemID)
	return true
}
