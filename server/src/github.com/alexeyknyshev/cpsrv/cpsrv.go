package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/tarantool/go-tarantool"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const SERVER_DEFAULT_CONFIG = "config.json"
const GOOGLE_AUTH_PATH = "../data/GoogleAuth.html"

type ServerConfig struct {
	TownsDataBase      string `json:"TownsDataBase"`
	CashPointsDataBase string `json:"CashPointsDataBase"`
	CertificateDir     string `json:"CertificateDir"`
	Port               uint64 `json:"Port"`
	UserLoginMinLength uint64 `json:"UserLoginMinLength"`
	UserPwdMinLength   uint64 `json:"UserPwdMinLength"`
	UseTLS             bool   `json:"UseTLS"`
	RedisHost          string `json:"RedisHost"`
	RedisScriptsDir    string `json:"RedisScriptsDir"`
	ReqResLogTTL       uint64 `json:"ReqResLogTTL"`
	UUID_TTL           uint64 `json:"UUID_TTL"`
	BanksIcoDir        string `json:"BanksIcoDir"`
	TestingMode        bool   `json:"TestingMode"`
	TntUser            string `json:"TntUser"`
	TntPass            string `json:"TntPass"`
	TntUrl             string `json:"TntUrl"`
}

type Message struct {
	Text string `json:"text"`
}

type HandlerContextStruct struct {
	TntConnection *tarantool.Connection
	TestLogger    *TestLogger
}

type HandlerContext interface {
	Tnt() *tarantool.Connection
	Logger() Logger
	Close()
}

func (handler HandlerContextStruct) Tnt() *tarantool.Connection {
	return handler.TntConnection
}

func (handler HandlerContextStruct) Logger() Logger {
	return handler.TestLogger
}

func (handler HandlerContextStruct) Close() {
	handler.TntConnection.Close()
}

func makeHandlerContext(serverConfig *ServerConfig) (*HandlerContextStruct, error) {
	opts := tarantool.Opts{
		Reconnect:     1 * time.Second,
		MaxReconnects: 3,
		User:          serverConfig.TntUser,
		Pass:          serverConfig.TntPass,
	}
	timeout := 10
	var err error
	var tnt *tarantool.Connection
	for i := 0; i <= timeout; i++ {
		time.Sleep(1 * time.Second)
		tnt, err = tarantool.Connect(serverConfig.TntUrl, opts)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("Cannot connect to tarantool: %v", err)
	}

	handlerContext := &HandlerContextStruct{
		TntConnection: tnt,
		TestLogger: &TestLogger{
			ch: make(chan string),
		},
	}

	return handlerContext, nil
}

func prepareResponse(w http.ResponseWriter, r *http.Request, logger Logger) (bool, int64) {
	requestId, err := getRequestUserId(r)
	if err != nil {
		logStr := getRequestContexString(r) + " prepareResponse " + err.Error()
		logger.logWriter(logStr)
		w.WriteHeader(http.StatusBadRequest)
		return false, 0
	}

	if requestId == 0 {
		strReqId := strconv.FormatInt(requestId, 10)
		logStr := getRequestContexString(r) + " prepareResponse unexpected requestId: " + strReqId
		logger.logWriter(logStr)
		w.WriteHeader(http.StatusBadRequest)
		return false, 0
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Id", strconv.FormatInt(requestId, 10))
	return true, requestId
}

func writeResponse(w http.ResponseWriter, r *http.Request, requestId int64, responseBody string, logger Logger) {
	io.WriteString(w, responseBody)
	logger.logResponse(w, r, requestId, responseBody)
}

func writeHeader(w http.ResponseWriter, r *http.Request, requestId int64, code int, logger Logger) {
	w.WriteHeader(code)
	logger.logResponse(w, r, requestId, "code "+strconv.FormatInt(int64(code), 10))
}

func checkConvertionUint(val uint32, err error, context string) uint32 {
	if err != nil {
		log.Printf("%s: uint conversion err => %v\n", context, err)
		return 0
	}
	return val
}

func getRequestContexString(r *http.Request) string {
	return r.RemoteAddr
}

func getHandlerContextString(funcName string, args map[string]string) string {
	result := funcName + "("
	i := 0
	argsCount := len(args)
	for argName, argVal := range args {
		result = result + argName + "=" + argVal
		if i < argsCount-1 {
			result = result + ","
		}
		i++
	}
	result = result + ")"

	return result
}

func getRequestUserId(r *http.Request) (int64, error) {
	requestIdStr := r.Header.Get("Id")
	if requestIdStr == "" {
		return 0, errors.New(`Request header val "Id" is not set`)
	}
	requestId, err := strconv.ParseInt(requestIdStr, 10, 64)
	if err != nil {
		return 0, errors.New(`Request header val "Id" uint conversion failed: ` + requestIdStr)
	}
	return requestId, nil
}

func getRequestJsonStr(r *http.Request, context string) (string, error) {
	jsonStr, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("%s => malformed json\n", context)
		return "", err
	}
	return string(jsonStr), nil
}

type EndpointCallback func(w http.ResponseWriter, r *http.Request)

func handlerPing(handlerContext HandlerContext) (string, EndpointCallback) {
	return "/ping", func(w http.ResponseWriter, r *http.Request) {
		logger := handlerContext.Logger()
		ok, requestId := prepareResponse(w, r, logger)
		if ok == false {
			return
		}

		logger.logRequest(w, r, requestId, "")
		msg := &Message{Text: "pong"}
		jsonByteArr, _ := json.Marshal(msg)
		writeResponse(w, r, requestId, string(jsonByteArr), logger)
	}
}

func handlerGoogleAuth(handlerContext HandlerContext, htmlCode []byte) (string, EndpointCallback) {
	return "/", func(w http.ResponseWriter, r *http.Request) {
		logger := handlerContext.Logger()
		requestId := int64(1)
		logger.logRequest(w, r, requestId, "")
		writeResponse(w, r, requestId, string(htmlCode), logger)
	}
}

func verifyTokenId(token string) (sub string, err error, httpCode int) {
	resp, err := http.Get("https://www.googleapis.com/oauth2/v3/tokeninfo?id_token=" + token)
	if err != nil {
		log.Println("Failed to calling the tokeninfo endpoint:", err)
		httpCode = http.StatusBadGateway
		return "", err, httpCode
	}
	defer resp.Body.Close()
	jsonResp, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Failed to read response:", err)
		httpCode = http.StatusInternalServerError
		return "", err, httpCode
	}
	var parsedResp map[string]interface{}
	err = json.Unmarshal(jsonResp, &parsedResp)
	if err != nil {
		log.Println("json decode error:", err)
		return "", err, http.StatusBadRequest
	}

	if parsedResp["error_description"] != nil {
		str, _ := parsedResp["error_description"].(string)
		log.Println("error_description:", str)
		return "", err, http.StatusBadRequest
	}
	if sub, success := (parsedResp["sub"]).(string); !success {
		err = errors.New("failed interface to string convertation")
		log.Println(err)
		return "", err, http.StatusBadRequest
	} else {
		return sub, err, http.StatusOK
	}
}

func main() {
	log.SetFlags(log.Flags() | log.Lmicroseconds)

	args := os.Args[1:]

	configFilePath := SERVER_DEFAULT_CONFIG
	if len(args) > 0 {
		configFilePath = args[0]
		log.Printf("Loading config file: %s\n", configFilePath)
	} else {
		log.Printf("Loading default config file: %s\n", configFilePath)
	}

	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		log.Fatalf("No such config file: %s\n", configFilePath)
	}

	configFile, _ := os.Open(configFilePath)
	decoder := json.NewDecoder(configFile)
	serverConfig := ServerConfig{}
	err := decoder.Decode(&serverConfig)
	if err != nil {
		log.Fatalf("Failed to decode config file: %s\nError: %v\n", configFilePath, err)
		return
	}

	if serverConfig.TestingMode {
		log.Printf("WARNING: Server started is TESTING mode! Make sure it is not prod server.")
	}
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	htmlCode, err := ioutil.ReadFile(dir + "/" + GOOGLE_AUTH_PATH)
	if err != nil {
		log.Fatal("Failed to open GoogleAuth.html:", err)
	}
	handlerContext, err := makeHandlerContext(&serverConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer handlerContext.Close()

	router := mux.NewRouter()
	router.HandleFunc(handlerPing(handlerContext)).Methods("GET")
	router.HandleFunc(handlerCashpoint(handlerContext)).Methods("GET")
	router.HandleFunc(handlerCashpointCreate(handlerContext)).Methods("POST")
	router.HandleFunc(handlerCashpointsBatch(handlerContext)).Methods("POST")
	router.HandleFunc(handlerCashpointPatches(handlerContext)).Methods("GET")
	router.HandleFunc(handlerTown(handlerContext)).Methods("GET")
	router.HandleFunc(handlerTownsBatch(handlerContext)).Methods("POST")
	router.HandleFunc(handlerTownsList(handlerContext)).Methods("GET")

	router.HandleFunc(handlerMetroList(handlerContext)).Methods("GET")
	router.HandleFunc(handlerMetro(handlerContext)).Methods("GET")
	router.HandleFunc(handlerMetroBatch(handlerContext)).Methods("POST")
	router.HandleFunc(handlerBank(handlerContext)).Methods("GET")
	router.HandleFunc(handlerBankIco(handlerContext, serverConfig)).Methods("GET")
	router.HandleFunc(handlerBanksList(handlerContext)).Methods("GET")
	router.HandleFunc(handlerBanksBatch(handlerContext)).Methods("POST")
	router.HandleFunc(handlerNearbyCashPoints(handlerContext)).Methods("POST")
	router.HandleFunc(handlerNearbyClusters(handlerContext)).Methods("POST")
	router.HandleFunc(handlerGoogleAuth(handlerContext, htmlCode)).Methods("GET")

	if serverConfig.TestingMode {
		router.HandleFunc(handlerCoordToQuadKey(handlerContext)).Methods("POST")
		router.HandleFunc(handlerQuadTreeBranch(handlerContext)).Methods("GET")
		router.HandleFunc(handlerCashpointDelete(handlerContext)).Methods("DELETE")
		router.HandleFunc(handlerSpaceMetrics(handlerContext)).Methods("GET")
	}

	port := strconv.FormatUint(serverConfig.Port, 10)
	log.Println("Listening port: " + port)

	server := &http.Server{
		Addr:           ":" + port,
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
