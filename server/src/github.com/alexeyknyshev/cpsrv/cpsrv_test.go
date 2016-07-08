package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/alexeyknyshev/gojsondiff"
	"github.com/alexeyknyshev/gojsondiff/formatter"
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type TestRequest struct {
	RequestType   string
	EndpointUrl   string
	HandlerUrl    string
	Data          string
	Authorization bool
}

type TestResponse struct {
	Code int
	Data []byte
}

func getServerConfig() *ServerConfig {
	url := "localhost"
	shift := 2
	for _, vol := range os.Args {
		if strings.Contains(vol, "-test.run") {
			shift++
		}
	}
	if len(os.Args) == shift {
		url = os.Args[shift-1]
	}
	return &ServerConfig{
		TntUrl:  url + ":3301",
		TntUser: "admin",
		TntPass: "admin",
	}
}

func readResponse(w *httptest.ResponseRecorder) (TestResponse, error) {
	response := TestResponse{}

	response.Code = w.Code

	data, err := ioutil.ReadAll(w.Body)
	if err != nil {
		err = errors.New("Cannot read response body: " + err.Error())
	} else {
		response.Data = data
	}
	return response, err
}

var DEFAULT_COMPARE_CONF gojsondiff.CompareConfig = gojsondiff.CompareConfig{FloatEpsilon: 0.0001}

func diff(expected, received []byte, conf *gojsondiff.CompareConfig) (string, error) {
	//isObject := true
	if conf == nil {
		conf = &DEFAULT_COMPARE_CONF
	}

	differ := gojsondiff.New()

	// try to compare as objects
	d, err := differ.Compare(expected, received, conf)
	if err != nil {
		// try to compare as arrays
		var nextErr error
		d, nextErr = differ.CompareArrays(expected, received, conf)

		// return first error on second failure
		if nextErr != nil {
			return "", errors.New("Failed to compare json pair: " + err.Error())
		}
		//isObject = false
	}

	if !d.Modified() {
		return "", nil
	}

	var expectedJson map[string]interface{}
	json.Unmarshal(expected, &expectedJson)
	formatter := formatter.NewAsciiFormatter(expectedJson)
	formatter.ShowArrayIndex = true
	diffString, err := formatter.Format(d)
	if err != nil {
		// No error can occur
	}

	return diffString, nil
}

func testRequest(request TestRequest, handler EndpointCallback) *httptest.ResponseRecorder {
	var req *http.Request = nil

	if request.Data != "" {
		req, _ = http.NewRequest(request.RequestType, request.EndpointUrl, bytes.NewBufferString(request.Data))
	} else {
		req, _ = http.NewRequest(request.RequestType, request.EndpointUrl, nil)
	}

	req.Header.Add("Id", "1")

	if request.Authorization {
		req.Header.Add("Authorization", "Bearer testMode")
	}
	w := httptest.NewRecorder()
	m := mux.NewRouter()
	if request.HandlerUrl == "" {
		request.HandlerUrl = request.EndpointUrl
	}
	m.HandleFunc(request.HandlerUrl, handler).Methods(request.RequestType)
	m.ServeHTTP(w, req)

	return w
}

func checkHttpCode(t *testing.T, got, expected int) bool {
	if got != expected {
		t.Errorf("Expected %d %s but got %d", expected, http.StatusText(expected), got)
		return false
	}
	return true
}

func checkJsonResponse(t *testing.T, got, expected []byte) bool {
	diffStr, err := diff(expected, got, nil)
	if err != nil {
		t.Errorf("Failed to compare json pair: %v", err)
		return false
	}
	if diffStr != "" {
		t.Errorf("\n%s", diffStr)
		return false
	}
	return true
}

// ======================================================================

type SpaceMetrics struct {
	Regions           uint32 `json:"regions"`
	Towns             uint32 `json:"towns"`
	Cashpoints        uint32 `json:"cashpoints"`
	Banks             uint32 `json:"banks"`
	Clusters          uint32 `json:"clusters"`
	CashpointsPatches uint32 `json:"cashpoints_patches"`
}

func getSpaceMetrics(hCtx HandlerContext) ([]byte, error) {
	url, handler := handlerSpaceMetrics(hCtx)
	request := TestRequest{RequestType: "GET", EndpointUrl: url}
	response, err := readResponse(testRequest(request, handler))
	if err != nil {
		return nil, err
	}

	return response.Data, nil
}

type SpaceMetricsGetter func() ([]byte, error)

func checkSpaceMetrics(t *testing.T, getMetrics SpaceMetricsGetter, expected []byte) bool {
	got, err := getMetrics()
	if err != nil {
		t.Errorf("Failed to get space metric on defer: %v", err)
		return false
	}

	return checkJsonResponse(t, got, expected)
}

// ======================================================================

func getQuadTreeBranch(t *testing.T, hCtx HandlerContext, longitude, latitude float64) ([]byte, error) {
	// get quadkey for coorditate
	quadKeyReq := QuadKeyRequest{
		Longitude: longitude,
		Latitude:  latitude,
	}
	quadkeyReqJson, _ := json.Marshal(quadKeyReq)
	url, handlerQuadKey := handlerCoordToQuadKey(hCtx)
	request := TestRequest{
		RequestType: "POST",
		EndpointUrl: url,
		Data:        string(quadkeyReqJson),
	}

	response, err := readResponse(testRequest(request, handlerQuadKey))
	if err != nil {
		return nil, err
	}
	if !checkHttpCode(t, response.Code, http.StatusOK) {
		return nil, fmt.Errorf("cannot get quadkey for coordinate: (%f, %f)",
			longitude, latitude)
	}

	quadKeyResponse := QuadKeyResponse{}
	err = json.Unmarshal(response.Data, &quadKeyResponse)
	if err != nil {
		return nil, fmt.Errorf("cannot unpack quadkey response: %v => %s",
			err, string(response.Data))
	}

	if quadKeyResponse.QuadKey == "" {
		return nil, fmt.Errorf("received empty quadkey => %s", string(response.Data))
	}

	// save quadtree branch state (before adding cashpoint)
	url, handlerTreeBranch := handlerQuadTreeBranch(hCtx)
	requestTreeBranch := TestRequest{
		RequestType: "GET",
		EndpointUrl: "/quadtree/branch/" + quadKeyResponse.QuadKey,
		HandlerUrl:  url,
	}

	response, err = readResponse(testRequest(requestTreeBranch, handlerTreeBranch))
	if err != nil {
		return nil, err
	}
	if !checkHttpCode(t, response.Code, http.StatusOK) {
		return nil, fmt.Errorf("cannot get quad tree branch for quadkey: %s", quadKeyResponse.QuadKey)
	}

	return response.Data, nil
}

type QuadTreeBranchGetter func() ([]byte, error)

func checkQuadTreeBranch(t *testing.T, getBranch QuadTreeBranchGetter, expected []byte) bool {
	got, err := getBranch()
	if err != nil {
		t.Errorf("Failed to get quad tree branch on defer: %v", err)
		return false
	}

	var clusters, clustersNew ClusterArray
	err = json.Unmarshal(expected, &clusters)
	if err != nil {
		t.Errorf("Cannot unpack expected quad tree branch response: %v", err)
	}

	err = json.Unmarshal(got, &clustersNew)
	if err != nil {
		t.Errorf("Cannot unpack defer quad tree branch response: %v", err)
	}

	if same, diffText := clusters.Compare(clustersNew); !same {
		t.Fatalf("%s\n\n%s\n%s\n%s",
			diffText,
			"ALERT! Quad tree branches before and after create + delete are different.",
			"Looks like quad tree is broken after test and data in tarantool is corrupted.",
			"Please, refill database with fresh testing data again by running 'build_db_tnt.sh' script.")
		return false
	}
	return true
}

// ======================================================================

func TestPing(t *testing.T) {
	hCtx, err := makeHandlerContext(getServerConfig())
	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	// check metrics before and after test
	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)

	url, handler := handlerPing(hCtx)
	request := TestRequest{RequestType: "GET", EndpointUrl: url}
	response, err := readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}

	checkHttpCode(t, response.Code, http.StatusOK)

	expected := Message{Text: "pong"}
	expectedJson, _ := json.Marshal(expected)

	checkJsonResponse(t, response.Data, expectedJson)
}

// ======================================================================

type Town struct {
	Id             uint32  `json:"id"`
	Name           string  `json:"name"`
	NameTr         string  `json:"name_tr"`
	Longitude      float64 `json:"longitude"`
	Latitude       float64 `json:"latitude"`
	RegionId       uint32  `json:"region_id"`
	RegionalCenter bool    `json:"regional_center"`
	Big            bool    `json:"big"`
	Zoom           uint32  `json:"zoom"`
	HasMetro       bool    `json:"has_metro"`
}

func TestTown(t *testing.T) {
	hCtx, err := makeHandlerContext(getServerConfig())
	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	// check metrics before and after test
	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)

	url, handler := handlerTown(hCtx)
	request := TestRequest{RequestType: "GET", EndpointUrl: "/town/4", HandlerUrl: url}
	response, err := readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusOK)

	expected := Town{
		Id:             4,
		Name:           "Москва",
		NameTr:         "Moskva",
		Longitude:      37.61775970459,
		Latitude:       55.755771636963,
		RegionId:       3,
		RegionalCenter: true,
		Big:            true,
		Zoom:           10,
		HasMetro:       true,
	}
	expectedJson, _ := json.Marshal(expected)

	checkJsonResponse(t, response.Data, expectedJson)
}

// =====================================================================

type ScheduleBreak struct {
	From int `json:"f"`
	To   int `json:"t"`
}

type ScheduleDay struct {
	Day    int              `json:"-"`
	From   int              `json:"f"`
	To     int              `json:"t"`
	Breaks *[]ScheduleBreak `json:"b,omitempty"`
}

type Schedule struct {
	Mon    *ScheduleDay     `json:"mon,omitempty"`
	Tue    *ScheduleDay     `json:"tue,omitempty"`
	Wed    *ScheduleDay     `json:"wed,omitempty"`
	Thu    *ScheduleDay     `json:"thu,omitempty"`
	Fri    *ScheduleDay     `json:"fri,omitempty"`
	Sat    *ScheduleDay     `json:"sat,omitempty"`
	Sun    *ScheduleDay     `json:"sun,omitempty"`
	Breaks *[]ScheduleBreak `json:"b,omitempty"`
}

type CashpointShort struct {
	Id             uint32   `json:"id,omitempty"`
	Longitude      float64  `json:"longitude"`
	Latitude       float64  `json:"latitude"`
	Type           string   `json:"type"`
	BankId         uint32   `json:"bank_id"`
	TownId         uint32   `json:"town_id"`
	Address        string   `json:"address"`
	AddressComment string   `json:"address_comment"`
	MetroName      string   `json:"metro_name"`
	FreeAccess     bool     `json:"free_access"`
	MainOffice     bool     `json:"main_office"`
	WithoutWeekend bool     `json:"without_weekend"`
	RoundTheClock  bool     `json:"round_the_clock"`
	WorksAsShop    bool     `json:"works_as_shop"`
	Schedule       Schedule `json:"schedule"`
	Tel            string   `json:"tel"`
	Additional     string   `json:"additional"`
	Currency       []uint32 `json:"currency"`
	CashIn         bool     `json:"cash_in"`
	UserId         string   `json:"user_id,omitempty"`
}

type CashpointFull struct {
	CashpointShort
	Version    uint32  `json:"version"`
	//	Timestamp      uint64  `json:"timestamp"` // TODO: timestamp on server
	Approved   bool    `json:"approved"`
	PatchCount uint32  `json:"patch_count"`
}

func TestCashpointGet(t *testing.T) {
	hCtx, err := makeHandlerContext(getServerConfig())
	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	// check metrics before and after test
	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)

	url, handler := handlerCashpoint(hCtx)
	var id uint32 = 7138832
	request := TestRequest{
		RequestType: "GET",
		EndpointUrl: "/cashpoint/" + strconv.FormatUint(uint64(id), 10),
		HandlerUrl:  url,
	}
	response, err := readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}

	checkHttpCode(t, response.Code, http.StatusOK)

	cpShort := CashpointShort{
		Id:             id,
		Longitude:      37.562019348145,
		Latitude:       55.6633644104,
		Type:           "atm",
		BankId:         2764,
		TownId:         4,
		Address:        "г. Москва, ул. Новочеремушкинская, д. 69",
		AddressComment: "ОАО «Вниизарубежгеология»",
		MetroName:      "",
		FreeAccess:     true,
		MainOffice:     false,
		WithoutWeekend: false,
		RoundTheClock:  false,
		WorksAsShop:    true,
		Schedule:       Schedule{},
		Tel:            "",
		Additional:     "",
		Currency:       []uint32{643},
		CashIn:         false,
	}

	cp := CashpointFull{
		CashpointShort: cpShort,
		Version:        0,
		//Timestamp: 0,
		Approved:       true,
		PatchCount:     0,
	}
	expectedJson, _ := json.Marshal(cp)
	checkJsonResponse(t, response.Data, expectedJson)
}

// ======================================================================

type QuadKeyRequest struct {
	Longitude float64 `json:"longitude,omitempty"`
	Latitude  float64 `json:"latitude,omitempty"`
	Zoom      uint32  `json:"zoom,omitempty"`
}

type QuadKeyResponse struct {
	QuadKey string `json:"quadkey"`
}

func TestQuadKeyFromCoord(t *testing.T) {
	hCtx, err := makeHandlerContext(getServerConfig())

	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	// check metrics before and after test
	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)

	url, handler := handlerCoordToQuadKey(hCtx)

	// empty request
	quadKeyReq := QuadKeyRequest{}
	reqJson, _ := json.Marshal(quadKeyReq)

	request := TestRequest{
		RequestType: "POST",
		EndpointUrl: url,
		Data:        string(reqJson),
	}

	response, err := readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}

	checkHttpCode(t, response.Code, http.StatusBadRequest)

	// request with missing Latitude
	quadKeyReq.Longitude = 56.6
	reqJson, _ = json.Marshal(quadKeyReq)

	request.Data = string(reqJson)

	response, err = readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}

	checkHttpCode(t, response.Code, http.StatusBadRequest)

	// normal request
	quadKeyReq.Latitude = 34.84
	reqJson, _ = json.Marshal(quadKeyReq)

	request.Data = string(reqJson)

	response, err = readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}

	expected := QuadKeyResponse{QuadKey: "3032100220113311"}
	expectedJson, _ := json.Marshal(expected)

	checkHttpCode(t, response.Code, http.StatusOK)
	checkJsonResponse(t, response.Data, expectedJson)

	// request with zoom
	quadKeyReq.Zoom = 16
	reqJson, _ = json.Marshal(quadKeyReq)

	request.Data = string(reqJson)

	response, err = readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}

	checkHttpCode(t, response.Code, http.StatusOK)
	checkJsonResponse(t, response.Data, expectedJson)

	// request with lower zoom
	quadKeyReq.Zoom = 12
	reqJson, _ = json.Marshal(quadKeyReq)

	request.Data = string(reqJson)

	response, err = readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}

	expected.QuadKey = "303210022011"
	expectedJson, _ = json.Marshal(expected)

	checkHttpCode(t, response.Code, http.StatusOK)
	checkJsonResponse(t, response.Data, expectedJson)
}

// ======================================================================

type Cluster struct {
	Id        string   `json:"id"`
	Longitude float64  `json:"longitude"`
	Latitude  float64  `json:"latitude"`
	Members   []uint32 `json:"members"`
	Size      uint32   `json:"size"`
}

type ClusterArray []Cluster

func (c ClusterArray) Compare(other ClusterArray) (bool, string) {
	if len(c) != len(other) {
		return false, "different length of ClusterArrays"
	}

	for i := 0; i < len(c); i++ {
		expectedJson, _ := json.Marshal(c[i])
		responseJson, _ := json.Marshal(other[i])

		diffStr, err := diff(expectedJson, responseJson, nil)
		if err != nil {
			return false, "failed to compare Cluster json pair at index " +
				strconv.FormatInt(int64(i), 10) + ": " + err.Error()
		}
		if diffStr != "" {
			return false, "different Cluster json pair at index " +
				strconv.FormatInt(int64(i), 10) + ": " + diffStr
		}
	}

	// 	return false, "successfully compared " + strconv.FormatInt(int64(len(c)), 10) + " clusters"
	return true, ""
}

func TestQuadTreeBranch(t *testing.T) {
	hCtx, err := makeHandlerContext(getServerConfig())
	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	// check metrics before and after test
	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)

	url, handler := handlerQuadTreeBranch(hCtx)
	request := TestRequest{
		RequestType: "GET",
		EndpointUrl: "/quadtree/branch/3201323213002023",
		HandlerUrl:  url,
	}

	response, err := readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}

	checkHttpCode(t, response.Code, http.StatusOK)

	// test short quadkey
	request.EndpointUrl = "/quadtree/branch/3201323213002"
	response, err = readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}

	checkHttpCode(t, response.Code, http.StatusOK)

	// test empty quadkey
	request.EndpointUrl = "/quadtree/branch/"
	response, err = readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}

	checkHttpCode(t, response.Code, http.StatusNotFound)

	// test too long quadkey
	request.EndpointUrl = "/quadtree/branch/320132321300211100"
	response, err = readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}

	checkHttpCode(t, response.Code, http.StatusBadRequest)

	// test wrong quadkey
	request.EndpointUrl = "/quadtree/branch/3201323253002023"
	response, err = readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}

	checkHttpCode(t, response.Code, http.StatusNotFound)
}

// ======================================================================

type CashpointCreateRequest struct {
	UserId string         `json:"user_id"`
	Data   CashpointShort `json:"data"`
}

type Coordinate struct {
	Longitude float64 `json:"longitude"`
	Latitude  float64 `json:"latitude"`
}

type Filter struct {
	BankIdList *[]uint32 `json:"bank_id,omitempty"`
	Approved   *bool     `json:"approved,omitempty"`
}

type CashpointNearbyRequest struct {
	TopLeft     Coordinate `json:"topLeft"`
	BottomRight Coordinate `json:"bottomRight"`
	Filter      Filter     `json:"filter"`
}

func TestCashpointCreateSuccessful(t *testing.T) {
	log.SetFlags(log.Flags() | log.Lmicroseconds)
	hCtx, err := makeHandlerContext(getServerConfig())
	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	// check metrics before and after test
	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)

	longitude := 37.6247
	latitude := 55.7591

	// predict quadkey of the future cashpoint
	quadKeyReq := QuadKeyRequest{
		Longitude: longitude,
		Latitude:  latitude,
	}
	quadkeyReqJson, _ := json.Marshal(quadKeyReq)

	url, handlerQuadKey := handlerCoordToQuadKey(hCtx)
	request := TestRequest{
		RequestType: "POST",
		EndpointUrl: url,
		Data:        string(quadkeyReqJson),
	}

	response, err := readResponse(testRequest(request, handlerQuadKey))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusOK)

	quadKeyResponse := QuadKeyResponse{}
	err = json.Unmarshal(response.Data, &quadKeyResponse)
	if err != nil {
		t.Errorf("Cannot unpack quadkey response: %v => %s", err, string(response.Data))
	}

	if quadKeyResponse.QuadKey == "" {
		t.Errorf("Received empty quadkey => %s", string(response.Data))
	}

	// save quadtree branch state (before adding cashpoint)
	url, handlerTreeBranch := handlerQuadTreeBranch(hCtx)
	requestTreeBranch := TestRequest{
		RequestType: "GET",
		EndpointUrl: "/quadtree/branch/" + quadKeyResponse.QuadKey,
		HandlerUrl:  url,
	}

	response, err = readResponse(testRequest(requestTreeBranch, handlerTreeBranch))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusOK)

	var clusters ClusterArray
	err = json.Unmarshal(response.Data, &clusters)
	if err != nil {
		t.Errorf("Cannot unpack quad tree branch response: %v", err)
	}

	// creating real cashpoint
	cp := CashpointShort{
		Longitude:      longitude,
		Latitude:       latitude,
		Type:           "atm",
		BankId:         322, // Sberbank
		TownId:         4,   // Moscow
		Address:        "",
		AddressComment: "",
		//		MetroName: "",
		FreeAccess:     true,
		MainOffice:     false,
		WithoutWeekend: true,
		RoundTheClock:  false,
		WorksAsShop:    false,
		Schedule:       Schedule{},
		Tel:            "",
		Additional:     "",
		Currency:       []uint32{643},
		CashIn:         true,
	}
	userId := "0"
	reqData := CashpointCreateRequest{
		UserId: userId, // TODO: check against real user
		Data:   cp,
	}
	reqJson, _ := json.Marshal(reqData)

	url, handlerCreate := handlerCashpointCreate(hCtx)
	request = TestRequest{
		RequestType:   "POST",
		EndpointUrl:   "/cashpoint",
		HandlerUrl:    url,
		Data:          string(reqJson),
		Authorization: true,
	}
	response, err = readResponse(testRequest(request, handlerCreate))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusOK)

	var cashpointId uint64 = 0
	err = json.Unmarshal(response.Data, &cashpointId)
	if err != nil {
		t.Errorf("Cannot unpack cashpoint id response: %v => %s", err, string(response.Data))
	}

	cashpointIdStr := strconv.FormatUint(cashpointId, 10)
	t.Logf("created cashpoint with id: %s", cashpointIdStr)

	// TODO: check cashpoint data
	urlGet, handlerGet := handlerCashpoint(hCtx)
	request = TestRequest{
		RequestType: "GET",
		EndpointUrl: "/cashpoint/" + cashpointIdStr,
		HandlerUrl:  urlGet,
	}

	response, err = readResponse(testRequest(request, handlerGet))
	if err != nil {
		t.Errorf("%v", err)
	}
	if !checkHttpCode(t, response.Code, http.StatusOK) {
		t.Fatalf("Cannot get created cashpoint with id: %d", cashpointId)
	}

	// extend cashpoint short data with returned id
	cp.Id = uint32(cashpointId)
	cp.UserId = userId
	cpFull := CashpointFull{
		CashpointShort: cp,
		Version:        0,
		Approved:       false,
		PatchCount:     1, // created & not approved cp has atleast 1 patch
	}
	expectedJson, _ := json.Marshal(cpFull)

	// repack response to remove timestamp field
	var tmpJson map[string]interface{}
	err = json.Unmarshal(response.Data, &tmpJson)
	if err != nil {
		t.Fatalf("Cannot unpack cashpoint data retrieved by id: %d", cashpointId)
	}
	delete(tmpJson, "timestamp")

	responseJson, _ := json.Marshal(tmpJson)

	checkJsonResponse(t, responseJson, expectedJson)

	// TODO: check cluster data

	// TODO: check nearby cashpoints
	url, handlerNearby := handlerNearbyCashPoints(hCtx)
	nearbyRequest := CashpointNearbyRequest{
		TopLeft: Coordinate{
			Longitude: longitude - 0.001,
			Latitude:  latitude - 0.001,
		},
		BottomRight: Coordinate{
			Longitude: longitude + 0.001,
			Latitude:  latitude + 0.001,
		},
		Filter: Filter{
			Approved: new(bool),
		},
	}
	reqJson, _ = json.Marshal(nearbyRequest)

	request = TestRequest{
		RequestType: "POST",
		EndpointUrl: url,
		HandlerUrl:  url,
		Data:        string(reqJson),
	}

	response, err = readResponse(testRequest(request, handlerNearby))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusOK)

	expectedJson, _ = json.Marshal([]uint64{cashpointId})
	checkJsonResponse(t, response.Data, expectedJson)

	// now delete created cashpoint
	url, handlerDelete := handlerCashpointDelete(hCtx)
	request = TestRequest{
		RequestType:   "DELETE",
		EndpointUrl:   "/cashpoint/" + cashpointIdStr,
		HandlerUrl:    url,
		Authorization: true,
	}

	response, err = readResponse(testRequest(request, handlerDelete))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusOK)

	// try to get deleted cashpoint
	request = TestRequest{
		RequestType: "GET",
		EndpointUrl: "/cashpoint/" + cashpointIdStr,
		HandlerUrl:  urlGet,
	}

	response, err = readResponse(testRequest(request, handlerGet))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusNotFound)

	// get new quadtree branch state (after adding cashpoint)
	// there is no expected changes
	response, err = readResponse(testRequest(requestTreeBranch, handlerTreeBranch))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusOK)

	var clustersNew ClusterArray
	err = json.Unmarshal(response.Data, &clustersNew)
	if err != nil {
		t.Errorf("Cannot unpack quad tree branch response: %v", err)
	}

	if same, diffText := clusters.Compare(clustersNew); !same {
		t.Fatalf("%s\n\n%s\n%s\n%s",
			diffText,
			"ALERT! Quad tree branches before and after create + delete are different.",
			"Looks like quad tree is broken after test and data in tarantool is corrupted.",
			"Please, refill database with fresh testing data again by running 'build_db_tnt.sh' script.")
	}
}

func TestCashpointCreateWrongCoordinates(t *testing.T) {
	hCtx, err := makeHandlerContext(getServerConfig())
	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	// check metrics before and after test
	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)

	longitude := 203.456
	latitude := 55.7591

	quadKeyReq := QuadKeyRequest{
		Longitude: longitude,
		Latitude:  latitude,
	}
	quadkeyReqJson, _ := json.Marshal(quadKeyReq)

	url, handlerQuadKey := handlerCoordToQuadKey(hCtx)
	request := TestRequest{
		RequestType: "POST",
		EndpointUrl: url,
		Data:        string(quadkeyReqJson),
	}

	response, err := readResponse(testRequest(request, handlerQuadKey))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusBadRequest)

	// creating real cashpoint with wrong coordinates
	cp := CashpointShort{
		Longitude:      longitude,
		Latitude:       latitude,
		Type:           "atm",
		BankId:         322, // Sberbank
		TownId:         4,   // Moscow
		Address:        "",
		AddressComment: "",
		//		MetroName: "",
		FreeAccess:     true,
		MainOffice:     false,
		WithoutWeekend: true,
		RoundTheClock:  false,
		WorksAsShop:    false,
		Schedule:       Schedule{},
		Tel:            "",
		Additional:     "",
		Currency:       []uint32{643},
		CashIn:         true,
	}

	reqData := CashpointCreateRequest{
		UserId: "0", // TODO: check against real user
		Data:   cp,
	}
	reqJson, _ := json.Marshal(reqData)

	url, handlerCreate := handlerCashpointCreate(hCtx)
	request = TestRequest{
		RequestType:   "POST",
		EndpointUrl:   "/cashpoint",
		HandlerUrl:    url,
		Data:          string(reqJson),
		Authorization: true,
	}

	response, err = readResponse(testRequest(request, handlerCreate))
	if err != nil {
		t.Errorf("%v", err)
	}
	if !checkHttpCode(t, response.Code, http.StatusInternalServerError) {
		// cashpoint created for some reason
		if response.Code == http.StatusOK {
			var cashpointId uint64 = 0
			err = json.Unmarshal(response.Data, &cashpointId)
			if err != nil {
				t.Fatalf(`ALERT! Looks like cashpoint created but its id was not returned.
					  Please, refill database with fresh testing data again by running 'build_db_tnt.sh' script.`)
			} else {
				t.Fatalf(`ALERT! Looks like cashpoint created with id '%d'.
					  Please, refill database with fresh testing data again by running 'build_db_tnt.sh' script
					  or delete cashpoint and following data manually.`, cashpointId)
			}
		}
	}
}

func TestCashpointCreateMissingRequredFields(t *testing.T) {
	hCtx, err := makeHandlerContext(getServerConfig())
	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	// check metrics before and after test
	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)

	longitude := 38.2371
	latitude := 56.4631

	// check quad tree branches for coordinate before and after test
	quadTreeBranch, err := getQuadTreeBranch(t, hCtx, longitude, latitude)
	if err != nil {
		t.Errorf("Failed to cache quad tree branch: %v", err)
	}
	defer checkQuadTreeBranch(t, func() ([]byte, error) { return getQuadTreeBranch(t, hCtx, longitude, latitude) }, quadTreeBranch)

	// creating real cashpoint with missing required fields
	cp := CashpointShort{
		Longitude:      longitude,
		Latitude:       latitude,
		Type:           "atm",
		BankId:         322, // Sberbank
		TownId:         4,   // Moscow
		Address:        "",
		AddressComment: "",
		//		MetroName: "",
		FreeAccess:     true,
		MainOffice:     false,
		WithoutWeekend: true,
		// 		RoundTheClock: false, // WARNING: here is missing field
		WorksAsShop: false,
		Schedule:    Schedule{},
		Tel:         "",
		Additional:  "",
		Currency:    []uint32{643},
		CashIn:      true,
	}

	reqData := CashpointCreateRequest{
		UserId: "0", // TODO: check against real user
		Data:   cp,
	}
	reqJson, _ := json.Marshal(reqData)

	var tmpJson map[string]interface{}
	err = json.Unmarshal(reqJson, &tmpJson)
	if err != nil {
		t.Errorf("Failed unmarshal tmp CashpointCreateRequest: %v", err)
	}

	// repack with missing field
	data := tmpJson["data"].(map[string]interface{})
	delete(data, "round_the_clock")
	reqJson, _ = json.Marshal(tmpJson)

	url, handlerCreate := handlerCashpointCreate(hCtx)
	request := TestRequest{
		RequestType:   "POST",
		EndpointUrl:   "/cashpoint",
		HandlerUrl:    url,
		Data:          string(reqJson),
		Authorization: true,
	}

	response, err := readResponse(testRequest(request, handlerCreate))
	if err != nil {
		t.Errorf("%v", err)
	}
	if !checkHttpCode(t, response.Code, http.StatusInternalServerError) {
		// cashpoint created for some reason
		if response.Code == http.StatusOK {
			var cashpointId uint64 = 0
			err = json.Unmarshal(response.Data, &cashpointId)
			if err != nil {
				t.Fatalf(`ALERT! Looks like cashpoint created but its id was not returned.
					  Please, refill database with fresh testing data again by running 'build_db_tnt.sh' script.`)
			} else {
				t.Fatalf(`ALERT! Looks like cashpoint created with id '%d'.
					  Please, refill database with fresh testing data again by running 'build_db_tnt.sh' script
					  or delete cashpoint and following data manually.`, cashpointId)
			}
		}
	}
}

func TestCashpointCreateApproveHack(t *testing.T) {
	hCtx, err := makeHandlerContext(getServerConfig())
	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	// check metrics before and after test
	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)

	longitude := 38.2371
	latitude := 56.4631

	// check quad tree branches for coordinate before and after test
	quadTreeBranch, err := getQuadTreeBranch(t, hCtx, longitude, latitude)
	if err != nil {
		t.Errorf("Failed to cache quad tree branch: %v", err)
	}
	defer checkQuadTreeBranch(t, func() ([]byte, error) { return getQuadTreeBranch(t, hCtx, longitude, latitude) }, quadTreeBranch)

	// creating real cashpoint with missing required fields
	cp := CashpointShort{
		Longitude:      longitude,
		Latitude:       latitude,
		Type:           "atm",
		BankId:         322, // Sberbank
		TownId:         4,   // Moscow
		Address:        "",
		AddressComment: "",
		//MetroName: "",
		FreeAccess:     true,
		MainOffice:     false,
		WithoutWeekend: true,
		//RoundTheClock: false, // WARNING: here is missing field
		WorksAsShop: false,
		Schedule:    Schedule{},
		Tel:         "",
		Additional:  "",
		Currency:    []uint32{643},
		CashIn:      true,
	}

	reqData := CashpointCreateRequest{
		UserId: "0", // TODO: check against real user
		Data:   cp,
	}
	reqJson, _ := json.Marshal(reqData)

	var tmpJson map[string]interface{}
	err = json.Unmarshal(reqJson, &tmpJson)
	if err != nil {
		t.Errorf("Failed unmarshal tmp CashpointCreateRequest: %v", err)
	}

	// repack with unexpected field approved
	data := tmpJson["data"].(map[string]interface{})
	data["approved"] = true
	reqJson, _ = json.Marshal(tmpJson)

	url, handlerCreate := handlerCashpointCreate(hCtx)
	request := TestRequest{
		RequestType:   "POST",
		EndpointUrl:   "/cashpoint",
		HandlerUrl:    url,
		Data:          string(reqJson),
		Authorization: true,
	}

	response, err := readResponse(testRequest(request, handlerCreate))
	if err != nil {
		t.Errorf("%v", err)
	}
	// expecting validation failure
	if !checkHttpCode(t, response.Code, http.StatusInternalServerError) {
		// cashpoint created for some reason
		if response.Code == http.StatusOK {
			var cashpointId uint64 = 0
			err = json.Unmarshal(response.Data, &cashpointId)
			if err != nil {
				t.Fatalf(`ALERT! Looks like cashpoint created but its id was not returned.
					  Please, refill database with fresh testing data again by running 'build_db_tnt.sh' script.`)
			} else {
				t.Fatalf(`ALERT! Looks like cashpoint created with id '%d'.
					  Please, refill database with fresh testing data again by running 'build_db_tnt.sh' script
					  or delete cashpoint and following data manually.`, cashpointId)
			}
		}
	}
}

// =====================================================

func TestCashpointEdit(t *testing.T) {
	hCtx, err := makeHandlerContext(getServerConfig())
	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	// check metrics before and after test
	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)

	var cpId uint32 = 7243171

	cpPatch := make(map[string]interface{})
	cpPatch["id"] = cpId
	cpPatch["type"] = "atm"

	cpReqPayload := make(map[string]interface{})
	cpReqPayload["user_id"] = "0" // TODO: user_id passing
	cpReqPayload["data"] = cpPatch

	req, _ := json.Marshal(cpReqPayload)
	url, handlerEdit := handlerCashpointCreate(hCtx)
	requestEdit := TestRequest{
		RequestType:   "POST",
		EndpointUrl:   url,
		Data:          string(req),
		Authorization: true,
	}

	response, err := readResponse(testRequest(requestEdit, handlerEdit))
	if err != nil {
		t.Errorf("%v", err)
	}

	checkHttpCode(t, response.Code, http.StatusOK)
	// TODO: check cp id in response
	//checkJsonResponse

	url, handlerGet := handlerCashpoint(hCtx)
	request := TestRequest{
		RequestType: "GET",
		EndpointUrl: "/cashpoint/" + strconv.FormatUint(uint64(cpId), 10),
		HandlerUrl:  url,
	}

	response, err = readResponse(testRequest(request, handlerGet))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusOK)

	sDay := &ScheduleDay{
		From: 540,  // 09:00
		To:   1260, // 21:00
	}
	cp := CashpointShort{
		Id:             cpId,
		Longitude:      48.049293518066,
		Latitude:       46.369739532471,
		Type:           "office", // must not be changed (patch has not approved yet)
		BankId:         194275,
		TownId:         290,
		Address:        "г. Астрахань, ул.Савушкина, д.23в",
		AddressComment: "",
		MetroName:      "",
		FreeAccess:     true,
		MainOffice:     false,
		WithoutWeekend: false,
		RoundTheClock:  false,
		WorksAsShop:    false,
		// 		Schedule:       "пн.—пт.: 09:00—21:00,сб.: 10:00—17:00",
		Schedule: Schedule{
			Mon: sDay,
			Tue: sDay,
			Wed: sDay,
			Thu: sDay,
			Fri: sDay,
			Sat: &ScheduleDay{
				From: 600,  // 10:00
				To:   1020, // 17:00
			},
		},
		Tel:        "",
		Additional: "",
		Currency:   []uint32{643},
		CashIn:     false,
	}
	cpFull := CashpointFull{
		CashpointShort: cp,
		Version:        0,
		Approved:       true,
		PatchCount:     1,
	}

	expectedJson, _ := json.Marshal(cpFull)

	checkJsonResponse(t, response.Data, expectedJson)

	url, handlerPatches := handlerCashpointPatches(hCtx)
	request = TestRequest{
		RequestType:   "GET",
		EndpointUrl:   "/cashpoint/" + strconv.FormatUint(uint64(cpId), 10) + "/patches",
		HandlerUrl:    url,
		Authorization: true,
	}

	response, err = readResponse(testRequest(request, handlerPatches))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusOK)

	var metrics_ SpaceMetrics
	err = json.Unmarshal(metrics, &metrics_)
	if err != nil {
		t.Errorf("%v", err)
	}

	cpPatchId := strconv.FormatUint(uint64(metrics_.CashpointsPatches + 1), 10)

	checkJsonResponse(t, response.Data, []byte(`{"` + cpPatchId + `":{"type":"atm"}}`))
	checkHttpCode(t, response.Code, http.StatusOK)

	// resend same patch
	response, err = readResponse(testRequest(requestEdit, handlerEdit))
	checkHttpCode(t, response.Code, http.StatusInternalServerError)

	_, err = hCtx.Tnt().Eval("box.space.cashpoints_patches:delete{" + cpPatchId + "}", []interface{}{})
	if err != nil {
		t.Errorf("Cannot delete patch with id '1': %v", err)
	}
}

type FilterSchedule struct {
	Time  uint64 `json:"time"`
	Delta uint32 `json:"delta"`
}

type NearByRequestFilter struct {
	BankId   []uint32        `json:"bank_id,omitempty"`
	FiltSch  *FilterSchedule `json:"schedule,omitempty"`
	Currency []uint32        `json:"currency,omitempty"`
}

type NearByRequest struct {
	BottomRight Coordinate          `json:"bottomRight"`
	TopLeft     Coordinate          `json:"topLeft"`
	Filter      NearByRequestFilter `json:"filter"`
}

func TestFilterBankIdCount(t *testing.T) {
	hCtx, err := makeHandlerContext(getServerConfig())
	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)

	reqNearBy := NearByRequest{
		BottomRight: Coordinate{
			Longitude: 12.0,
			Latitude:  13.0,
		},
		TopLeft: Coordinate{
			Longitude: 12.01,
			Latitude:  13.01,
		},
		Filter: NearByRequestFilter{
			BankId:  []uint32{322, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 357, 338, 339, 340},
			FiltSch: &FilterSchedule{},
		},
	}

	url, handlerCreate := handlerNearbyCashPoints(hCtx)

	reqJson, _ := json.Marshal(reqNearBy)
	request := TestRequest{
		RequestType: "POST",
		EndpointUrl: url,
		Data:        string(reqJson),
	}

	response, err := readResponse(testRequest(request, handlerCreate))
	if err != nil {
		t.Errorf("%v", err)
	}

	if !checkHttpCode(t, response.Code, http.StatusInternalServerError) {
		// cashpoint created for some reason
		if response.Code == http.StatusOK {
			var cashpointId uint64 = 0
			err = json.Unmarshal(response.Data, &cashpointId)
			if err != nil {
				t.Fatalf(`ALERT! Looks like cashpoint created but its id was not returned.
					  Please, refill database with fresh testing data again by running 'build_db_tnt.sh' script.`)
			} else {
				t.Fatalf(`ALERT! Looks like cashpoint created with id '%d'.
					  Please, refill database with fresh testing data again by running 'build_db_tnt.sh' script
					  or delete cashpoint and following data manually.`, cashpointId)
			}
		}
	}
}

func TestFilterCurrency(t *testing.T) {
	hCtx, err := makeHandlerContext(getServerConfig())
	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)
	reqNearBy := NearByRequest{
		BottomRight: Coordinate{
			Longitude: 37.64, //, , ,
			Latitude:  55.76,
		},
		TopLeft: Coordinate{
			Longitude: 37.65,
			Latitude:  55.77,
		},
		Filter: NearByRequestFilter{
			Currency: []uint32{840},
		},
	}

	url, handlerCreate := handlerNearbyCashPoints(hCtx)

	reqJson, _ := json.Marshal(reqNearBy)
	request := TestRequest{
		RequestType: "POST",
		EndpointUrl: url,
		Data:        string(reqJson),
	}
	response, err := readResponse(testRequest(request, handlerCreate))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusOK)
	expectedResp := []int{6575135, 6580021, 341381, 342266}
	var respDataArray []int
	err = json.Unmarshal(response.Data, &respDataArray)
	sort.Ints(respDataArray)
	sort.Ints(expectedResp)
	if len(expectedResp) != len(respDataArray) {
		t.Error("Received amount of cashpoints not equal expected")
		return
	}

	for i, _ := range respDataArray {
		if respDataArray[i] != expectedResp[i] {
			t.Error("Comparison failed")
			return
		}
	}
}

func TestTimeFilter(t *testing.T) {
	hCtx, err := makeHandlerContext(getServerConfig())
	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)

	reqNearBy := NearByRequest{
		BottomRight: Coordinate{
			Longitude: 37.614022861099215,
			Latitude:  55.758164990332041,
		},
		TopLeft: Coordinate{
			Longitude: 37.608873019790622,
			Latitude:  55.762994273656425,
		},
		Filter: NearByRequestFilter{
			FiltSch: &FilterSchedule{
				Time:  1458397500, // sat, 17:25 (UTC+3)
				Delta: 1800,
			},
		},
	}

	url, handlerCreate := handlerNearbyCashPoints(hCtx)

	reqJson, _ := json.Marshal(reqNearBy)
	request := TestRequest{
		RequestType: "POST",
		EndpointUrl: url,
		Data:        string(reqJson),
	}

	response, err := readResponse(testRequest(request, handlerCreate))
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	checkHttpCode(t, response.Code, http.StatusOK)

	expectedResponse := []int{
		384924, 316411, 316416, 324453, 3470560,
		4437472, 4508915, 4406301, 5500542, 943485,
		2376541, 2820889, 7125785, 7194801, 7194843,
		7235343, 7913779, 8158920, 8158944, 605269,
		6764619, 736685, 6484376, 7129653, 7688033,
		8128184, 8232204, 1259403, 1272692}

	var respDataArray []int
	err = json.Unmarshal(response.Data, &respDataArray)
	if err != nil {
		t.Errorf("Failed unmarshal response.Data:%v", err)
		return
	}

	sort.Ints(respDataArray)
	sort.Ints(expectedResponse)
	if len(expectedResponse) != len(respDataArray) {
		t.Error("Received amount of cashpoints not equal expected")
		return
	}

	for i, _ := range respDataArray {
		if respDataArray[i] != expectedResponse[i] {
			t.Error("Comparison failed")
			return
		}
	}

}

//Test metro
type Metro struct {
	StationName     string  `json:"station_name"`
	Longitude       float64 `json:"longitude"`
	Latitude        float64 `json:"latitude"`
	Id              uint32  `json:"id"`
	StationExitName string  `json:"station_exit_name"`
	TownId          uint32  `json:"town_id"`
	BranchId        uint32  `json:"branch_id"`
}

func getMetroTuple() Metro {
	expected := Metro{
		StationName:     "Беляево",
		Longitude:       37.526596999601,
		Latitude:        55.643621500032,
		Id:              779,
		StationExitName: "вход-выход 2 в северный вестибюль",
		TownId:          4,
		BranchId:        3,
	}
	return expected
}

func TestMetro(t *testing.T) {
	hCtx, err := makeHandlerContext(getServerConfig())
	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)

	url, handler := handlerMetro(hCtx)
	metroId := uint32(779)
	request := TestRequest{RequestType: "GET", EndpointUrl: "/metro/" + strconv.FormatInt(int64(metroId), 10), HandlerUrl: url}
	response, err := readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusOK)
	expectedJson, _ := json.Marshal(getMetroTuple())
	checkJsonResponse(t, response.Data, expectedJson)
}

func TestMetroBatch(t *testing.T) {
	hCtx, err := makeHandlerContext(getServerConfig())
	if err != nil {
		t.Fatalf("Connection to tarantool failed: %v", err)
	}
	defer hCtx.Close()

	metrics, err := getSpaceMetrics(hCtx)
	if err != nil {
		t.Errorf("Failed to get space metric on start: %v", err)
	}
	defer checkSpaceMetrics(t, func() ([]byte, error) { return getSpaceMetrics(hCtx) }, metrics)

	url, handler := handlerMetroBatch(hCtx)
	data := struct {
		Metro []uint32 `json:"metro"`
	}{
		[]uint32{779},
	}
	dataJson, _ := json.Marshal(data)
	request := TestRequest{
		RequestType: "POST",
		EndpointUrl: url,
		Data:        string(dataJson),
	}
	response, _ := readResponse(testRequest(request, handler))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusOK)
	expectedTuple, err := json.Marshal(getMetroTuple())
	expectedResponse := "[" + string(expectedTuple) + "]"
	checkJsonResponse(t, response.Data, []byte(expectedResponse))
}
