package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"
)

type PatchRequest struct {
	Id             uint32    `json:"id,omitempty"`
	Longitude      float64   `json:"longitude,omitempty"`
	Latitude       float64   `json:"latitude,omitempty"`
	Type           string    `json:"type,omitempty"`
	BankId         uint32    `json:"bank_id,omitempty"`
	TownId         uint32    `json:"town_id,omitempty"`
	Address        string    `json:"address,omitempty"`
	AddressComment string    `json:"address_comment,omitempty"`
	MetroName      string    `json:"metro_name,omitempty"`
	FreeAccess     *bool     `json:"free_access,omitempty"`
	MainOffice     *bool     `json:"main_office,omitempty"`
	WithoutWeekend *bool     `json:"without_weekend,omitempty"`
	RoundTheClock  *bool     `json:"round_the_clock,omitempty"`
	WorksAsShop    *bool     `json:"works_as_shop,omitempty"`
	Schedule       *Schedule `json:"schedule,omitempty"`
	Tel            string    `json:"tel,omitempty"`
	Additional     string    `json:"additional,omitempty"`
	Currency       []uint32  `json:"currency,omitempty"`
	CashIn         *bool     `json:"cash_in,omitempty"`
}

type TestPatchReq struct {
	Data   PatchRequest `json:"data"`
	UserId string       `json:"user_id"`
}

func getPatchExampleNewCP() *PatchRequest {
	False := false
	True := true
	sched := Schedule{}
	patchReq := PatchRequest{
		Longitude:      37.6878262,
		Latitude:       55.6946643,
		Type:           "atm",
		BankId:         322,
		TownId:         4,
		Address:        "г. Москва, Район Моей Мечты",
		AddressComment: "ОАО UnderButtom",
		MetroName:      "",
		FreeAccess:     &True,
		MainOffice:     &False,
		WithoutWeekend: &False,
		RoundTheClock:  &False,
		WorksAsShop:    &True,
		Tel:            "",
		Schedule:       &sched,
		Additional:     "",
		Currency:       []uint32{643},
		CashIn:         &False,
	}
	return &patchReq

}

func getPatchExampleExistCP() (*PatchRequest, string) {
	patchReq := PatchRequest{
		Id:     58552,
		BankId: 322,
	}
	exampleJson := "{\"bank_id\":" + strconv.FormatUint(uint64(patchReq.BankId), 10) + "}"
	return &patchReq, exampleJson

}

func searchLastPatch(t *testing.T, resJsonPatches []byte) uint32 {
	var CPPatches map[string]interface{}
	err := json.Unmarshal(resJsonPatches, &CPPatches)
	if err != nil {
		t.Errorf("Unmarshal err %v", err)
		return 0
	}
	last_key := uint64(0)
	//Search last patch number
	for key := range CPPatches {
		int_key, _ := strconv.ParseUint(key, 10, 64)
		if int_key > last_key {
			last_key = int_key
		}
	}
	return uint32(last_key)
}

func comparePatches(t *testing.T, resPatch []interface{}, expectedPatch []interface{}) {
	if len(resPatch) != len(expectedPatch) {
		t.Error("response and expected patches have different field amount")
		return
	}

	fields := []string{"patch id", "cashpoint id", "user_id", "data", "timestamp"}
	for i, vol := range expectedPatch {
		if i == 2 {
			if resPatch[i].(string) != vol.(string) {
				t.Error("comparePatches: fields", fields[i], "don't match")
			}
		} else if i == 3 { //PATCH_DATA
			checkJsonResponse(t, []byte(vol.(string)), []byte(resPatch[i].(string)))
		} else if i != 4 { //don't check timestamp
			if resPatch[i].(uint64) != vol.(uint64) {
				t.Error("comparePatches: fields", fields[i], "don't match")
			}
		}
	}
}

func invokeTaranPatchFuncs(t *testing.T, hCtx *HandlerContextStruct, requestJson []byte) (uint32, uint64) {
	url, handlerCreate := handlerCashpointCreate(hCtx)
	request := TestRequest{
		RequestType:   "POST",
		EndpointUrl:   "/cashpoint",
		HandlerUrl:    url,
		Data:          string(requestJson),
		Authorization: true,
	}
	response, err := readResponse(testRequest(request, handlerCreate))
	if err != nil {
		t.Errorf("%v", err)
	}
	checkHttpCode(t, response.Code, http.StatusOK)

	var CpId uint64 = 0
	err = json.Unmarshal(response.Data, &CpId)
	if err != nil {
		t.Errorf("Cannot unpack cashpoint id response: %v => %s", err, string(response.Data))
	}

	resp, err := hCtx.Tnt().Call("getCashpointPatches", []interface{}{CpId})
	if err != nil {
		t.Errorf("Tnt getCashpointPatches call err: %v", err)
	}
	byteResp := []byte(resp.Data[0].([]interface{})[0].(string))
	lastPatch := searchLastPatch(t, byteResp)
	if lastPatch == 0 {
		fmt.Println("Delete cashpoint ", CpId)
		resp, err = hCtx.Tnt().Call("deleteCashpointById", []interface{}{CpId})
		if err != nil {
			t.Errorf("Tnt call deleteCashpointById err: %v", err)
		}
		if !resp.Data[0].([]interface{})[0].(bool) {
			t.Error("deleteCashpointById return false")
		}
	}
	return lastPatch, CpId
}

func TestPatchCreateNewCP(t *testing.T) {

	patchReq := getPatchExampleNewCP()
	request := TestPatchReq{
		Data:   *patchReq,
		UserId: "1",
	}
	requestJson, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Json Marshal error %v", err)
	}
	fmt.Println("Request:\n", string(requestJson), "\n")

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

	lastPatch, CpId := invokeTaranPatchFuncs(t, hCtx, requestJson)
	if lastPatch == 0 {
		return
	}
	resp, err := hCtx.Tnt().Call("getCashpointPatchByPatchId", []interface{}{lastPatch})
	resPatch := resp.Data[0].([]interface{})
	expPatchData := "{\"id\":" + strconv.FormatInt(int64(CpId), 10) + "}"
	expectedPatch := []interface{}{uint64(lastPatch), CpId, request.UserId, expPatchData, uint64(0)}
	comparePatches(t, resPatch, expectedPatch)
	fmt.Println("Delete cashpoint ", CpId)
	resp, err = hCtx.Tnt().Call("deleteCashpointById", []interface{}{CpId})
	if err != nil {
		t.Errorf("Tnt call deleteCashpointById err: %v", err)
	}
	if !resp.Data[0].([]interface{})[0].(bool) {
		t.Error("deleteCashpointById return false")
	}
}

func TestPatchChangeExistCP(t *testing.T) {

	patchReq, expPatchData := getPatchExampleExistCP()
	request := TestPatchReq{
		Data:   *patchReq,
		UserId: "1",
	}
	requestJson, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Json Marshal error %v", err)
	}
	fmt.Println("Request:\n", string(requestJson), "\n")

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

	lastPatch, CpId := invokeTaranPatchFuncs(t, hCtx, requestJson)
	if lastPatch == 0 {
		return
	}
	resp, err := hCtx.Tnt().Call("getCashpointPatchByPatchId", []interface{}{lastPatch})
	resPatch := resp.Data[0].([]interface{})
	expectedPatch := []interface{}{uint64(lastPatch), CpId, request.UserId, expPatchData, uint64(0)}
	comparePatches(t, resPatch, expectedPatch)

	fmt.Println("response patch:\n", resPatch)

	fmt.Println("Delete patch ", lastPatch)
	resp, err = hCtx.Tnt().Call("_deleteCashpointPatchById", []interface{}{lastPatch})
	if err != nil {
		t.Errorf("Tnt _deleteCashpointPatchById call err: %v", err)
	}
}

type VotePatch struct {
	PatchId uint32 `json:"patch_id,omitempty"`
	UserId  string `json:"user_id"`
	Score   uint32 `json:"score"`
}

func voteCompare(t *testing.T, res, expected *VotePatch) bool {
	success := true
	if res.UserId != expected.UserId {
		t.Error("expected UserId = ", expected.UserId, "got UserId = ", res.UserId)
		success = false
	}
	if res.Score != expected.Score {
		t.Error("expected Score = ", expected.Score, "got Score = ", res.Score)
		success = false
	}
	return success
}

func invokeTaranVoteFuncs(t *testing.T, hCtx *HandlerContextStruct, voteJsonReq []byte, lastPatch uint32) (*([]VotePatch), bool) {
	voteResp, err := hCtx.Tnt().Call("cashpointVotePatch", []interface{}{voteJsonReq})
	if err != nil {
		t.Errorf("Tnt cashpointVotePatch call err:\n%v", err)
		fmt.Println("voteResp:", voteResp)
		return nil, false
	}
	decodeVoteResp := voteResp.Data[0].([]interface{})[0].(bool)
	if !decodeVoteResp {
		return nil, decodeVoteResp
	}

	voteList, err := hCtx.Tnt().Call("getCashpointPatchVotes", []interface{}{lastPatch})
	if err != nil {
		t.Errorf("Tnt getCashpointPatchVotes call err: %v", err)
	}
	//fmt.Println("getCashpointPatchVotes return:", voteList.Data[0].([]interface{})[0].(string))
	var decodeVoteList []VotePatch
	err = json.Unmarshal([]byte(voteList.Data[0].([]interface{})[0].(string)), &decodeVoteList)
	if err != nil {
		t.Errorf("Unmarshal err: %v", err)
		return nil, decodeVoteResp
	}
	return &decodeVoteList, decodeVoteResp
}

//Test single and double voting by one user
func TestPatchOneUserVoting(t *testing.T) {

	patchReq := getPatchExampleNewCP()
	request := TestPatchReq{
		Data:   *patchReq,
		UserId: "1",
	}
	requestJson, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Json Marshal error %v", err)
	}
	fmt.Println("Request:\n", string(requestJson), "\n")

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

	lastPatch, CpId := invokeTaranPatchFuncs(t, hCtx, requestJson)
	if lastPatch == 0 {
		return
	}
	resp, err := hCtx.Tnt().Call("getCashpointPatchByPatchId", []interface{}{lastPatch})
	resPatch := resp.Data[0].([]interface{})
	fmt.Println("response patch:\n", resPatch)
	voteReq := VotePatch{
		PatchId: lastPatch,
		UserId:  "2",
		Score:   1,
	}
	voteJsonReq, _ := json.Marshal(voteReq)
	fmt.Println("\nrequest vote:", string(voteJsonReq))
	decodeVoteList, success := invokeTaranVoteFuncs(t, hCtx, voteJsonReq, lastPatch)
	if !success {
		t.Error("cashpointVotePatch return false. Expected true")
	}
	success = voteCompare(t, &(*decodeVoteList)[0], &voteReq)
	if success {
		fmt.Println("compare success")
	}
	//test double voting
	fmt.Println("Test double voting")
	_, success = invokeTaranVoteFuncs(t, hCtx, voteJsonReq, lastPatch)
	if success {
		t.Error("Double voting test failed")
	} else {
		fmt.Println("Double voting test pass")
	}
	fmt.Println("Delete cashpoint ", CpId)
	resp, err = hCtx.Tnt().Call("deleteCashpointById", []interface{}{CpId})
	if err != nil {
		t.Errorf("Tnt call deleteCashpointById err: %v", err)
	}
	if !resp.Data[0].([]interface{})[0].(bool) {
		t.Error("deleteCashpointById return false")
	}
}

//Test voting by different users. Check approve mark after expected limit of votes
func TestPatchVotingByDiffUsers(t *testing.T) {
	patchReq := getPatchExampleNewCP()
	request := TestPatchReq{
		Data:   *patchReq,
		UserId: "1",
	}
	requestJson, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Json Marshal error %v", err)
	}
	fmt.Println("Request:\n", string(requestJson), "\n")

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

	lastPatch, CpId := invokeTaranPatchFuncs(t, hCtx, requestJson)
	if lastPatch == 0 {
		return
	}
	resp, err := hCtx.Tnt().Call("getCashpointPatchByPatchId", []interface{}{lastPatch})
	resPatch := resp.Data[0].([]interface{})
	fmt.Println("response patch:\n", resPatch)
	const NumberOfUsers = 5 // equals PATCH_APPROVE_VOTES from cpapi.lua
	var voteReqs [NumberOfUsers]VotePatch
	var voteJsonReqs [NumberOfUsers][]byte
	for i, _ := range voteReqs {
		voteReqs[i].PatchId = lastPatch
		voteReqs[i].Score = 1
		voteReqs[i].UserId = strconv.FormatInt(int64(i+1), 10)
		voteJsonReqs[i], _ = json.Marshal(voteReqs[i])
		fmt.Println("request vote №", i, ":", voteReqs[i])
	}
	for i, voteJsonReq := range voteJsonReqs {
		decodeVoteList, success := invokeTaranVoteFuncs(t, hCtx, voteJsonReq, lastPatch)
		if !success {
			t.Error("cashpointVotePatch return false but expected true")
		}
		voteCompare(t, &(*decodeVoteList)[i], &(voteReqs[i]))
	}
	//approve check
	resp, err = hCtx.Tnt().Call("getCashpointById", []interface{}{CpId})

	if err != nil {
		t.Errorf("Tnt call getCashpointById err: %v", err)
	}
	strResp := []byte(resp.Data[0].([]interface{})[0].(string))
	var decodeResp map[string]interface{}
	err = json.Unmarshal(strResp, &decodeResp)
	if err != nil {
		t.Error("unmarshal err: ", err)
	} else {
		if decodeResp["approved"].(bool) {
			fmt.Println("cashpoint approved")
		} else {
			t.Error("cashpoint not approved after", NumberOfUsers, "votes")
		}
	}

	fmt.Println("Delete cashpoint ", CpId)

	resp, err = hCtx.Tnt().Call("deleteCashpointById", []interface{}{CpId})

	if err != nil {
		t.Errorf("Tnt call deleteCashpointById err: %v", err)
	}
	if !resp.Data[0].([]interface{})[0].(bool) {
		t.Error("deleteCashpointById return false")
	}
}
