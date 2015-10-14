package main

import (
    "os"
    "log"
    "strconv"
    "database/sql"
    "encoding/json"
    _ "github.com/mattn/go-sqlite3"
    "github.com/mediocregopher/radix.v2/redis"
)

func boolToInt(val bool) uint {
    if val {
        return 1
    }
    return 0
}

type Town struct {
	Id             uint32  `json:"id"`
	Name           string  `json:"name"`
	NameTr         string  `json:"name_tr"`
	RegionId       uint32  `json:"region_id"`
	RegionalCenter bool    `json:"regional_center"`
	Latitude       float32 `json:"latitude"`
	Longitude      float32 `json:"longitude"`
	Zoom           uint32  `json:"zoom"`
}

type Region struct {
	Id        uint32  `json:"id"`
	Name      string  `json:"name"`
	NameTr    string  `json:"name_tr"`
	Latitude  float32 `json:"latitude"`
	Longitude float32 `json:"longitude"`
	Zoom      uint32  `json:"zoom"`
}

type CashPoint struct {
	Id             uint32  `json:"id"`
	Type           string  `json:"type"`
	BankId         uint32  `json:"bank_id"`
	TownId         uint32  `json:"town_id"`
	Longitude      float32 `json:"longitude"`
	Latitude       float32 `json:"latitude"`
	Address        string  `json:"address"`
	AddressComment string  `json:"address_comment"`
	MetroName      string  `json:"metro_name"`
	FreeAccess     bool    `json:"free_access"`
	MainOffice     bool    `json:"main_office"`
	WithoutWeekend bool    `json:"without_weekend"`
	RoundTheClock  bool    `json:"round_the_clock"`
	WorksAsShop    bool    `json:"works_as_shop"`
	Schedule       string  `json:"schedule"`
	Tel            string  `json:"tel"`
	Additional     string  `json:"additional"`
	Rub            bool    `json:"rub"`
	Usd            bool    `json:"usd"`
	Eur            bool    `json:"eur"`
	CashIn         bool    `json:"cash_in"`
}


func migrateTowns(townsDb *sql.DB, redisCli *redis.Client) {
    var townsCount int
    err := townsDb.QueryRow(`SELECT COUNT(*) FROM towns`).Scan(&townsCount)
    if err != nil {
        log.Fatalf("migrate: towns: %v\n", err)
    }

    rows, err := townsDb.Query(`SELECT id, name, name_tr, region_id,
                                       regional_center, latitude,
                                       longitude, zoom FROM towns`)
    if err != nil {
        log.Fatalf("migrate: towns: %v\n", err)
    }

    currentTownIdx := 1
    for rows.Next() {
        town := new(Town)
        err = rows.Scan(&town.Id, &town.Name, &town.NameTr,
                        &town.RegionId, &town.RegionalCenter,
                        &town.Latitude, &town.Longitude, &town.Zoom)
        if err != nil {
            log.Fatal(err)
        }

        jsonData, err := json.Marshal(town)
        if err != nil {
            log.Fatal(err)
        }

        err = redisCli.Cmd("SET", "town:" + strconv.FormatUint(uint64(town.Id), 10), string(jsonData)).Err
        if err != nil {
            log.Fatal(err)
        }

        err = redisCli.Cmd("GEOADD", "towns", town.Longitude, town.Latitude, town.Id).Err
        if err != nil {
            log.Fatal(err)
        }

        currentTownIdx++

        if currentTownIdx % 500 == 0 {
            log.Printf("[%d/%d] Towns processed\n", currentTownIdx, townsCount)
        }
    }
    log.Printf("[%d/%d] Towns processed\n", townsCount, townsCount)
}

func migrateRegions(townsDb *sql.DB, redisCli *redis.Client) {
    var regionsCount int
    err := townsDb.QueryRow(`SELECT COUNT(*) FROM regions`).Scan(&regionsCount)
    if err != nil {
        log.Fatalf("migrate: regions: %v\n", err)
    }

    rows, err := townsDb.Query(`SELECT id, name, name_tr,
                                       latitude, longitude, zoom FROM regions`)
    if err != nil {
        log.Fatalf("migrate: regions: %v\n", err)
    }

    currentRegionIdx := 1
    for rows.Next() {
        region := new(Region)
        err = rows.Scan(&region.Id, &region.Name, &region.NameTr,
                        &region.Latitude, &region.Longitude, &region.Zoom)
        if err != nil {
            log.Fatal(err)
        }

        jsonData, err := json.Marshal(region)
        if err != nil {
            log.Fatal(err)
        }

        err = redisCli.Cmd("SET", "region:" + strconv.FormatUint(uint64(region.Id), 10), string(jsonData)).Err
        if err != nil {
            log.Fatal(err)
        }

        currentRegionIdx++

        if currentRegionIdx % 500 == 0 {
            log.Printf("[%d/%d] Regions processed\n", currentRegionIdx, regionsCount)
        }
    }
    log.Printf("[%d/%d] Regions processed\n", regionsCount, regionsCount)
}

func migrateCashpoints(cpDb *sql.DB, redisCli *redis.Client) {
    var cashpointsCount int
    err := cpDb.QueryRow(`SELECT COUNT(*) FROM cashpoints`).Scan(&cashpointsCount)
    if err != nil {
        log.Fatalf("migrate: cashpoints: %v\n", err)
    }

    rows, err := cpDb.Query(`SELECT id, type, bank_id, town_id,
                                    longitude, latitude,
                                    address, address_comment,
                                    metro_name, free_access,
                                    main_office, without_weekend,
                                    round_the_clock, works_as_shop,
                                    schedule_general, tel, additional,
                                    rub, usd, eur, cash_in FROM cashpoints`)
    if err != nil {
        log.Fatalf("migrate: cashpoints: %v\n", err)
    }

    currentCashpointIndex := 1
    for rows.Next() {
        cp := new(CashPoint)
        err = rows.Scan(&cp.Id, &cp.Type, &cp.BankId, &cp.TownId,
                        &cp.Longitude, &cp.Latitude,
                        &cp.Address, &cp.AddressComment,
                        &cp.MetroName, &cp.FreeAccess,
                        &cp.MainOffice, &cp.WithoutWeekend,
                        &cp.RoundTheClock, &cp.WorksAsShop,
                        &cp.Schedule, &cp.Tel, &cp.Additional,
                        &cp.Rub, &cp.Usd, &cp.Eur, &cp.CashIn)
        if err != nil {
            log.Fatal(err)
        }

        cashpointIdStr := strconv.FormatUint(uint64(cp.Id), 10)
        townIdStr := strconv.FormatUint(uint64(cp.TownId), 10)
        bankIdStr := strconv.FormatUint(uint64(cp.BankId), 10)

        jsonData, err := json.Marshal(cp)
        if err != nil {
            log.Fatal(err)
        }

        err = redisCli.Cmd("SET", "cp:" + cashpointIdStr, string(jsonData)).Err

        if err != nil {
            log.Fatal(err)
        }

        err = redisCli.Cmd("GEOADD", "cashpoints", cp.Longitude, cp.Latitude, cp.Id).Err
        if err != nil {
            log.Fatal(err)
        }

        err = redisCli.Cmd("SADD", "town:" + townIdStr + ":cp", cp.Id).Err
        if err != nil {
            log.Fatal(err)
        }

        err = redisCli.Cmd("SADD", "bank:" + bankIdStr + ":cp", cp.Id).Err
        if err != nil {
            log.Fatal(err)
        }

        currentCashpointIndex++

        if currentCashpointIndex % 500 == 0 {
            log.Printf("[%d/%d] Cashpoints processed\n", currentCashpointIndex, cashpointsCount)
        }
    }
    log.Printf("[%d/%d] Cashpoints processed\n", cashpointsCount, cashpointsCount)
}

func migrate(townsDb *sql.DB, cpDb *sql.DB, redisCli *redis.Client) {
    migrateTowns(townsDb, redisCli)
    migrateRegions(townsDb, redisCli)
    migrateCashpoints(cpDb, redisCli)
}

func main() {
    args := os.Args[1:]

    if len(args) == 0 {
        log.Fatal("Towns db file path is not specified")
    }

    if len(args) == 1 {
        log.Fatal("Cashpoints db file path is not specified")
    }

    if len(args) == 2 {
        log.Fatal("Redis database url is not specified")
    }

    townsDbPath := args[0]
    cashpointsDbPath := args[1]
    redisUrl := args[2]

    townsDb, err := sql.Open("sqlite3", townsDbPath)
    if err != nil {
        log.Fatal(err)
    }
    defer townsDb.Close()

    cashpointsDb, err := sql.Open("sqlite3", cashpointsDbPath)
    if err != nil {
        log.Fatal(err)
    }
    defer cashpointsDb.Close()

    redisCli, err := redis.Dial("tcp", redisUrl)
    if err != nil {
        log.Fatal(err)
    }
    defer redisCli.Close()

    migrate(townsDb, cashpointsDb, redisCli)
}
