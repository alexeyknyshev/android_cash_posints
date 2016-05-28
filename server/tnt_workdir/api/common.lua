json = require('json')
local COL_CP_ID = 1
local COL_CP_COORD = 2
local COL_CP_TYPE = 3
local COL_CP_BANK_ID = 4
local COL_CP_TOWN_ID = 5
local COL_CP_ADDRESS = 6
local COL_CP_ADDRESS_COMMENT = 7
local COL_CP_METRO_NAME = 8
local COL_CP_FREE_ACCESS = 9
local COL_CP_MAIN_OFFICE = 10
local COL_CP_WITHOUT_WEEKEND = 11
local COL_CP_ROUND_THE_CLOCK = 12
local COL_CP_WORKS_AS_SHOP = 13
local COL_CP_SCHEDULE = 14
local COL_CP_TEL = 15
local COL_CP_ADDITIONAL = 16
local COL_CP_RUB = 17
local COL_CP_USD = 18
local COL_CP_EUR = 19
local COL_CP_CASH_IN = 20
local COL_CP_VERSION = 21
local COL_CP_TIMESTAMP = 22
local COL_CP_APPROVED = 23
local COL_CP_PATCH_COUNT = 24

local COL_TOWN_CP_COUNT = 9

local COL_CLUSTER_ID = 1
local COL_CLUSTER_COORD = 2
local COL_CLUSTER_MEMBERS = 3
local COL_CLUSTER_SIZE = 4

local COL_PATCH_ID = 1
local COL_PATCH_CP_ID = 2

local CLUSTER_ZOOM_MIN = 10
local CLUSTER_ZOOM_MAX = 16

function malformedRequest(err, func)
    if func then
        func = func .. ": "
    else
        func = ""
    end
    return { code = 400, reason =  func .. err }
end

local function _cashpointTupleToTable(t)
    local approved = false
    if t[COL_CP_APPROVED] ~= nil then
        approved = t[COL_CP_APPROVED]
    else
        approved = true
    end
    local ok, schedule = pcall(json.decode, t[COL_CP_SCHEDULE])
    if not ok then
        schedule = setmetatable({}, { __serialize = "map" })
    end

    local cpId = t[COL_CP_ID]
    local cp = {
        id = cpId,
        longitude = t[COL_CP_COORD][1],
        latitude = t[COL_CP_COORD][2],
        type = t[COL_CP_TYPE],
        bank_id = t[COL_CP_BANK_ID],
        town_id = t[COL_CP_TOWN_ID],
        address = t[COL_CP_ADDRESS],
        address_comment = t[COL_CP_ADDRESS_COMMENT],
        metro_name = t[COL_CP_METRO_NAME],
        free_access = t[COL_CP_FREE_ACCESS],
        main_office = t[COL_CP_MAIN_OFFICE],
        without_weekend = t[COL_CP_WITHOUT_WEEKEND],
        round_the_clock = t[COL_CP_ROUND_THE_CLOCK],
        works_as_shop = t[COL_CP_WORKS_AS_SHOP],
        schedule = schedule,
        tel = t[COL_CP_TEL],
        additional = t[COL_CP_ADDITIONAL],
        rub = t[COL_CP_RUB],
        usd = t[COL_CP_USD],
        eur = t[COL_CP_EUR],
        cash_in = t[COL_CP_CASH_IN],
        version = t[COL_CP_VERSION],
        timestamp = t[COL_CP_TIMESTAMP],
        approved = approved,
        patch_count = getCashpointPatchesCount(cpId)
    }

    return cp
end

local function _clusterTupleToTable(t)
    local cluster = {
        id = t[COL_CLUSTER_ID],
        longitude = t[COL_CLUSTER_COORD][1],
        latitude = t[COL_CLUSTER_COORD][2],
        members = t[COL_CLUSTER_MEMBERS],
        size = t[COL_CLUSTER_SIZE],
    }

    return cluster
end

function _getCashpointById(cpId)
    local t = box.space.cashpoints.index[0]:select(cpId)
    if #t == 0 then
        return nil
    end

    local tuple = t[1]

    return _cashpointTupleToTable(tuple)
end

function getCashpointById(cpId)
    local cp = _getCashpointById(cpId)
    if cp then
        return json.encode(cp)
    end

    return ""
end

-- TODO: set access control
function deleteCashpointById(cpId)
    local func = "deleteCashpointById"
    print(func)
    local tuple = box.space.cashpoints.index[0]:delete(cpId)
    if tuple then
        print("Found cashpoint by id: " .. tostring(cpId))
        local quadKey = getQuadKey(tuple[COL_CP_COORD][1], tuple[COL_CP_COORD][2])
        if quadKey:len() == 0 then
            return false
        end
        if not _deleteCashpointFromQuadTree(tuple[COL_CP_ID], quadKey) then
            -- TODO: log warning
            print("Cashpoint has been deleted but has not found in quadtree")
        end
        if tuple[COL_CP_APPROVED] == true then -- dec town cashpoint count only if cashpoint has been commited
            box.space.towns:update(tuple[COL_CP_TOWN_ID], {{ '-',  COL_TOWN_CP_COUNT, 1 }})
        end

        _deleteCashpointPatches(cpId)
        return true
    end
    print("Cannot find cashpoint by id: " .. tostring(cpId))
    return false
end

function _deleteCashpointPatchById(patchId)
    local votes = box.space.cashpoints_patches_votes.index[1]:select{ patchId }
    for _, vote in pairs(votes) do
        local voteId = vote[1]
        box.space.cashpoints_patches_votes:delete{ voteId }
        print("deleted vote " .. tostring(voteId) .. " for patch " .. tostring(patchId))
    end
    box.space.cashpoints_patches:delete{ patchId }
    print("deleted patch " .. tostring(patchId))
end

function _deleteCashpointPatches(cpId)
    local patches = box.space.cashpoints_patches.index[1]:select{ cpId }
    for _, patch in pairs(patches) do
        _deleteCashpointPatchById(patch[COL_PATCH_ID])
    end
    local tuple = box.space.cashpoints.index[0]:select{cpId}[1]
    if not tuple[COL_CP_APPROVED] then
        print("deleted cashpoint " .. tostring(cpId))
        box.space.cashpoints.index[0]:delete{cpId}
    end
end

function _insertCashpointIntoQuadTree(cp, quadKey)
    for zoom = CLUSTER_ZOOM_MIN, CLUSTER_ZOOM_MAX do
        local quadPrefix = quadKey:sub(1, zoom)
        _insertCashpointIntoQuadKey(cp, quadPrefix)
    end
end

function _deleteCashpointFromQuadTree(cpId, quadKey)
    local deleted = false
    for zoom = CLUSTER_ZOOM_MAX, CLUSTER_ZOOM_MIN, -1 do
        local quadPrefix = quadKey:sub(1, zoom)
        if not _deleteCashpointFromQuadKey(cpId, quadPrefix) then
            break
        end
        deleted = true
    end
    return deleted
end

-- Insert cashpoint exactly into passed quadKey
function _insertCashpointIntoQuadKey(cp, quadKey)
    local cluster = _getClusterById(quadKey)

    if cluster then -- cluster already exists
        cluster = _recalcClusterCoords(cluster)

        cluster.members[#cluster.members + 1] = cp.id
        cluster.size = cluster.size + 1

        cluster.longitude = (cluster.longitude + cp.longitude) / cluster.size
        cluster.latitude  = (cluster.latitude  + cp.latitude)  / cluster.size

        box.space.clusters:replace{
            quadKey,
            { cluster.longitude, cluster.latitude },
            cluster.members,
            cluster.size,
        }
    else -- no such cluster, need to create one
        box.space.clusters:insert{
            quadKey,
            { cp.longitude, cp.latitude },
            { cp.id },
            1,
        }
    end
end

-- Remove cashpoint exactly from passed quadKey
function _deleteCashpointFromQuadKey(cpId, quadKey)
    local cluster = _getClusterById(quadKey)

    local deleted = false
    if cluster then
        for j = 1, #cluster.members do
            if cluster.members[j] == cpId then
                table.remove(cluster.members, j)
                deleted = true
                break
            end
        end
    else -- no such cluster, assuming that deleting was successfull
        deleted = true
    end

    if deleted and cluster then
        cluster = _recalcClusterCoords(cluster)
        if cluster.size > 0 then
            cluster.longitude = cluster.longitude / cluster.size
            cluster.latitude  = cluster.latitude  / cluster.size

            box.space.clusters:replace{
                cluster.id,
                { cluster.longitude, cluster.latitude },
                cluster.members,
                cluster.size,
            }
        else -- delete empty cluster
            box.space.clusters:delete(cluster.id)
        end
    end

    return deleted
end

-- WARNING: This function does NOT avg coord
function _recalcClusterCoords(cluster)
    cluster.longitude = 0.0
    cluster.latitude  = 0.0
    cluster.size      = 0

    for _, member in pairs(cluster.members) do
        local cp = _getCashpointById(member)
        if cp then
            cluster.longitude = cluster.longitude + cp.longitude
            cluster.latitude  = cluster.latitude  + cp.latitude
            cluster.size      = cluster.size + 1
        end
    end

    return cluster
end

function _changeCashpointQuadKey(cp, oldQuadKey, newQuadKey)
    for zoom = CLUSTER_ZOOM_MIN, CLUSTER_ZOOM_MAX do
        local newQuadPrefix = newQuadKey:sub(1, zoom)
        local oldQuadPrefix = oldQuadKey:sub(1, zoom)
        if newQuadPrefix ~= oldQuadPrefix then
            _deleteCashpointFromQuadKey(cp, oldQuadPrefix)
            _insertCashpointIntoQuadKey(cp, newQuadPrefix)
        end
    end
end

function _getClusterById(clusterId)
    local t = box.space.clusters.index[0]:select(clusterId)
    if #t == 0 then
        return nil
    end

    local tuple = t[1]

    return _clusterTupleToTable(tuple)
end

function getClusterById(clusterId)
    local cluster = _getClusterById(clusterId)
    if cluster then
        return json.encode(cluster)
    end

    return ""
end

function getQuadKeyFromCoord(reqJson)
    local req = json.decode(reqJson)
    if req then
        local quadkey = getQuadKey(req.longitude, req.latitude, req.zoom)
        if quadkey:len() > 0 then
            return json.encode({ quadkey = quadkey })
        end
    end

    return ""
end

local function isValidCoordinate(longitude, latitude)
    if type(longitude) ~= 'number' or type(latitude) ~= 'number' then
        return false
    end

    if math.abs(latitude) > 90.0 or math.abs(longitude) > 180.0 then
        return false
    end

    return true
end

function getQuadKey(longitude, latitude, zoom)
    if not longitude or not latitude then
        return ''
    end

    local geoRectPart = function(minLon, maxLon, minLat, maxLat, lon, lat)
        local midLon = (minLon + maxLon) * 0.5
        local midLat = (minLat + maxLat) * 0.5

        local quad = ""
        if lat < midLat then
            maxLat = midLat
            if lon < midLon then
                maxLon = midLon
                quad = '0'
            else
                minLon = midLon
                quad = '1'
            end
        else
            minLat = midLat
            if lon < midLon then
                maxLon = midLon
                quad = '2'
            else
                minLon = midLon
                quad = '3'
            end
        end

        return minLon, maxLon, minLat, maxLat, quad
    end

    local minLon = -180.0
    local maxLon = 180.0

    local minLat = -90.0
    local maxLat = 90.0

    if not isValidCoordinate(longitude, latitude) then
        return ""
    end

    zoom = zoom or CLUSTER_ZOOM_MAX -- use maximum zoom by default
    zoom = math.floor(zoom)

    if zoom < CLUSTER_ZOOM_MIN or zoom > CLUSTER_ZOOM_MAX then
        return ""
    end

    local quadKey = ""
    for currentZoom = 1, zoom do
        local q = ""
        minLon, maxLon, minLat, maxLat, q = geoRectPart(minLon, maxLon, minLat, maxLat, longitude, latitude)
        quadKey = quadKey .. q
    end
    return quadKey
end

function getQuadTreeBranch(quadKey)
    local result = {}
    for zoom = CLUSTER_ZOOM_MIN, #quadKey do
        local quadPrefix = quadKey:sub(1, zoom)
        result[#result + 1] = _getClusterById(quadPrefix)
    end
    return json.encode(setmetatable(result, { __serialize = "seq" }))
end

function getSupportedFilters()
    return {
        type = 'string',
        free_access = 'boolean',
        main_office = 'boolean',
        without_weekend = 'boolean',
        round_the_clock = 'boolean',
        works_as_shop = 'boolean',
        rub = 'boolean',
        usd = 'boolean',
        eur = 'boolean',
        cash_in = 'boolean',
    }
end

function getSupportedFiltersOrder()
    return {
        "type",
        "free_access",
        "main_office",
        "without_weekend",
        "round_the_clock",
        "works_as_shop",
        "rub",
        "usd",
        "eur",
        "cash_in",
        "bank_id"
    }
end

function createFilterChain(filter)
    if next(filter) == nil then
        return ""
    end

    local func = "createFilterChain"

    local chain = ""
    if filter.bank_id then
        if type(filter.bank_id) ~= 'table' then
            return "", malformedRequest('filter.bank_id must be an array', func)
        end

        -- sort to order ids => prevent bankIdChain variations
        table.sort(filter.bank_id, function(a, b) return a < b end)

        -- remove duplicates
        local prevBankId = 0
        local i = 1
        while i <= #filter.bank_id do
            if filter.bank_id[i] == prevBankId then
                table.remove(filter.bank_id, i)
            else
                prevBankId = filter.bank_id[i]
                i = i + 1
            end
        end

        for _, bankId in ipairs(filter.bank_id) do
            if type(bankId) == 'number' then
                chain = ':' .. tostring(math.floor(bankId))
            else
                return "",  malformedRequest('filter.bank_id contains non-numerical value', func)
            end
        end

        if string.len(chain) > 0 then
            chain = ':bank' .. chain
        end
    end

    for i, field in ipairs(getSupportedFiltersOrder()) do
        if field ~= 'bank_id' and filter[field] ~= nil then
            chain = chain .. ':' .. field .. ':' .. tostring(filter[field])
        end
    end

    return chain
end

function matchingBankFilter(tuple, filter)
    if not filter.bank_id then
        return true
    end

    for _, id in ipairs(filter.bank_id) do
        if tuple[COL_CP_BANK_ID] == id then
            return true
        end
    end

    return false
end

function matchingTypeFilter(tuple, filter)
    if filter.type ~= nil then
        return tuple[COL_CP_TYPE] == filter.type
    end
    return true
end

function matchingFreeAccess(tuple, filter)
    if filter.free_access ~= nil then
        return tuple[COL_CP_FREE_ACCESS] == filter.free_access
    end
    return true
end

function matchingRubFilter(tuple, filter)
    if filter.rub ~= nil then
        return tuple[COL_CP_RUB] == filter.rub
    end
    return true
end

function matchingUsdFilter(tuple, filter)
    if filter.usd ~= nil then
        return tuple[COL_CP_USD] == filter.usd
    end
    return true
end

function matchingEurFilter(tuple, filter)
    if filter.eur ~= nil then
        return tuple[COL_CP_EUR] == filter.eur
    end
    return true
end

function deltaInside(from, to, delta, curTime)
    if from > to then
        to = to + 60 * 24
    end
    if (from - curTime) <= 0 and (to - delta - curTime) >= 0 then
        return true
    end
    return false
end

function getPrevDaySch(schedule, nameCurDay)
    local daysName = {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
    local invertDaysTable = {}
    for i, name in ipairs(daysName) do
        invertDaysTable[name] = i 
    end
    local prevDayNum = invertDaysTable[nameCurDay] - 1
    prevDayNum = prevDayNum ~= 0 and prevDayNum or 7
    return schedule[daysName[prevDayNum]]
end

function matchingTimeFilter(tuple, filter)
    if not filter.schedule then
        return true
    end

    local ok, schedule = pcall(json.decode, tuple[COL_CP_SCHEDULE])
    if not ok then
        return true
    end
    if not next(schedule) then 
        return true
    end
    local UTCPlus3 = 3
    local nameCurDay = os.date("%a", filter.schedule.time)
    nameCurDay = nameCurDay:lower()
    local curDayTimeInMin = math.floor(((filter.schedule.time + UTCPlus3 * 60 * 60) % (60 * 60 * 24)) / 60)
    local curDaySch = schedule[nameCurDay]
    local delta = filter.schedule.delta / 60

    if curDaySch == nil then 
        return false
    end

    if curDayTimeInMin < curDaySch.f then
        prevDaySch = getPrevDaySch(schedule, nameCurDay)
        if prevDaySch.f > prevDaySch.t then
            return deltaInside(0, prevDaySch.t, delta, curDayTimeInMin)
        else
            return false
        end
    end

    return deltaInside(curDaySch.f, curDaySch.t, delta, curDayTimeInMin)
end

function matchingRoundTheClock(tuple, filter)
    if filter.round_the_clock ~= nil then
        return tuple[COL_CP_ROUND_THE_CLOCK] == filter.round_the_clock
    end
    return true
end

function matchingWithoutWeekend(tuple, filter)
    if filter.without_weekend ~= nil then
        return tuple[COL_CP_WITHOUT_WEEKEND] == filter.without_weekend
    end
    return true
end

function matchingApproved(tuple, filter)
    if filter.approved == nil then
        return true
    end

    local approved = true
    if tuple[COL_CP_APPROVED] ~= nil then
        approved = tuple[COL_CP_APPROVED]
    end

    return approved == filter.approved
end

function validateRequest(req, func)
    if not req then
        return malformedRequest("empty request", func)
    end

    local missingReqired = "missing required request field"
    if not req.topLeft then
        return malformedRequest(missingReqired .. ": topLeft", func)
    end

    if not req.topLeft.longitude then
        return malformedRequest(missingReqired .. ": topLeft.longitude", func)
    end

    if not req.topLeft.latitude then
        return malformedRequest(missingReqired .. ": topLeft.latitude", func)
    end

    if not req.bottomRight then
        return malformedRequest(missingReqired .. ": bottomRight", func)
    end

    if not req.bottomRight.longitude then
        return malformedRequest(missingReqired .. ": bottomRight.longitude", func)
    end

    if not req.bottomRight.latitude then
        return malformedRequest(missingReqired .. ": bottomRight.latitude", func)
    end

    if req.filter.bank_id then
        for i, id in ipairs(req.filter.bank_id) do
            local idType = type(id)
            if idType ~= 'number' then
                return malformedRequest("invalid type of " .. tostring(i) " bank_id in filter.bank_id, " ..
                                        "expected 'number' but got '" .. idType .. "'")
            end
        end
    end

    local supportedFilters = getSupportedFilters()
    for expectedName, expectedType in pairs(supportedFilters) do
        if req.filter[expectedName] ~= nil then
            local filterType = type(req.filter[expectedName])
            if filterType ~= expectedType then
                return malformedRequest("invalid type of filter '" .. expectedName .. "', expected '" ..
                                        expectedType .. "' but got '" .. filterType .. "'")
            end
        end
    end

    return nil
end

local function isValidCashpointType(cpType)
    local avaliableTypes = { "atm", "office", "branch", "cash" }
    for _, v in ipairs(avaliableTypes) do
        if cpType == v then
            return true
        end
    end
    return false
end

local function validateCashpointFields(cp, checkRequired, func)
    local allowedFields = {
        id = { type = 'number', required = false },
        type = { type = 'string', required = true },
        bank_id = { type = 'number', required = true },
        town_id = { type = 'number', required = true },
        longitude = { type = 'number', required = true },
        latitude = { type = 'number', required = true },
        address = { type = 'string', required = false, default = "" },
        address_comment = { type = 'string', required = false, default = "" },
        metro_name = { type = 'string', required = false, default = "" },
        free_access = { type = 'boolean', required = true },
        main_office = { type = 'boolean', required = true },
        without_weekend = { type = 'boolean', required = true },
        round_the_clock = { type = 'boolean', required = true },
        works_as_shop = { type = 'boolean', required = true },
        schedule = { type = 'table', required = true },
        tel = { type = 'string', required = false, default = "" },
        additional = { type = 'string', required = false, default = "" },
        rub = { type = 'boolean', required = true },
        usd = { type = 'boolean', required = true },
        eur = { type = 'boolean', required = true },
        cash_in = { type = 'boolean', required = true },
        version = { type = 'number', required = false },
        timestamp = { type = 'number', required = false },
    }

    if checkRequired then
        for k, v in pairs(allowedFields) do
            if cp[k] == nil then
                if v.required then
                    return malformedRequest("missing required cashpoint field '" .. tostring(k) .. "'")
                else
                    cp[k] = v.default
                end
            else
                local cpKType = type(cp[k])
                if cpKType ~= v.type then
                    return malformedRequest("wrong type of cashpoint field '" .. tostring(k) .. "'. " ..
                                            "Expected '" .. v.type .. "' but got '" .. cpKType .. "'", func)
                end
            end
        end
    end

    for k, v in pairs(cp) do
        if allowedFields[k] == nil then -- unknown field
            return malformedRequest("unknown cashpoint field '" .. tostring(k) .. "'", func)
        end
        local fieldType = type(v)
        local expectedType = allowedFields[k].type
        if fieldType ~= expectedType then -- type missmatch
            return malformedRequest("wrong type of cashpoint field '" .. tostring(k) .. "'. Expected '" .. expectedType .. "' but got '" .. fieldType .. "'", func)
        end
    end
end

function validateCashpoint(cp, checkRequired, func)
    local err = validateCashpointFields(cp, checkRequired, func)
    if err then
        return err
    end

    if cp.bank_id then
        local t = box.space.banks.index[0]:select{ cp.bank_id }
        if #t == 0 then
            return malformedRequest("no such bank_id: " .. tostring(cp.bank_id), func)
        end
    end

    if cp.town_id then
        local t = box.space.towns.index[0]:select{ cp.town_id }
        if #t == 0 then
            return malformedRequest("no such town_id: " .. tostring(cp.town_id), func)
        end
    end

    if cp.type then
        if not isValidCashpointType(cp.type) then
            return malformedRequest("wrong cashpoint type '" .. tostring(cp.type) .. "'", func)
        end
    end

    if cp.longitude and cp.latitude then
        if not isValidCoordinate(cp.longitude, cp.latitude) then
            return malformedRequest("invalid cashpoint coordinate (" .. tostring(cp.longitude) .. ", " .. tostring(cp.latitude) .. ")", func)
        end
    end

    return nil
end
