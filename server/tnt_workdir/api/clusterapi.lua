json = require('json')
local common = require('common')

local CP_ID = 1
local CP_COORD = 2

local CLUSTER_ID = 1
local CLUSTER_COORD = 2
local CLUSTER_MEMBERS = 3
local CLUSTER_SIZE = 4

local TOWN_ID = 1
local TOWN_COORD = 2
local TOWN_CASHPOINTS_COUNT = 9

local CLUSTER_ZOOM_MIN = 10
local CLUSTER_ZOOM_MAX = 16

local CLUSTER_MAX_BANK_ID_FILTER = 16

function getNearbyClusters(reqJson, countLimit)
    local fund = "getNearbyClusters"
    local req = json.decode(reqJson)

    local err = validateRequest(req, func)
    if err then
        box.error(err)
        return nil
    end

    req.filter = req.filter or {}

    if #(req.filter.bank_id or {}) > CLUSTER_MAX_BANK_ID_FILTER then
        box.error(malformedRequest("Receive " .. #req.filter.bank_id .. " bank_id filter. But max filter amount " .. CLUSTER_MAX_BANK_ID_FILTER))
        return nil
    end

    if not req.zoom then
        box.error{ code = 400, reason = func .. ": missing required argument => req.zoom"}
        return nil
    end

    if req.zoom < CLUSTER_ZOOM_MIN then
        return _getNearbyTownClusters(req, countLimit)
    else
        return _getNearbyQuadClusters(req)
    end
end

function _getNearbyQuadClusters(req)
    local t = box.space.clusters.index[1]:select({ req.topLeft.longitude, req.topLeft.latitude,
                                                   req.bottomRight.longitude, req.bottomRight.latitude },
                                                 { iterator = "le" })
    local filtersList = _getFiltersList()

    local result = {}

    for _, tuple in pairs(t) do
        local clusterId = tuple[CLUSTER_ID]
        if clusterId:len() == req.zoom + 1 then
            local cluster = {
                id = clusterId,
                longitude = tuple[CLUSTER_COORD][1],
                latitude = tuple[CLUSTER_COORD][2],
                --size = tuple[CLUSTER_SIZE],
            }

            local matchingIdList = {}
            if next(req.filter) ~= nil then
                --cluster.size = 0
                cluster.longitude = 0.0
                cluster.latitude = 0.0

                --print(json.encode(tuple[CLUSTER_MEMBERS]))

                for _, cpId in pairs(tuple[CLUSTER_MEMBERS]) do
                    local cpTupleList = box.space.cashpoints.index[0]:select{ cpId }
                    if #cpTupleList > 0 then
                        local cpTuple = cpTupleList[1]
                        local matching = true
                        for _, filter in ipairs(filtersList) do
                            matching = filter(cpTuple, req.filter)
                            if not matching then
                                break
                            end
                        end
                        if matching then
                            matchingIdList[#matchingIdList + 1] = cpId
                            --cluster.size = cluster.size + 1
                            cluster.longitude = cluster.longitude + cpTuple[CP_COORD][1]
                            cluster.latitude = cluster.latitude + cpTuple[CP_COORD][2]
                        end
                    end
                end

                if #matchingIdList > 0 then
                    cluster.longitude = cluster.longitude / #matchingIdList
                    cluster.latitude = cluster.latitude / #matchingIdList
                end
            else
                for _, cpId in pairs(tuple[CLUSTER_MEMBERS]) do
                    matchingIdList[#matchingIdList + 1] = cpId
                end
            end

            cluster.size = #matchingIdList
            if cluster.size > 0 then
                if cluster.size == 1 then
                    result[#result + 1] = _getCashpointById(matchingIdList[1])
                else
                    result[#result + 1] = cluster
                end
            end
        end

--         local chain = createFilterChain(req.filter)
--         if chain:len() > 0 then
--
--         end
    end

    return json.encode(setmetatable(result, { __serialize = "seq" }))
end

function _getNearbyTownClusters(req, countLimit)
    local countLimit = countLimit or 32

    local t = box.space.towns.index[1]:select({ req.topLeft.longitude, req.topLeft.latitude,
                                                req.bottomRight.longitude, req.bottomRight.latitude },
                                              { iterator = "le" })

    local result = {} -- town cluster list

    for _, tuple in pairs(t) do
        local townId = tuple[TOWN_ID]
        result[#result + 1] = {
            id = townId,
            longitude = tuple[TOWN_COORD][1],
            latitude = tuple[TOWN_COORD][2],
            size = tuple[TOWN_CASHPOINTS_COUNT],
        }
    end

    table.sort(result, function(a, b) return a.size > b.size end)
    local deltaLon = math.abs(req.topLeft.longitude - req.bottomRight.longitude)
    local deltaLat = math.abs(req.topLeft.latitude - req.bottomRight.latitude)

    local minDist = math.min(deltaLon, deltaLat) * 0.2
    local minDistSqr = minDist * minDist

    local getDistSqr = function(a, b)
        local deltaLon = a.longitude - b.longitude
        local deltaLat = a.latitude - b.latitude
        return deltaLon * deltaLon + deltaLat * deltaLat
    end

    for i = 1, #result do
        if result[i].size ~= 0 then
            for j = #result, i + 1, -1 do
                if result[j].size ~= 0 then
                    local dist = getDistSqr(result[i], result[j])
                    if dist < minDist then
                        result[i].size = result[i].size + result[j].size
                        result[j].size = 0
                    end
                end
            end
        end
    end

    -- remove town clusters which has been consumed
    -- by bigger ones
    for i = #result, 1, -1 do
        if result[i].size == 0 then
            table.remove(result, i)
        end
    end

    while #result > countLimit do
        table.remove(result)
    end

    local filtersList = {
        matchingTypeFilter,
        matchingRubFilter,
        matchingUsdFilter,
        matchingEurFilter,
        matchingRoundTheClock,
        matchingWithoutWeekend,
        matchingFreeAccess,
        matchingApproved,
    }

    local countMatching = function(t)
        local size = 0

        for _, tuple in pairs(t) do
            local matching = true
            if tuple then
                for _, filter in ipairs(filtersList) do
                    matching = filter(tuple, req.filter)
                    if not matching then
                        break
                    end
                end
            else
                 matching = false
            end

            if matching then
                 size = size + 1
            end
        end

        return size
    end

    if req.filter.bank_id and #req.filter.bank_id > 0 then
        -- drop size cached value
        for i = 1, #result do
            result[i].size = 0
        end
        for _, bankId in ipairs(req.filter.bank_id) do
            for i = 1, #result do
                -- select by composite key: (town_id, bank_id)
                local t = box.space.cashpoints.index[2]:select{ result[i].id, bankId }

                -- count of matching cashpoints for this town
                result[i].size = result[i].size + countMatching(t)
            end
        end
    elseif next(req.filter) then-- no filter.bank_id but others filters
        for i = 1, #result do
            -- select only by first part of composite key: (town_id)
            local t = box.space.cashpoints.index[2]:select{ result[i].id }

            -- count of matching cashpoints for this town
            result[i].size = countMatching(t)
        end
    end

    -- remove town clusters which has been filtered out
    for i = #result, 1, -1 do
        if result[i].size == 0 then
            table.remove(result, i)
        end
    end

    return json.encode(setmetatable(result, { __serialize = "seq" }))
end
