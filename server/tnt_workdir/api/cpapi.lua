json = require('json')
local fiber = require('fiber')
local common = require('common')

local COL_CP_ID = 1
--local COL_CP_COORD = 2
--local COL_TYPE = 3
--local COL_BANK_ID = 4
--local COL_TOWN_ID = 5
--local COL_ADDRESS = 6
--local COL_ADDRESS_COMMENT = 7
--local COL_METRO_NAME = 8
--local COL_FREE_ACCESS = 9
--local COL_MAIN_OFFICE = 10
--local COL_WITHOUT_WEEKEND = 11
--local COL_ROUND_THE_CLOCK = 12
--local COL_WORKS_AS_SHOP = 13
--local COL_SCHEDULE = 14
--local COL_TEL = 15
--local COL_ADDITIONAL = 16
--local COL_CP_CURRENCY = 17

local COL_CP_APPROVED = 21
local COL_CP_CREATOR = 22

local COL_TOWN_CP_COUNT = 9

local COL_CP_PATCH_ID = 1
local COL_CP_PATCH_CASHPOINT_ID = 2
local COL_CP_PATCH_CASHPOINT_USER_ID = 3
local COL_CP_PATCH_DATA = 4
--local COL_CP_PATCH_TIMESTAMP = 5

local COL_CP_PATCH_VOTE_ID = 1
local COL_CP_PATCH_VOTE_PATCH_ID = 2
local COL_CP_PATCH_VOTE_USER_ID = 3
local COL_CP_PATCH_VOTE_DATA = 4
local COL_CP_PATCH_VOTE_TIMESTAMP = 5

local PATCH_APPROVE_VOTES = 5

local MAX_CASHPOINTS_BATCH_SIZE = 1024
local MAX_COORD_DELTA = 0.02
local CP_MAX_BANK_ID_FILTER = 16

local INT32_MAX = 2147483647

function getCashpointsBatch(reqJson)
    local func = "getCashpointsBatch"
    local req = json.decode(reqJson)
    if not req or not req.cashpoints then
        box.error(malformedRequest("malformed request json", func))
        return nil
    end

    local result = {}
    for _, cpId in pairs(req.cashpoints) do
        local cp = _getCashpointById(cpId)
        if cp then
            result[#result + 1] = cp
        end
        if #result == MAX_CASHPOINTS_BATCH_SIZE then
            break
        end
    end

    return json.encode(setmetatable(result, { __serialize = "seq" }))
end

function getCashpointsStateBatch(reqJson)
    local func = "getCashpointsStateBatch"
    local req = json.decode(reqJson)
    if not req or not req.cashpoints then
        box.error(malformedRequest("malformed request json", func))
        return nil
    end

    local result = {}
    for _, cpId in ipairs(req.cashpoints) do
        result[#result + 1] = { id = cpId }
    end

    --[[
      result element:
      {
         id: %id%
         working: true / false -- based on schedule
      }
    ]]--

    return json.encode(setmetatable(result, { __serialize = "seq" }))
end

function getNearbyCashpoints(reqJson)
    local func = "getNearbyCashpoints"
    local req = json.decode(reqJson)

    local err = validateRequest(req, func)
    if err then
        box.error(err)
        return nil
    end

    req.filter = req.filter or {}

    if #(req.filter.bank_id or {}) > CP_MAX_BANK_ID_FILTER then
        box.error(malformedRequest("Receive " .. #req.filter.bank_id .. " bank_id filter. But max filter amount " .. CP_MAX_BANK_ID_FILTER))
        return nil
    end

    local t = box.space.cashpoints.index[1]:select({ req.topLeft.longitude, req.topLeft.latitude,
                                                     req.bottomRight.longitude, req.bottomRight.latitude },
                                                   { iterator = "le" })

    local tooBigRegion = "too big region size in request"
    if math.abs(req.topLeft.longitude - req.bottomRight.longitude) > MAX_COORD_DELTA then
        box.error(malformedRequest(tooBigRegion .. ": longitude", func))
        return nil
    end

    if math.abs(req.topLeft.latitude - req.bottomRight.latitude) > MAX_COORD_DELTA then
        box.error(malformedRequest(tooBigRegion .. ": latitude", func))
        return nil
    end



    local filtersList = _getFiltersList()

    local result = {}

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
            result[#result + 1] = tuple[COL_CP_ID]
        end
    end

    return json.encode(setmetatable(result, { __serialize = "seq" }))
end

local function updateOldCp(old, new)
    local dataChanged = false
    for k, v in pairs(new) do
        if old[k] ~= nil and old[k] ~= v then
            old[k] = v
            dataChanged = true
        end
    end
    return old, dataChanged
end

-- patch table contains 1+ field except id
local function isCashpointPatchTable(cp)
    for k, _ in pairs(cp) do
        if k ~= 'id' then
            return true
        end
    end
    return false
end

-- return id of created / updated cashpoint if success, 0 otherwise
function cashpointCommit(reqJson, userId)
    local func = "cashpointCommit"
    local timestamp = fiber.time64()

    print(func)

    local cp = json.decode(reqJson)

    if cp.id then -- editing existing cashpoint
        local err = validateCashpoint(cp, false, func)
        if err then
            box.error(err)
            return 0
        end

        local oldCp = _getCashpointById(cp.id)
        if not oldCp then
            box.error(malformedRequest("attempt to edit non existing cashpoint with id: " .. tostring(cp.id)), func)
            return 0
        end

        if not isCashpointPatchTable(cp) then -- req is not patch, it is mark of new cashpoint
            box.space.cashpoints:update(cp.id, {{ "=", COL_CP_APPROVED, true }})
            box.space.towns:update(oldCp.town_id, {{ '+', COL_TOWN_CP_COUNT, 1 }})
            return cp.id
        end

        if cp.longitude and cp.latitude then -- coordinates changed
            local oldQuadKey = getQuadKey(oldCp.longitude, oldCp.latitude)
            local newQuadKey = getQuadKey(cp.longitude, cp.latitude)

            if newQuadKey:len() == 0 then
                box.error(malformedRequest("invalid coordinates of cashpoint: (" .. tostring(cp.longitude) .. ", " .. tostring(cp.latitude) .. ")"), func)
                return 0
            end

            if oldQuadKey ~= newQuadKey then -- quadkey changed
                _changeCashpointQuadKey(cp, oldQuadKey, newQuadKey)
            end
        end

        if cp.town_id ~= oldCp.town_id then -- update towns' cp count
            box.space.towns:update(oldCp.town_id, {{ '-',  COL_TOWN_CP_COUNT, 1 }})
            box.space.towns:update(cp.town_id, {{ '+', COL_TOWN_CP_COUNT, 1 }})
        end

        local updated = false
        cp, updated = updateOldCp(oldCp, cp)
        if not updated then
            return 0
        end
        cp.version = (cp.version or 0) + 1
        local approved = true
        box.space.cashpoints:replace{
            cp.id, { cp.longitude, cp.latitude }, cp.type, cp.bank_id, cp.town_id,
            cp.address, cp.address_comment, cp.metro_name, cp.free_access,
            cp.main_office, cp.without_weekend, cp.round_the_clock,
            cp.works_as_shop, cp.schedule, cp.tel, cp.additional, cp.currency, cp.cash_in, cp.version, timestamp, approved, cp.creator
        }

        return cp.id
    else -- creating new cashpoint
        print(func .. ": creating new cashpoint")
        local err = validateCashpoint(cp, true, func)
        if err then
            print(func .. ": validation failed => " .. err.reason)
            box.error(err)
            return 0
        end

        local quadKey = getQuadKey(cp.longitude, cp.latitude)
        if quadKey:len() == 0 then
            print(func .. ": generation quadkey failed")
            box.error(malformedRequest("invalid coordinates of cashpoint: (" .. tostring(cp.longitude) .. ", " .. tostring(cp.latitude) .. ")"), func)
            return 0
        end

        print(func .. ": got quadKey for new cashpoint: " .. quadKey)
        local version = 0
        local approved = false
        local tuple = box.space.cashpoints:auto_increment{
            { cp.longitude, cp.latitude }, cp.type, cp.bank_id, cp.town_id, cp.address, cp.address_comment,
            cp.metro_name, cp.free_access, cp.main_office, cp.without_weekend, cp.round_the_clock,
            cp.works_as_shop, cp.schedule, cp.tel, cp.additional, cp.currency, cp.cash_in, version, timestamp, approved, userId
        }
        cp.id = tuple[COL_CP_ID]

        _insertCashpointIntoQuadTree(cp, quadKey)

        --box.space.towns:update(cp.town_id, {{ '+', COL_TOWN_CP_COUNT, 1 }})
        local patch = { id = cp.id }
        local patchTuple = box.space.cashpoints_patches:auto_increment{ cp.id, userId, json.encode(patch), timestamp } -- patch is unique (due to unique cp.id)
        print(func .. ": created patch for cashpoint: " .. tostring(patchTuple[1]))
        return cp.id
    end
end

-- return id of created / pached cashpoint if success, 0 otherwise
function cashpointProposePatch(reqJson)
    local func = "cashpointProposePatch"
    local timestamp = fiber.time64()

    print(func)

    local req = json.decode(reqJson)

    local userId = req.user_id
    if not userId then
        box.error(malformedRequest("missing required field user_id in request", func))
        return 0
    end
    -- TODO: check session exists

    local cp = req.data
    if not cp then
        box.error(malformedRequest("missing required field data in request", func))
        return 0
    end

    if cp.id then -- editing existing cashpoint
        local err = validateCashpoint(cp, false, func)
        if err then
            return 0
        end

        local cpId = cp.id
        cp.id = nil -- don't save cashpoint id in patch

        local oldCp = _getCashpointById(cp.id)
        if not oldCp then
            return 0
        end

        local updatedCp, updated = updateOldCp(oldCp, cp)
        if not updated then
            return 0
        end

        -- TODO: transaction here?
        local t = box.space.cashpoints_patches.index[1]:select{ cpId }

        reqJson = json.encode(cp)
        for _, tuple in pairs(t) do
            if reqJson == tuple[COL_CP_PATCH_DATA] then -- same patch already exists
                return 0
            end
        end

        box.space.cashpoints_patches:auto_increment{ cpId, userId, reqJson, timestamp }
        return cpId
    else -- creating new cashpoint
        print(func .. ": creating new cashpoint")
        local err = validateCashpoint(cp, true, func)
        if err then
            print(func .. ": validation failed => " .. err.reason)
            return 0
        end

        box.begin()
        local id = cashpointCommit(json.encode(cp), userId)
        if id > 0 then
            box.commit()
        else
            box.rollback()
        end

        return id
    end
end

function getCashpointPatchesCount(cpId)
    if not cpId then
        return nil
    end

    return #box.space.cashpoints_patches.index[1]:select{ cpId }
end

function getCashpointPatches(cpId)
    if not cpId then
        return nil
    end

    local t = box.space.cashpoints_patches.index[1]:select{ cpId }

    local result = {}
    for _, tuple in pairs(t) do
        local patchId = tuple[COL_CP_PATCH_ID]
        local cpPatchJson = tuple[COL_CP_PATCH_DATA]
        local cp = json.decode(cpPatchJson)
        if cp then
            result[patchId] = cp
        end
    end

    return json.encode(setmetatable(result, { __serialize = "map" }))
end

function getCashpointPatchByPatchId(id)
    if not id then
        return nil
    end

    return box.space.cashpoints_patches.index[0]:select{ id }[1]
end

function _getCashpointPatchVotes(patchId)
    if not patchId then
        return nil
    end

    local t = box.space.cashpoints_patches_votes.index[1]:select{ patchId }

    local result = {}
    for _, tuple in pairs(t) do
        local patchVote = {
            user_id = tuple[COL_CP_PATCH_VOTE_USER_ID],
            score = tuple[COL_CP_PATCH_VOTE_DATA],
            timestamp = tuple[COL_CP_PATCH_VOTE_TIMESTAMP],
        }
        result[#result + 1] = patchVote
    end
    return result
end

function getCashpointPatchVotes(patchId)
    local result = _getCashpointPatchVotes(patchId)
    if result then
        return json.encode(setmetatable(result, { __serialize = "seq" }))
    end
end

local function validateVote(userId, score, func)
    if not userId then
        return malformedRequest("missing user_id for vote", func)
    end
    -- TODO: vote user_id validation

    if not score then
        return malformedRequest("missing vote score", func)
    end

    if math.abs(score) ~= 1 then
        return malformedRequest("wrong vote score", func)
    end
end

local function isCashpointPatchApproved(patchId)
    local votes = _getCashpointPatchVotes(patchId)
    if votes then
        local score = 0
        for _, vote in ipairs(votes) do
            score = score + vote.score
        end
        return score >= PATCH_APPROVE_VOTES
    end
    return false
end

-- vote struct:
--    patch_id
--    user_id
--    score
function cashpointVotePatch(reqJson)
    local func = "cashpointVotePatch"
    local vote = json.decode(reqJson)
    if type(vote.patch_id) ~= 'number' then
        box.error(malformedRequest("missing patch id for vote", func))
        return false
    end
    local t = box.space.cashpoints_patches.index[0]:select{ vote.patch_id }
    if #t == 0 then
        box.error(malformedRequest("no such patch id for vote", func))
        return false
    end
    local patchTuple = t[1]

    local err = validateVote(vote.user_id, vote.score)
    if err then
        box.error(err)
        return false
    end
    box.begin()
    local ok, err = pcall(box.space.cashpoints_patches_votes.auto_increment, box.space.cashpoints_patches_votes, {vote.patch_id, vote.user_id, vote.score})
    if not ok then
        print(func..": "..err)
        box.rollback()
        return false
    end

    if isCashpointPatchApproved(vote.patch_id) then
        if cashpointCommit(patchTuple[COL_CP_PATCH_DATA], vote.user_id) == 0 then
            box.rollback()
            box.error{ code = 400, reason = "cannot commit approved cashpoint patch" }
            return false
        end
        -- TODO: deleting and archiving patches
        --box.space.cashpoints_patches_votes:delete{ vote.patch_id }
    end
    box.commit()

    return true
end
