-- Copyright (C) UPYUN, Inc.

local _M = {}

local match = require "modules.match"
local utils = require "modules.utils"

local null = utils.null
local set_req_header = ngx.req.set_header
local match_uri_args = match.match_uri_args

local marco = marco

local METADATA_LOC = "/internal/get_metadata"
local MP4_OFFSET_LOC   = "/internel/get_mp4_offset"
local FLV_OFFSET_LOC   = "/internel/get_flv_offset"


local function get_offset(drag_start, drag_end, slice_size, metadata_size, typ)
    local newuri = ngx.var.newuri
    local newargs = ngx.var.newargs
    local newhost = ngx.var.newhost

    if typ ~= "flv" then
        typ = "mp4"
    end

    if metadata_size >= marco.global.drag_max_metadata_size then
        ngx.log(ngx.ERR, "[drag] metadata size too large")
        return
    end

    local meta_res = ngx.location.capture(METADATA_LOC,
                                          { method = ngx.HTTP_GET,
                                            args = {
                                                slice_size = slice_size,
                                                metadata_size = metadata_size },
                                            vars = {
                                                newuri = newuri,
                                                newargs = newargs,
                                                newhost = newhost }})
    if not meta_res then
        ngx.log(ngx.WARN, "[drag] " .. typ .. " get meta failed")
        return
    end

    if not meta_res.truncated and
    (meta_res.status == 200 or meta_res.status == 206) then
        ngx.log(ngx.INFO, "[drag] " .. typ .. " get meta success, status = ",
                meta_res.status, ", length = ",
                meta_res.header["Content-Length"])

        local offset_loc = MP4_OFFSET_LOC
        if typ == "flv" then
            offset_loc = FLV_OFFSET_LOC
        end

        local compute_res = ngx.location.capture(offset_loc,
                                                 { method = ngx.HTTP_POST,
                                                   body = meta_res.body,
                                                   args = {
                                                       start = drag_start,
                                                       ["end"] = drag_end,
                                                   }})
        if not compute_res then
            ngx.log(ngx.WARN, "[drag] " .. typ .. " compute offset failed")
            return
        end

        if not compute_res.truncated and compute_res.status == 200 then
            ngx.log(ngx.INFO, "[drag] " .. typ ..
                        " compute offset success, status = ",
                    compute_res.status, ", length = ",
                    compute_res.header["Content-Length"],
                    ", range = ", compute_res.header["Content-Type"])

            return 200, compute_res.header["Content-Type"], compute_res.body
        else
            if compute_res.status == 299 then
                ngx.log(ngx.ERR, "[drag] " .. typ ..
                        " compute offset failed, status = ",
                    compute_res.status, ", truncated = ", compute_res.truncated,
                    ", expect_metadata_size = ", compute_res.header["Content-Type"])

                return 299, compute_res.header["Content-Type"]
            end

            ngx.log(ngx.WARN, "[drag] " .. typ ..
                        " compute offset failed, status = ",
                    compute_res.status, ", truncated = ", compute_res.truncated)

            return
        end
    else
        ngx.log(ngx.WARN, "[drag] " .. typ .. " get metadata failed, status = ",
                meta_res.status, " truncated = ", meta_res.truncated)
        return
    end
end


local function check_args(drag_start, drag_end)
    local drag_start = tonumber(drag_start)
    if not drag_start or drag_start <= 0 then
        drag_start = nil
    end

    local drag_end = tonumber(drag_end)
    if not drag_end or drag_end <= 0 then
        drag_end = nil
    end

    if drag_end and drag_start and drag_start >= drag_end then
        drag_end = nil
    end

    return drag_start, drag_end
end


_M.parse_options = function(options)
    if type(options) ~= "table" then
        return
    end

    local uri = ngx.var.uri
    local args = ngx.var.args

    local default_drag_pattern = {
        MP4 = {"/*.mp4"},
        FLV = {"/*.flv"},
    }

    local default_drag_type = {
        MP4 = "time",
        FLV = "byte",
    }

    local option
    for _, v in ipairs(options) do
        if null(v.format) or not default_drag_pattern[v.format] then
            v.format = "MP4"
        end

        if null(v.type) then
            v.type = default_drag_type[v.format]
        end

        local patterns = v.url_patterns
        if null(patterns) or #patterns == 0 then
            patterns = default_drag_pattern[v.format]
        end

        if type(patterns) == "table" then
            for _, pattern in ipairs(patterns) do
                if match_uri_args(uri, args, pattern) then
                    option = v
                    break
                end
            end
        end

        if option then
            break
        end
    end

    return option
end


_M.drag_mp4 = function(drag_type, drag_start, drag_end, slice_size)
    if drag_type ~= "time" then
        return
    end

    local drag_start, drag_end = check_args(drag_start, drag_end)
    if not drag_start and not drag_end then
        return
    end

    local metadata_size = marco.global.mp4_metadata_size
    local status, offset, metadata = get_offset(drag_start, drag_end, slice_size, metadata_size, "mp4")
    if not status then
        return
    end

    if status == 299 then
        metadata_size = tonumber(offset)
        if not metadata_size then
            return
        end

        status, offset, metadata = get_offset(drag_start, drag_end, slice_size, metadata_size, "mp4")
        if not status or not offset or not metadata then
            return
        end
    end

    ngx.ctx.drag_metadata = metadata
    ngx.var.slice_top_data = metadata

    local range_str = "bytes=" .. offset
    set_req_header("Range", range_str)
    ngx.var.newrange = range_str

    return offset
end


_M.drag_flv = function(drag_type, drag_start, drag_end, slice_size)
    if drag_type ~= "byte" then
        return
    end

    local drag_start, drag_end = check_args(drag_start, drag_end)
    if not drag_start and not drag_end then
        return
    end

    local metadata_size = marco.global.flv_metadata_size
    local status, offset, metadata = get_offset(drag_start, drag_end, slice_size, metadata_size, "flv")
    if not status then
        return
    end

    if status == 299 then
        metadata_size = tonumber(offset)
        if not metadata_size then
            return
        end

        status, offset, metadata = get_offset(drag_start, drag_end, slice_size, metadata_size, "flv")
        if not status or not offset or not metadata_size then
            return
        end
    end

    ngx.ctx.drag_metadata = metadata
    ngx.var.slice_top_data = metadata

    local range_str = "bytes=" .. offset
    set_req_header("Range", range_str)
    ngx.var.newrange = range_str

    return offset
end


return _M
