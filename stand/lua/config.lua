--
-- SPDX-License-Identifier: BSD-2-Clause-FreeBSD
--
-- Copyright (c) 2015 Pedro Souza <pedrosouza@freebsd.org>
-- Copyright (C) 2018 Kyle Evans <kevans@FreeBSD.org>
-- All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
--
-- THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
-- ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
-- FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
-- OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
-- HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
-- LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
-- OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-- SUCH DAMAGE.
--
-- $FreeBSD$
--

local hook = require("hook")

local config = {}
local modules = {}
local carousel_choices = {}

local MSG_FAILEXEC = "Failed to exec '%s'"
local MSG_FAILSETENV = "Failed to '%s' with value: %s"
local MSG_FAILOPENCFG = "Failed to open config: '%s'"
local MSG_FAILREADCFG = "Failed to read config: '%s'"
local MSG_FAILPARSECFG = "Failed to parse config: '%s'"
local MSG_FAILEXBEF = "Failed to execute '%s' before loading '%s'"
local MSG_FAILEXMOD = "Failed to execute '%s'"
local MSG_FAILEXAF = "Failed to execute '%s' after loading '%s'"
local MSG_MALFORMED = "Malformed line (%d):\n\t'%s'"
local MSG_DEFAULTKERNFAIL = "No kernel set, failed to load from module_path"
local MSG_KERNFAIL = "Failed to load kernel '%s'"
local MSG_KERNLOADING = "Loading kernel..."
local MSG_MODLOADING = "Loading configured modules..."
local MSG_MODLOADFAIL = "Could not load one or more modules!"

local pattern_table = {
	{
		str = "^%s*(#.*)",
		process = function(_, _)  end,
	},
	--  module_load="value"
	{
		str = "^%s*([%w_]+)_load%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			if modules[k] == nil then
				modules[k] = {}
			end
			modules[k].load = v:upper()
		end,
	},
	--  module_name="value"
	{
		str = "^%s*([%w_]+)_name%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			config.setKey(k, "name", v)
		end,
	},
	--  module_type="value"
	{
		str = "^%s*([%w_]+)_type%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			config.setKey(k, "type", v)
		end,
	},
	--  module_flags="value"
	{
		str = "^%s*([%w_]+)_flags%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			config.setKey(k, "flags", v)
		end,
	},
	--  module_before="value"
	{
		str = "^%s*([%w_]+)_before%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			config.setKey(k, "before", v)
		end,
	},
	--  module_after="value"
	{
		str = "^%s*([%w_]+)_after%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			config.setKey(k, "after", v)
		end,
	},
	--  module_error="value"
	{
		str = "^%s*([%w_]+)_error%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			config.setKey(k, "error", v)
		end,
	},
	--  exec="command"
	{
		str = "^%s*exec%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, _)
			if cli_execute_unparsed(k) ~= 0 then
				print(MSG_FAILEXEC:format(k))
			end
		end,
	},
	--  env_var="value"
	{
		str = "^%s*([%w%p]+)%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			if config.setenv(k, v) ~= 0 then
				print(MSG_FAILSETENV:format(k, v))
			end
		end,
	},
	--  env_var=num
	{
		str = "^%s*([%w%p]+)%s*=%s*(%d+)%s*(.*)",
		process = function(k, v)
			if config.setenv(k, v) ~= 0 then
				print(MSG_FAILSETENV:format(k, tostring(v)))
			end
		end,
	},
}

local function readFile(name, silent)
	local f = io.open(name)
	if f == nil then
		if not silent then
			print(MSG_FAILOPENCFG:format(name))
		end
		return nil
	end

	local text, _ = io.read(f)
	-- We might have read in the whole file, this won't be needed any more.
	io.close(f)

	if text == nil then
		if not silent then
			print(MSG_FAILREADCFG:format(name))
		end
		return nil
	end
	return text
end

local function checkNextboot()
	local nextboot_file = loader.getenv("nextboot_file")
	if nextboot_file == nil then
		return
	end

	local text = readFile(nextboot_file, true)
	if text == nil then
		return
	end

	if text:match("^nextboot_enable=\"NO\"") ~= nil then
		-- We're done; nextboot is not enabled
		return
	end

	if not config.parse(text) then
		print(MSG_FAILPARSECFG:format(nextboot_file))
	end

	-- Attempt to rewrite the first line and only the first line of the
	-- nextboot_file. We overwrite it with nextboot_enable="NO", then
	-- check for that on load.
	-- It's worth noting that this won't work on every filesystem, so we
	-- won't do anything notable if we have any errors in this process.
	local nfile = io.open(nextboot_file, 'w')
	if nfile ~= nil then
		-- We need the trailing space here to account for the extra
		-- character taken up by the string nextboot_enable="YES"
		-- Or new end quotation mark lands on the S, and we want to
		-- rewrite the entirety of the first line.
		io.write(nfile, "nextboot_enable=\"NO\" ")
		io.close(nfile)
	end
end

-- Module exports
-- Which variables we changed
config.env_changed = {}
-- Values to restore env to (nil to unset)
config.env_restore = {}
config.verbose = false

-- The first item in every carousel is always the default item.
function config.getCarouselIndex(id)
	local val = carousel_choices[id]
	if val == nil then
		return 1
	end
	return val
end

function config.setCarouselIndex(id, idx)
	carousel_choices[id] = idx
end

function config.restoreEnv()
	-- Examine changed environment variables
	for k, v in pairs(config.env_changed) do
		local restore_value = config.env_restore[k]
		if restore_value == nil then
			-- This one doesn't need restored for some reason
			goto continue
		end
		local current_value = loader.getenv(k)
		if current_value ~= v then
			-- This was overwritten by some action taken on the menu
			-- most likely; we'll leave it be.
			goto continue
		end
		restore_value = restore_value.value
		if restore_value ~= nil then
			loader.setenv(k, restore_value)
		else
			loader.unsetenv(k)
		end
		::continue::
	end

	config.env_changed = {}
	config.env_restore = {}
end

function config.setenv(key, value)
	-- Track the original value for this if we haven't already
	if config.env_restore[key] == nil then
		config.env_restore[key] = {value = loader.getenv(key)}
	end

	config.env_changed[key] = value

	return loader.setenv(key, value)
end

-- name here is one of 'name', 'type', flags', 'before', 'after', or 'error.'
-- These are set from lines in loader.conf(5): ${key}_${name}="${value}" where
-- ${key} is a module name.
function config.setKey(key, name, value)
	if modules[key] == nil then
		modules[key] = {}
	end
	modules[key][name] = value
end

function config.isValidComment(line)
	if line ~= nil then
		local s = line:match("^%s*#.*")
		if s == nil then
			s = line:match("^%s*$")
		end
		if s == nil then
			return false
		end
	end
	return true
end

function config.loadmod(mod, silent)
	local status = true
	local pstatus
	for k, v in pairs(mod) do
		if v.load == "YES" then
			local str = "load "
			if v.flags ~= nil then
				str = str .. v.flags .. " "
			end
			if v.type ~= nil then
				str = str .. "-t " .. v.type .. " "
			end
			if v.name ~= nil then
				str = str .. v.name
			else
				str = str .. k
			end
			if v.before ~= nil then
				pstatus = cli_execute_unparsed(v.before) == 0
				if not pstatus and not silent then
					print(MSG_FAILEXBEF:format(v.before, k))
				end
				status = status and pstatus
			end

			if cli_execute_unparsed(str) ~= 0 then
				if not silent then
					print(MSG_FAILEXMOD:format(str))
				end
				if v.error ~= nil then
					cli_execute_unparsed(v.error)
				end
				status = false
			end

			if v.after ~= nil then
				pstatus = cli_execute_unparsed(v.after) == 0
				if not pstatus and not silent then
					print(MSG_FAILEXAF:format(v.after, k))
				end
				status = status and pstatus
			end

--		else
--			if not silent then
--				print("Skipping module '". . k .. "'")
--			end
		end
	end

	return status
end

-- Returns true if we processed the file successfully, false if we did not.
-- If 'silent' is true, being unable to read the file is not considered a
-- failure.
function config.processFile(name, silent)
	if silent == nil then
		silent = false
	end

	local text = readFile(name, silent)
	if text == nil then
		return silent
	end

	return config.parse(text)
end

-- silent runs will not return false if we fail to open the file
function config.parse(text)
	local n = 1
	local status = true

	for line in text:gmatch("([^\n]+)") do
		if line:match("^%s*$") == nil then
			local found = false

			for _, val in ipairs(pattern_table) do
				local k, v, c = line:match(val.str)
				if k ~= nil then
					found = true

					if config.isValidComment(c) then
						val.process(k, v)
					else
						print(MSG_MALFORMED:format(n,
						    line))
						status = false
					end

					break
				end
			end

			if not found then
				print(MSG_MALFORMED:format(n, line))
				status = false
			end
		end
		n = n + 1
	end

	return status
end

-- other_kernel is optionally the name of a kernel to load, if not the default
-- or autoloaded default from the module_path
function config.loadKernel(other_kernel)
	local flags = loader.getenv("kernel_options") or ""
	local kernel = other_kernel or loader.getenv("kernel")

	local function tryLoad(names)
		for name in names:gmatch("([^;]+)%s*;?") do
			local r = loader.perform("load " .. flags ..
			    " " .. name)
			if r == 0 then
				return name
			end
		end
		return nil
	end

	local function loadBootfile()
		local bootfile = loader.getenv("bootfile")

		-- append default kernel name
		if bootfile == nil then
			bootfile = "kernel"
		else
			bootfile = bootfile .. ";kernel"
		end

		return tryLoad(bootfile)
	end

	-- kernel not set, try load from default module_path
	if kernel == nil then
		local res = loadBootfile()

		if res ~= nil then
			-- Default kernel is loaded
			config.kernel_loaded = nil
			return true
		else
			print(MSG_DEFAULTKERNFAIL)
			return false
		end
	else
		-- Use our cached module_path, so we don't end up with multiple
		-- automatically added kernel paths to our final module_path
		local module_path = config.module_path
		local res

		if other_kernel ~= nil then
			kernel = other_kernel
		end
		-- first try load kernel with module_path = /boot/${kernel}
		-- then try load with module_path=${kernel}
		local paths = {"/boot/" .. kernel, kernel}

		for _, v in pairs(paths) do
			loader.setenv("module_path", v)
			res = loadBootfile()

			-- succeeded, add path to module_path
			if res ~= nil then
				config.kernel_loaded = kernel
				if module_path ~= nil then
					loader.setenv("module_path", v .. ";" ..
					    module_path)
				end
				return true
			end
		end

		-- failed to load with ${kernel} as a directory
		-- try as a file
		res = tryLoad(kernel)
		if res ~= nil then
			config.kernel_loaded = kernel
			return true
		else
			print(MSG_KERNFAIL:format(kernel))
			return false
		end
	end
end

function config.selectKernel(kernel)
	config.kernel_selected = kernel
end

function config.load(file)
	if not file then
		file = "/boot/defaults/loader.conf"
	end

	if not config.processFile(file) then
		print(MSG_FAILPARSECFG:format(file))
	end

	local f = loader.getenv("loader_conf_files")
	if f ~= nil then
		for name in f:gmatch("([%w%p]+)%s*") do
			-- These may or may not exist, and that's ok. Do a
			-- silent parse so that we complain on parse errors but
			-- not for them simply not existing.
			if not config.processFile(name, true) then
				print(MSG_FAILPARSECFG:format(name))
			end
		end
	end

	checkNextboot()

	-- Cache the provided module_path at load time for later use
	config.module_path = loader.getenv("module_path")
	local verbose = loader.getenv("verbose_loading")
	if verbose == nil then
		verbose = "no"
	end
	config.verbose = verbose:lower() == "yes"
end

-- Reload configuration
function config.reload(file)
	modules = {}
	config.restoreEnv()
	config.load(file)
	hook.runAll("config.reloaded")
end

function config.loadelf()
	local kernel = config.kernel_selected or config.kernel_loaded
	local loaded

	print(MSG_KERNLOADING)
	loaded = config.loadKernel(kernel)

	if not loaded then
		return
	end

	print(MSG_MODLOADING)
	if not config.loadmod(modules, not config.verbose) then
		print(MSG_MODLOADFAIL)
	end
end

hook.registerType("config.reloaded")
return config
