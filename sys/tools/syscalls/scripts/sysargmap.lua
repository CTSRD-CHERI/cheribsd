#!/usr/libexec/flua
--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2024 SRI International
-- Copyright (c) 2024 Tyler Baxter <agge@FreeBSD.org>
-- Copyright (c) 2023 Warner Losh <imp@bsdimp.com>
-- Copyright (c) 2019 Kyle Evans <kevans@FreeBSD.org>
--

-- Setup to be a module, or ran as its own script.
local sysargmap = {}
local script = not pcall(debug.getlocal, 4, 1)	-- TRUE if script.
if script then
	-- Add library root to the package path.
	local path = arg[0]:gsub("/[^/]+.lua$", "")
	package.path = package.path .. ";" .. path .. "/../?.lua"
end

local FreeBSDSyscall = require("core.freebsd-syscall")
local generator = require("tools.generator")
local util = require("tools.util")

-- File has not been decided yet; config will decide file. Default defined as
-- null
sysargmap.file = "/dev/null"

function sysargmap.generate(tbl, config, fh)
	-- Grab the master system calls table.
	local s = tbl.syscalls

	local print_decl = function (s)
		return s:native() and not s.type.NODEF and not s.type.NOPROTO
	end

	-- Bind the generator to the parameter file.
	local gen = generator:new({}, fh)

	-- Write the generated preamble.
	gen:preamble("System call argument map.")

	gen:write(string.format([[
#ifndef %s
#define	%s

]], config.sysargmap_h, config.sysargmap_h))

	gen:write(string.format([[
static int %s[] = {
]], config.sysargmaskname))

	for _, v in pairs(s) do
		if print_decl(v) then
			gen:write(string.format("\t[%s%s] = (0x0",
			   config.syscallprefix, v.name, v.argstr_type))

			local i = 0
			for _, arg in ipairs(v.args) do
				if util.isPtrType(arg.type,
				    config.abi_intptr_t) then
					gen:write(string.format(" | 0x%x",
					    1 << i))
				end
				i = i + 1
			end

			gen:write("),\n")
		end
	end

	gen:write("};\n")
	-- End
	gen:write(string.format([[

#endif /* !%s */
]], config.sysargmap_h))
end

-- Entry of script:
if script then
	local config = require("config")

	if #arg < 1 or #arg > 2 then
		error("usage: " .. arg[0] .. " syscall.master")
	end

	local sysfile, configfile = arg[1], arg[2]

	config.merge(configfile)
	config.mergeCompat()
	config.mergeCapability()

	-- The parsed syscall table
	local tbl = FreeBSDSyscall:new{sysfile = sysfile, config = config}

	sysargmap.file = config.sysargmap -- change file here
	sysargmap.generate(tbl, config, sysargmap.file)
end

-- Return the module.
return sysargmap
