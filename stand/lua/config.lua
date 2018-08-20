--
-- Copyright (c) 2015 Pedro Souza <pedrosouza@freebsd.org>
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

local config = {};

local modules = {};

function config.setKey(k, n, v)
	if modules[k] == nil then
		modules[k] = {};
	end
	modules[k][n] = v;
end

local pattern_table = {
	[1] = {
		str = "^%s*(#.*)",
		process = function(k, v)  end
	},
	--  module_load="value"
	[2] = {
		str = "^%s*([%w_]+)_load%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			if modules[k] == nil then
				modules[k] = {};
			end
			modules[k].load = string.upper(v);
		end
	},
	--  module_name="value"
	[3] = {
		str = "^%s*([%w_]+)_name%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			config.setKey(k, "name", v);
		end
	},
	--  module_type="value"
	[4] = {
		str = "^%s*([%w_]+)_type%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			config.setKey(k, "type", v);
		end
	},
	--  module_flags="value"
	[5] = {
		str = "^%s*([%w_]+)_flags%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			config.setKey(k, "flags", v);
		end
	},
	--  module_before="value"
	[6] = {
		str = "^%s*([%w_]+)_before%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			config.setKey(k, "before", v);
		end
	},
	--  module_after="value"
	[7] = {
		str = "^%s*([%w_]+)_after%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			config.setKey(k, "after", v);
		end
	},
	--  module_error="value"
	[8] = {
		str = "^%s*([%w_]+)_error%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			config.setKey(k, "error", v);
		end
	},
	--  exec="command"
	[9] = {
		str = "^%s*exec%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			if loader.perform(k) ~= 0 then
				print("Failed to exec '"..k.."'");
			end
		end
	},
	--  env_var="value"
	[10] = {
		str = "^%s*([%w%p]+)%s*=%s*\"([%w%s%p]-)\"%s*(.*)",
		process = function(k, v)
			if loader.setenv(k, v) ~= 0 then
				print("Failed to set '"..k.."' with value: "..v.."");
			end
		end
	},
	--  env_var=num
	[11] = {
		str = "^%s*([%w%p]+)%s*=%s*(%d+)%s*(.*)",
		process = function(k, v)
			if loader.setenv(k, v) ~= 0 then
				print("Failed to set '"..k.."' with value: "..v.."");
			end
		end
	}
};

function config.isValidComment(c)
	if c ~= nil then
		local s = string.match(c, "^%s*#.*");
		if s == nil then
			s = string.match(c, "^%s*$");
		end
		if s == nil then
			return false;
		end
	end
	return true;
end

function config.loadmod(mod, silent)
	local status = true;
	for k, v in pairs(mod) do
		if v.load == "YES" then
			local str = "load ";
			if v.flags ~= nil then
				str = str .. v.flags .. " ";
			end
			if v.type ~= nil then
				str = str .. "-t " .. v.type .. " ";
			end
			if v.name ~= nil then
				str = str .. v.name;
			else
				str = str .. k;
			end

			if v.before ~= nil then
				if loader.perform(v.before) ~= 0 then
					if not silent then
						print("Failed to execute '"..v.before.."' before loading '"..k.."'");
					end
					status = false;
				end
			end

			if loader.perform(str) ~= 0 then
				if not silent then
					print("Failed to execute '" .. str .. "'");
				end
				if v.error ~= nil then
					loader.perform(v.error);
				end
				status = false;
			end

			if v.after ~= nil then
				if loader.perform(v.after) ~= 0 then
					if not silent then
						print("Failed to execute '"..v.after.."' after loading '"..k.."'");
					end
					status = false;
				end
			end

		else
			--if not silent then print("Skiping module '".. k .. "'"); end
		end
	end

	return status;
end

function config.parse(name, silent)
	local f = io.open(name);
	if f == nil then
		if not silent then
			print("Failed to open config: '" .. name.."'");
		end
		return false;
	end

	local text;
	local r;

	text, r = io.read(f);

	if text == nil then
		if not silent then
			print("Failed to read config: '" .. name.."'");
		end
		return false;
	end

	local n = 1;
	local status = true;

	for line in string.gmatch(text, "([^\n]+)") do

		if string.match(line, "^%s*$") == nil then
			local found = false;

			for i, val in ipairs(pattern_table) do
				local k, v, c = string.match(line, val.str);
				if k ~= nil then
					found = true;

					if config.isValidComment(c) then
						val.process(k, v);
					else
						print("Malformed line ("..n.."):\n\t'"..line.."'");
						status = false;
					end

					break;
				end
			end

			if found == false then
				print("Malformed line ("..n.."):\n\t'"..line.."'");
				status = false;
			end
		end
		n = n + 1;
	end

	return status;
end

function config.loadkernel()
	local flags = loader.getenv("kernel_options") or "";
	local kernel = loader.getenv("kernel");

	local try_load = function (names)
		for name in names:gmatch("([^;]+)%s*;?") do
			r = loader.perform("load "..flags.." "..name);
			if r == 0 then
				return name;
			end
		end
		return nil;
	end;

	local load_bootfile = function()
		local bootfile = loader.getenv("bootfile");

		-- append default kernel name
		if not bootfile then
			bootfile = "kernel";
		else
			bootfile = bootfile..";kernel";
		end

		return try_load(bootfile);
	end;

	-- kernel not set, try load from default module_path
	if kernel == nil then
		local res = load_bootfile();

		if res ~= nil then
			return true;
		else
			print("Failed to load kernel '"..res.."'");
			return false;
		end
	else
		local module_path = loader.getenv("module_path");
		local res = nil;

		-- first try load kernel with module_path = /boot/${kernel}
		-- then try load with module_path=${kernel}
		local paths = {"/boot/"..kernel, kernel};

		for k,v in pairs(paths) do

			loader.setenv("module_path", v);
			res = load_bootfile();

			-- succeeded add path to module_path
			if res ~= nil then
				loader.setenv("module_path", v..";"..module_path);
				return true;
			end
		end

		-- failed to load with ${kernel} as a directory
		-- try as a file
		res = try_load(kernel);
		if res ~= nil then
			return true;
		else
			print("Failed to load kernel '"..res.."'");
			return false;
		end
	end
end


function config.load(file)

	if not file then
		file = "/boot/defaults/loader.conf";
	end

	if not config.parse(file) then
--		print("Failed to parse configuration: '"..file.."'");
	end

	local f = loader.getenv("loader_conf_files");
	if f ~= nil then
		for name in string.gmatch(f, "([%w%p]+)%s*") do
			if not config.parse(name) then
--				print("Failed to parse configuration: '"..name.."'");
			end
		end
	end

	print("Loading kernel...");
	config.loadkernel();

	print("Loading configurations...");
	if not config.loadmod(modules) then
		print("Could not load configurations!");
	end
end

function config.reload(kernel)
	local res = 1;

	-- unload all modules
	print("Unloading modules...");
	loader.perform("unload");

	if kernel ~= nil then
		res = loader.perform("load "..kernel);
		if res == 0 then
			print("Kernel '"..kernel.."' loaded!");
		end
	end

	-- failed to load kernel or it is nil
	-- then load default
	if res == 1 then
		print("Loading default kernel...");
		config.loadkernel();
	end

	-- load modules
	config.loadmod(modules);
end

return config
