-- Load the DLL through IH. The working directory must be the game folder.
local this = {}
if rawget(_G, "ChoomAudio_Core") then return _G.ChoomAudio_Core end
local init, err = package.loadlib("plugins/choomaudio.dll", "luaopen_choomaudio")
if not init then error("ChoomAudio_Core: " .. tostring(err)) end
init()
_G.ChoomAudio_Core = this
return this
