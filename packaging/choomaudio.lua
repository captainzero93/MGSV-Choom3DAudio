-- Plugin settings. Restart the game after editing.
-- The native parser reads literal values; it does not execute this file.
-- No GUI or hotkeys.
local this={
	enableAudioBridge=true,--[true] 3D headphone audio
	audioSpatialEmphasis=0.65,--[0.65] strength of direction cues for in-world sounds, 0 to 1
	audioPeakGuard=true,--[true] loud 3D sounds never peak above the game's own mix
	audioBedCentreDirect=false,--[false] cutscene dialogue with no HRTF colouring (in-head instead of in front)
	audioDebugLog=false,--[false] full diagnostic audio log (~8 MB a session)
	enableNullGuard=true,--[true] skips a null-object game call that crashed one story cutscene
	enableViewGuard=true,--[true] skips a view update when its render context is missing
	-- Troubleshooting switches. Leave enabled for normal use.
	audioNativeHooks=true,
	audioListenerHook=true,
	audioMixerHook=true,
	audioFoxHooks=true,
}
return this
