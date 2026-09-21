#pragma once
#include <string>

namespace MGSVAudioIdentityBridge {
// Call Configure before Install.
void Configure(bool overlay, bool hotkeys, float emphasis, bool debugLog, bool bedCentreDirect,
               bool peakGuard, bool foxHooks);
void ConfigureHookGroups(bool nativeHooks, bool listenerHook, bool mixerHook);
bool Install();
bool GetAudioStatus(std::string& text);
void ConfigureLogPath(const std::wstring& path);
void Shutdown();
}
