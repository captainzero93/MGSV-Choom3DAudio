#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <atomic>
#include <stdexcept>
#include <stdexcept>
#include "Config.h"
#include "Hooks_AudioIdentityBridge.h"
#include "MinHook/MinHook.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
namespace ChoomAudioGuards {void Install(bool,bool);}
namespace {
HMODULE g_module=nullptr;
std::wstring ModulePath(HMODULE m){
 std::vector<wchar_t> b(32768);DWORD n=GetModuleFileNameW(m,b.data(),static_cast<DWORD>(b.size()));
 if(!n || n>=b.size())throw std::runtime_error("GetModuleFileNameW failed");return {b.data(),n};
}
bool SupportedGame(){
 auto base=reinterpret_cast<const unsigned char*>(GetModuleHandleW(nullptr));
 auto dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
 if(dos->e_magic!=IMAGE_DOS_SIGNATURE)return false;
 auto nt=reinterpret_cast<const IMAGE_NT_HEADERS64*>(base+dos->e_lfanew);
 return nt->Signature==IMAGE_NT_SIGNATURE && nt->FileHeader.Machine==IMAGE_FILE_MACHINE_AMD64 &&
  nt->OptionalHeader.Magic==IMAGE_NT_OPTIONAL_HDR64_MAGIC && nt->FileHeader.TimeDateStamp==0x6A4CB898u;
}
bool HasAudioBridge(HMODULE module){
 if(!module)return false;
 std::ifstream file(std::filesystem::path(ModulePath(module)),std::ios::binary);
 const std::string needle="MGSV_AUDIO_NATIVE_POSITION,";
 std::string prior;char bytes[65536];
 while(file){file.read(bytes,sizeof(bytes));prior.append(bytes,static_cast<std::size_t>(file.gcount()));
  if(prior.find(needle)!=std::string::npos)return true;
  if(prior.size()>needle.size())prior.erase(0,prior.size()-needle.size());
 }
 return false;
}
// Plugin settings are read at startup; no GUI or hotkeys.
DWORD WINAPI Start(LPVOID){
 try{
  const auto game=std::filesystem::path(ModulePath(nullptr)).parent_path();
  const auto folder=std::filesystem::path(ModulePath(g_module)).parent_path();
  const auto logPath=folder/L"choomaudio.log";
  auto log=spdlog::basic_logger_mt("choomaudio_bootstrap",logPath.wstring(),true);
  spdlog::set_default_logger(log);log->flush_on(spdlog::level::info);
  spdlog::info("CHOOMAUDIO_PLUGIN_PORT_073_R1 | worker started | pid={}",GetCurrentProcessId());
  if(_wcsicmp(std::filesystem::path(ModulePath(nullptr)).filename().c_str(),L"mgsvtpp.exe") || !SupportedGame()){
   spdlog::error("Unsupported executable. No hooks installed.");return 0;
  }
  ChoomAudio::Config config;
  auto configPath=folder/L"choomaudio.lua";
  if(!std::filesystem::exists(configPath))configPath=game/L"ihhook_config.lua";
  std::ifstream in(configPath);const bool loaded=bool(in);if(loaded)ChoomAudio::ReadConfig(in,config);
  spdlog::info("Config: plugin_file={} loaded={} invalid={} enabled={} emphasis={} peakGuard={} bedCentreDirect={} nullGuard={} viewGuard={}",
   configPath.filename()==L"choomaudio.lua",loaded,config.invalid,config.enableAudioBridge,
   config.audioSpatialEmphasis,config.audioPeakGuard,config.audioBedCentreDirect,config.enableNullGuard,config.enableViewGuard);
  if(HasAudioBridge(GetModuleHandleW(L"dinput8.dll")) || HasAudioBridge(GetModuleHandleW(L"IHHook.dll"))){
   ChoomAudio::Config host;std::ifstream hostFile(game/L"ihhook_config.lua");
   if(hostFile)ChoomAudio::ReadConfig(hostFile,host);
   if(host.enableAudioBridge || host.enableNullGuard || host.enableViewGuard){
    spdlog::error("Modded IHHook found. Use your plugin-capable stock IHHook, or set enableAudioBridge=false, enableNullGuard=false, enableViewGuard=false in the ROOT ihhook_config.lua. Plugin settings belong in plugins/choomaudio.lua. No hooks installed.");return 0;
   }
  }
  const auto status=MH_Initialize();
  if(status!=MH_OK){spdlog::error("Private MinHook initialization failed: {}",static_cast<int>(status));return 0;}
  ChoomAudioGuards::Install(config.enableNullGuard,config.enableViewGuard);
  bool installed=false;
  if(config.enableAudioBridge){
   MGSVAudioIdentityBridge::ConfigureLogPath((folder/L"choomaudio_audio.log").wstring());
   MGSVAudioIdentityBridge::ConfigureHookGroups(config.audioNativeHooks,config.audioListenerHook,config.audioMixerHook);
   MGSVAudioIdentityBridge::Configure(false,false,config.audioSpatialEmphasis,
    config.audioDebugLog,config.audioBedCentreDirect,config.audioPeakGuard,config.audioFoxHooks); // no overlay, no hotkeys
   installed=MGSVAudioIdentityBridge::Install();
  }
  spdlog::info("Audio install returned {}. Detailed hook results: plugins/choomaudio_audio.log",installed);
 }catch(const std::exception& e){
  OutputDebugStringA(e.what());
  try{spdlog::error("ChoomAudio initialization failed: {}",e.what());spdlog::default_logger()->flush();}catch(...){}
 }catch(...){OutputDebugStringA("ChoomAudio initialization failed");}
 return 0;
}
}
// Lua entry point. DLL attachment starts initialization.
extern "C" __declspec(dllexport) int __cdecl luaopen_choomaudio(void*){return 0;}
extern "C" __declspec(dllexport) const char* __cdecl ChoomAudioVersion(){return "CHOOMAUDIO_PLUGIN_PORT_073_R1";}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID){
 if(reason==DLL_PROCESS_ATTACH){
  g_module=instance;
  // Keep the DLL loaded while native callbacks are installed.
  HMODULE pinned=nullptr;
  if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
      reinterpret_cast<LPCWSTR>(&DllMain),&pinned))return FALSE;
  HANDLE thread=CreateThread(nullptr,0,&Start,nullptr,0,nullptr);
  if(thread)CloseHandle(thread);else OutputDebugStringA("ChoomAudio: could not start initialization thread");
 }
 // Do not tear down hooks or wait under the loader lock.
 return TRUE;
}
