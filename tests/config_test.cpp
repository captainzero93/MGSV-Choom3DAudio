#include "Config.h"
#include <cassert>
#include <fstream>
#include <sstream>
int main(int argc,char** argv){
 assert(argc==2);
 ChoomAudio::Config c;std::ifstream f(argv[1]);assert(f);ChoomAudio::ReadConfig(f,c);
 assert(c.invalid==0 && c.enableAudioBridge); // v0.74: audioOverlay/audioHotkeys no longer exist
 assert(c.audioSpatialEmphasis==0.65f && !c.audioDebugLog && c.audioPeakGuard && !c.audioBedCentreDirect);
 assert(c.audioNativeHooks && c.audioListenerHook && c.audioMixerHook && c.audioFoxHooks);
 assert(c.enableNullGuard && c.enableViewGuard);
 std::istringstream other("  enableAudioBridge = false, -- off\n audioHotkeys=false\n enableNullGuard=false\n enableViewGuard=false\n audioSpatialEmphasis=nan\n audioSpatialEmphasis=1.2\n audioSpatialEmphasis=0.7junk\n audioSpatialEmphasis=\n audioOverlay=yes\n unrelated=true\n"); // removed and unknown keys are ignored, not counted as invalid
 ChoomAudio::ReadConfig(other,c);
 assert(!c.enableAudioBridge && !c.enableNullGuard && !c.enableViewGuard);
 assert(c.invalid==4 && c.audioSpatialEmphasis==0.65f);
 std::istringstream bounds("audioSpatialEmphasis=0\naudioSpatialEmphasis=1,\n");
 ChoomAudio::ReadConfig(bounds,c);assert(c.audioSpatialEmphasis==1.f && c.invalid==4);
}
