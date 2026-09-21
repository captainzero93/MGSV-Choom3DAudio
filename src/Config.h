#pragma once
#include <string>
#include <istream>
#include <cstdlib>
#include <cmath>

namespace ChoomAudio
{
    // Ignore obsolete overlay and hotkey settings.
    struct Config
    {
        bool enableAudioBridge = true, audioDebugLog = false;
        bool audioBedCentreDirect = false, audioPeakGuard = true, audioFoxHooks = true;
        bool audioNativeHooks = true, audioListenerHook = true, audioMixerHook = true;
        bool enableNullGuard = true, enableViewGuard = true;
        float audioSpatialEmphasis = 0.65f;
        unsigned invalid = 0;
    };

    inline std::string Trim(std::string s)
    {
        auto a = s.find_first_not_of(" \t\r\n");
        if (a == std::string::npos)
            return {};
        return s.substr(a, s.find_last_not_of(" \t\r\n") - a + 1);
    }

    inline void ReadConfig(std::istream& input, Config& c)
    {
        std::string line;
        while (std::getline(input, line))
        {
            auto comment = line.find("--");
            if (comment != std::string::npos)
                line.resize(comment);
            auto eq = line.find('=');
            if (eq == std::string::npos)
                continue;
            auto key = Trim(line.substr(0, eq)), value = Trim(line.substr(eq + 1));
            if (!value.empty() && value.back() == ',')
                value.pop_back();
            value = Trim(value);
            bool* target = nullptr;
#define CHOOM_BOOL(name)                                                                                                                                       \
    if (key == #name)                                                                                                                                          \
        target = &c.name;
            CHOOM_BOOL(enableAudioBridge)
            CHOOM_BOOL(audioDebugLog)
            CHOOM_BOOL(audioBedCentreDirect)
            CHOOM_BOOL(audioPeakGuard)
            CHOOM_BOOL(audioFoxHooks)
            CHOOM_BOOL(audioNativeHooks)
            CHOOM_BOOL(audioListenerHook)
            CHOOM_BOOL(audioMixerHook)
            CHOOM_BOOL(enableNullGuard)
            CHOOM_BOOL(enableViewGuard)
#undef CHOOM_BOOL
            if (target)
            {
                if (value == "true")
                    *target = true;
                else if (value == "false")
                    *target = false;
                else
                    ++c.invalid;
            }
            else if (key == "audioSpatialEmphasis")
            {
                char* end = nullptr;
                float f = std::strtof(value.c_str(), &end);
                if (end == value.c_str() || *end || !std::isfinite(f) || f < 0 || f > 1)
                    ++c.invalid;
                else
                    c.audioSpatialEmphasis = f;
            }
        }
    }
}
