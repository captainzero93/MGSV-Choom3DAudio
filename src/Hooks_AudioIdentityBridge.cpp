// Positional audio hooks for MGSV 1.0.15.4.
// Reference SHA-256: 085c2f82d1c963c40b3d2d55786661dfee2b18cbbf388a710c00fa76c5e9bb45
// PE timestamp: 0x6A4CB898
#include "Hooks_AudioIdentityBridge.h"
#include <string>
#include <cstdio>

#include <Windows.h>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <memory>
#include <intrin.h>

#include "MIT_KEMAR_HRIR_48K_128_360.h"
#include "MGSV_HRIR_KU100.h" // default HRIR set: Neumann KU 100 (TH Koeln, CC BY-SA 3.0)
#include "MinHook/MinHook.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

namespace MGSVAudioIdentityBridge {
namespace {
std::wstring g_pluginLogPath=L"choomaudio_audio.log";

constexpr std::uint32_t kExpectedPeTimestamp = 0x6A4CB898u;

// Exact-current-build RVAs from the Ghidra audit.
constexpr std::uintptr_t kRvaSourcePostEvent        = 0x01D728F0ull;
constexpr std::uintptr_t kRvaSourceTransformSync    = 0x01D72C40ull;
constexpr std::uintptr_t kRvaListenerBridge         = 0x00437B60ull;
constexpr std::uintptr_t kRvaWwisePostGateway       = 0x0033C050ull;
constexpr std::uintptr_t kRvaWwiseGameObjectLookup  = 0x0034CA50ull;
constexpr std::uintptr_t kRvaPlaybackActionDispatch = 0x00347E00ull;
constexpr std::uintptr_t kRvaPlayingEventPack         = 0x00342060ull;
constexpr std::uintptr_t kRvaVoiceRenderNode          = 0x00352330ull;
constexpr std::uintptr_t kRvaSinkPump                 = 0x003A1470ull;
constexpr std::uintptr_t kRvaSourceToDestinationMix  = 0x003A77B0ull;
constexpr std::uintptr_t kRvaAlternateMixCore         = 0x003A7DF0ull;
constexpr std::uintptr_t kRvaLowLevelChannelMix       = 0x003D67B0ull;

// Pointer slot for 256 registered-source records, each 0xE0 bytes.
constexpr std::uintptr_t kRvaRegisteredSourceTablePtr = 0x02B9E8B0ull;
constexpr std::size_t kRegisteredSourceRecordSize = 0xE0;
constexpr std::size_t kRegisteredSourceCount = 0x100;

namespace KEMAR360 = ::MGSVAudioProbe::KEMAR360;
namespace HRIRSET = ::MGSVAudioProbe::HRIRSET;

constexpr double kRadiansToDegrees = 57.2957795130823208768;
constexpr std::size_t kBinauralMaxFrames = 1024;
constexpr std::size_t kBinauralHistorySamples = 512; // power of two
constexpr std::size_t kBinauralStateSlots = 1024;     // power of two
constexpr std::uint64_t kListenerFreshMs = 250;
constexpr float kDirectHrtfOutputGain = 1.00f;
constexpr float kHybridLowpassAlpha = 0.0994231307f; // 800 Hz one-pole at 48 kHz
constexpr float kHybridPeakGuard = 0.98f;

constexpr std::size_t kRecentFoxSlots = 512;       // power of two
constexpr std::size_t kRecentKeySlots = 512;       // power of two
constexpr std::size_t kRecentObjectSlots = 512;    // power of two
constexpr std::size_t kRecentPlayingSlots = 512;   // power of two
constexpr std::size_t kTraceSlots = 8192;          // power of two
constexpr std::uint64_t kRecentIdentityTtlMs = 15000;
constexpr std::uint64_t kTransformLogIntervalMs = 500;
constexpr std::uint64_t kSummaryIntervalMs = 2000;
constexpr std::size_t kMaxFlushPerBridge = 512;
constexpr std::uint64_t kMaxLogRecords = 150000;

// Bounded active-render snapshots for three diagnostic event families.
constexpr std::size_t kRenderGateSlots = 256;          // power of two
constexpr std::size_t kRenderSnapshotSlots = 128;      // power of two
constexpr std::uint64_t kRenderSnapshotIntervalMs = 250;
constexpr std::size_t kRenderNodeBytes = 0x200;
constexpr std::size_t kRenderWrapperBytes = 0x80;
constexpr std::size_t kRenderContextBytes = 0x300;
constexpr std::size_t kMaxRenderFlushPerBridge = 32;
constexpr std::uint32_t kEventGenerator = 0xDC384714u;
constexpr std::uint32_t kEventSteam = 0xDC26FE36u;
constexpr std::uint32_t kEventObservedA54F = 0xA54F174Fu;
constexpr std::uint64_t kMatrixBindLogIntervalMs = 250;
constexpr std::size_t kMatrixBindGateSlots = 256;      // power of two


using SourcePostEventFn = int* (__fastcall*)(
    std::int64_t body,
    int* outResult,
    std::uint32_t eventId);

using SourceTransformSyncFn = void (__fastcall*)(std::int64_t body);
using ListenerBridgeFn = void (__fastcall*)(std::int64_t owner);

// Ghidra signature:
// int FUN_14033c050(undefined4 event, undefined8 objectKey,
//     undefined4 p3, undefined8 p4, undefined8 p5,
//     int p6, undefined8 p7, undefined4 p8)
using WwisePostGatewayFn = int (__fastcall*)(
    std::uint32_t eventId,
    std::uint64_t objectKey,
    std::uint32_t param3,
    std::uint64_t param4,
    std::uint64_t param5,
    int param6,
    std::uint64_t param7,
    std::uint32_t param8);

// Call sites in FUN_140348ED0 pass DAT_142B9EAE8 and the queued object key.
using WwiseGameObjectLookupFn = std::int64_t (__fastcall*)(
    std::int64_t manager,
    std::uint64_t objectKey);

// Ghidra: void FUN_140347e00(longlong runtime, longlong *action)
using PlaybackActionDispatchFn = void (__fastcall*)(
    std::int64_t runtime,
    std::int64_t action);

// FUN_140342060 takes (outPair, PostGateway result, eventId).
// Callers queue the first 8 output bytes.
using PlayingEventPackFn = void (__fastcall*)(
    std::uint32_t* outPair,
    std::uint32_t playingId,
    std::uint32_t eventId);

// FUN_140352330 receives a buffer with its render-node pointer at +0x40.
using VoiceRenderNodeFn = void (__fastcall*)(std::int64_t audioBufferLike);

using SinkPumpFn = void (__fastcall*)(std::int64_t sink);

using SourceToDestinationMixFn = void (__fastcall*)(
    std::int64_t destination,
    std::int64_t sourceBuffer,
    const float* coefficientBlock);

using AlternateMixCoreFn = void (__fastcall*)(
    std::int64_t frameInfo,
    std::int64_t sourceBuffer,
    std::int64_t destinationBuffer,
    char directSameMask,
    const float* coefficientBlock);

// FUN_1403D67B0(sourcePCM, destinationPCM, gainStart, gainDelta, frames)
using LowLevelChannelMixFn = void (__fastcall*)(
    std::int64_t sourcePcm,
    std::int64_t destinationPcm,
    float gainStart,
    float gainDelta,
    std::uint32_t frames);


SourcePostEventFn g_sourcePostOriginal = nullptr;
SourceTransformSyncFn g_transformOriginal = nullptr;
ListenerBridgeFn g_listenerOriginal = nullptr;
WwisePostGatewayFn g_wwisePostOriginal = nullptr;
WwiseGameObjectLookupFn g_gameObjectLookupOriginal = nullptr;
PlaybackActionDispatchFn g_actionDispatchOriginal = nullptr;
PlayingEventPackFn g_playingEventPackOriginal = nullptr;
VoiceRenderNodeFn g_voiceRenderOriginal = nullptr;
SinkPumpFn g_sinkPumpOriginal = nullptr;
SourceToDestinationMixFn g_sourceToDestinationMixOriginal = nullptr;
AlternateMixCoreFn g_alternateMixCoreOriginal = nullptr;
LowLevelChannelMixFn g_lowLevelChannelMixOriginal = nullptr;

std::uintptr_t g_exeBase = 0;
std::size_t g_imageSize = 0;
std::shared_ptr<spdlog::logger> g_log;
// Startup settings supplied by Configure.
std::atomic<bool> g_overlay062{true},g_hotkeys062{true};
std::atomic<float> g_emphasis062{0.65f}; // 0 = plain KU 100, 1 = full cue emphasis
std::atomic<bool> g_debugLog063{false}; // full diagnostics (census rows, periodic counters)
std::atomic<bool> g_bedCentreDirect064{false}; // cutscene centre channel without HRTF
std::atomic<bool> g_peakGuard066{true};
std::atomic<bool> g_foxHooks068{true};  // Fox sound-source identity hooks (bisect switch)
std::atomic<bool> g_nativeHooks069{true},g_listenerHook069{true},g_mixerHook069{true}; // bisect switches
std::atomic<std::uint64_t> g_peakGuarded066{0};
std::uint32_t g_bedCentreDelay064=0;           // front HRIR arrival (taps), set at Configure
// No plugin hotkeys. Keep the configured processing defaults.
bool AudioKey062(int) { return false; }
std::atomic<bool> g_installed{false};
std::atomic<std::uint64_t> g_logRecords{0};
std::atomic<bool> g_logLimitReported{false};

std::atomic<std::uint64_t> g_sourceEvents{0};
std::atomic<std::uint64_t> g_sourceRecordsValid{0};
std::atomic<std::uint64_t> g_sourceRecordsInvalid{0};
std::atomic<std::uint64_t> g_sourceTransforms{0};
std::atomic<std::uint64_t> g_wwisePosts{0};
std::atomic<std::uint64_t> g_wwisePostsWithRecord{0};
std::atomic<std::uint64_t> g_gameObjectLookups{0};
std::atomic<std::uint64_t> g_gameObjectLookupsTracked{0};
std::atomic<std::uint64_t> g_actionDispatches{0};
std::atomic<std::uint64_t> g_actionDispatchesTracked{0};
std::atomic<std::uint64_t> g_playingIdMatches{0};
std::atomic<std::uint64_t> g_objectFallbackMatches{0};
std::atomic<std::uint64_t> g_traceDropped{0};
std::atomic<std::uint64_t> g_summaryTick{0};
std::atomic<std::uint64_t> g_tlsEventMatches{0};
std::atomic<std::uint64_t> g_tlsEventMismatches{0};
std::atomic<std::uint64_t> g_sourceZeroBeforeNonzeroAfter{0};
std::atomic<std::uint64_t> g_sourceChangedAcrossCall{0};
std::atomic<std::uint64_t> g_lookupTraceRows{0};
std::atomic<std::uint64_t> g_sourceDerivedKeyMatches{0};
std::atomic<std::uint64_t> g_tableSourceMatches{0};
std::atomic<std::uint64_t> g_tableKeyMatches{0};
std::atomic<std::uint64_t> g_playingEventPackCalls{0};
std::atomic<std::uint64_t> g_playingEventPackTracked{0};
std::atomic<std::uint64_t> g_playingEventPackOutputMatches{0};
std::atomic<std::uint64_t> g_renderNodeCalls{0};
std::atomic<std::uint64_t> g_renderSnapshotsQueued{0};
std::atomic<std::uint64_t> g_renderSnapshotsProcessed{0};
std::atomic<std::uint64_t> g_renderIdentityMatches{0};
std::atomic<std::uint64_t> g_renderNoMatchRows{0};
std::atomic<std::uint64_t> g_matrixCalls{0};
std::atomic<std::uint64_t> g_matrixActiveCalls{0};
std::atomic<std::uint64_t> g_matrixRouteBMonoStereo{0};
std::atomic<std::uint64_t> g_matrixPlayingMatches{0};
std::atomic<std::uint64_t> g_matrixDualIdentityMatches{0};
std::atomic<std::uint64_t> g_matrixIdentityRenewals{0};
std::atomic<std::uint64_t> g_matrixResearchMatches{0};

// deterministic write-path telemetry.
std::atomic<bool> g_holdDirectHrtf{false};
std::atomic<bool> g_holdWorldAuditionMute{false};
std::atomic<std::uint64_t> g_worldAuditionMuteCalls{0};
std::atomic<std::uint64_t> g_primaryFamilyCalls{0};
std::atomic<std::uint64_t> g_primaryFamilyMuteCalls{0};
std::atomic<std::uint64_t> g_alternateFamilyCalls{0};
std::atomic<std::uint64_t> g_alternateFamilyMuteCalls{0};
std::atomic<std::uint64_t> g_alternateFamilyTrackedContext{0};

// final-sink audition.
std::atomic<std::uint64_t> g_sinkPumpCalls{0};
std::atomic<std::uint64_t> g_sinkForcedSilenceCalls{0};
std::atomic<std::uint64_t> g_sinkSkippedCalls{0};
std::atomic<std::uintptr_t> g_lastSinkObject{0};
std::atomic<std::uintptr_t> g_lastSinkVtable{0};
std::atomic<std::uint32_t> g_lastSinkFrames{0};
std::atomic<std::uint64_t> g_directHrtfAttempts{0};
std::atomic<std::uint64_t> g_directHrtfAppliedBlocks{0};
std::atomic<std::uint64_t> g_directHrtfNoListener{0};
std::atomic<std::uint64_t> g_directHrtfNoTransform{0};
std::atomic<std::uint64_t> g_directHrtfBadPcm{0};
std::atomic<std::uint64_t> g_directHrtfLeftCalls{0};
std::atomic<std::uint64_t> g_directHrtfRightCalls{0};
std::atomic<bool> g_holdDirectDry{false};
std::atomic<std::uint64_t> g_directDryAttempts{0};
std::atomic<std::uint64_t> g_directDryAppliedBlocks{0};
std::atomic<std::uint64_t> g_directDryLeftCalls{0};
std::atomic<std::uint64_t> g_directDryRightCalls{0};
std::atomic<std::uint64_t> g_binauralHistoryResets{0};
std::atomic<std::uint64_t> g_wideHrtfMultiAttempts{0};
std::atomic<std::uint64_t> g_wideHrtfMultiApplied{0};
std::atomic<std::uint64_t> g_wideHrtfStereoApplied{0};
std::atomic<std::uint64_t> g_wideHrtfQuadApplied{0};
std::atomic<std::uint64_t> g_wideHrtfUnsupported{0};


// Render coverage counters for voices matched to a Fox SoundSourceBody.
std::atomic<std::uint64_t> g_renderTrackedCalls{0};
std::atomic<std::uint64_t> g_renderPlayingIdentity{0};
std::atomic<std::uint64_t> g_renderObjectIdentity{0};
std::atomic<std::uint64_t> g_renderDualIdentity{0};
std::atomic<std::uint64_t> g_renderUnidentifiedCalls{0};
std::atomic<std::uint64_t> g_matrixTrackedCalls{0};
std::atomic<std::uint64_t> g_matrixTrackedRoute1{0};
std::atomic<std::uint64_t> g_matrixTrackedRoute2{0};
std::atomic<std::uint64_t> g_matrixTrackedRoute3{0};
std::atomic<std::uint64_t> g_matrixTrackedOther{0};
std::atomic<std::uint64_t> g_lowLevelCalls{0};
std::atomic<std::uint64_t> g_lowLevelTrackedCalls{0};
std::atomic<std::uint64_t> g_lowLevelTrackedViaMatrix{0};
std::atomic<std::uint64_t> g_lowLevelTrackedViaRender{0};

constexpr std::size_t kCoverageSlots = 2048;       // power of two
constexpr std::size_t kCallerCensusSlots = 256;    // power of two
constexpr std::uint64_t kCoverageTraceIntervalMs = 1000;

struct CoverageSlot {
    std::atomic<std::uint64_t> signature{0};
    std::atomic<std::uintptr_t> body{0};
    std::atomic<std::uint32_t> eventId{0};
    std::atomic<std::uint32_t> source{0};
    std::atomic<std::uint64_t> key{0};
    std::atomic<std::uint32_t> latestPlaying{0};
    std::atomic<std::uint64_t> firstTick{0};
    std::atomic<std::uint64_t> lastTick{0};
    std::atomic<std::uint64_t> sourcePosts{0};
    std::atomic<std::uint64_t> renderCalls{0};
    std::atomic<std::uint32_t> renderMatchMask{0}; // bit0 playing, bit1 objA8, bit2 obj148
    std::atomic<std::uint64_t> matrixCalls{0};
    std::atomic<std::uint32_t> matrixRouteMask{0}; // bits 0..3 => other/route1/route2/route3
    std::array<std::atomic<std::uint32_t>, 4> sourceMasks{};
    std::array<std::atomic<std::uint32_t>, 4> destinationMasks{};
    std::array<std::atomic<std::uintptr_t>, 4> matrixCallers{};
    std::atomic<std::uint64_t> lowLevelCalls{0};
    std::atomic<std::uint64_t> lowViaMatrix{0};
    std::atomic<std::uint64_t> lowViaRender{0};
    std::array<std::atomic<std::uintptr_t>, 4> lowCallers{};
    std::atomic<std::uint64_t> renderTraceTick{0};
    std::atomic<std::uint64_t> matrixTraceTick{0};
    std::atomic<std::uint64_t> lowTraceTick{0};
};

struct CallerCensusSlot {
    std::atomic<std::uintptr_t> caller{0};
    std::atomic<std::uint64_t> calls{0};
    std::atomic<std::uint64_t> tracked{0};
};

std::array<CoverageSlot, kCoverageSlots> g_coverage{};
std::array<CallerCensusSlot, kCallerCensusSlots> g_matrixCallerCensus{};
std::array<CallerCensusSlot, kCallerCensusSlots> g_lowCallerCensus{};

std::array<std::atomic<std::uint32_t>, 8> g_latestListenerTransformBits{};
std::atomic<std::uint64_t> g_latestListenerTransformTick{0};

struct BinauralHistoryState {
    std::uintptr_t ownerBody047=0;
    std::uint32_t ownerPlaying047=0;
    std::uint64_t ownerNativeGeneration050=0;
    std::uint64_t ownerEpoch047=0,lastTick047=0;
    std::uintptr_t node = 0;
    std::uintptr_t destination = 0;
    std::uint32_t writeIndex = 0;
    float priorAzimuthDeg = 0.0f;
    float lowHrtfLeft = 0.0f;
    float lowHrtfRight = 0.0f;
    float lowDryLeft = 0.0f;
    float lowDryRight = 0.0f;
    float limiterGain = 1.0f; // smoothed peak limiter (replaces per-block hard scaling)
    std::uint64_t lastUse056 = 0; // LRU for probed slot selection
    float priorElevationDeg = 0.0f; // v0.59
    float peakGuard066 = 1.0f;       // per-voice 'never louder than the game' gain
    bool initialized = false;
    float history[kBinauralHistorySamples]{};
};

// counters
std::atomic<std::uint64_t> g_filterCrossfades056{0},g_limiterEngaged056{0},g_stereoWide056{0},g_bedOrderMismatch056{0};
std::atomic<bool> g_stereoSpread056{true};
// Elevation processing, enabled by default.
std::atomic<bool> g_elevation059{true};
std::atomic<std::uint64_t> g_elevBelow059{0},g_elevLevel059{0},g_elevAbove059{0};
alignas(16) thread_local float g_directLeftEar[kBinauralMaxFrames]{};
alignas(16) thread_local float g_directRightEar[kBinauralMaxFrames]{};
alignas(16) thread_local float g_wideMono[kBinauralMaxFrames]{};
thread_local BinauralHistoryState g_binauralHistory[kBinauralStateSlots]{};


struct RecentFoxSlot {
    std::atomic<std::uint32_t> source{0};
    std::atomic<std::uintptr_t> body{0};
    std::atomic<std::uint32_t> eventId{0};
    std::atomic<std::uint64_t> eventTick{0};
    std::array<std::atomic<std::uint32_t>, 8> transformBits{};
    std::atomic<std::uint64_t> transformTick{0};
    std::atomic<std::uint64_t> transformLogTick{0};
};

struct RecentKeySlot {
    std::atomic<std::uint64_t> key{0};
    std::atomic<std::uint64_t> tick{0};
    std::atomic<std::uint32_t> eventId{0};
    std::atomic<std::uint32_t> source{0};
    std::atomic<std::uintptr_t> body{0};
    std::atomic<std::uintptr_t> record{0};
    std::atomic<std::uint32_t> recordMatches{0};
    std::atomic<std::int32_t> postResult{0};
    // only emit the first successful object lookup per posted key.
    std::atomic<std::uintptr_t> lookupTraceObject{0};
};

struct RecentObjectSlot {
    std::atomic<std::uintptr_t> object{0};
    std::atomic<std::uint64_t> tick{0};
    std::atomic<std::uint64_t> key{0};
    std::atomic<std::uint32_t> eventId{0};
    std::atomic<std::uint32_t> source{0};
    std::atomic<std::uintptr_t> body{0};
    std::atomic<std::uintptr_t> record{0};
};

struct RecentPlayingSlot {
    std::atomic<std::uint32_t> playingId{0};
    std::atomic<std::uint64_t> tick{0};
    std::atomic<std::uint64_t> key{0};
    std::atomic<std::uint32_t> eventId{0};
    std::atomic<std::uint32_t> source{0};
    std::atomic<std::uintptr_t> body{0};
    std::atomic<std::uintptr_t> record{0};
};

std::array<RecentFoxSlot, kRecentFoxSlots> g_recentFox{};
std::array<RecentKeySlot, kRecentKeySlots> g_recentKeys{};
std::array<RecentObjectSlot, kRecentObjectSlots> g_recentObjects{};
std::array<RecentPlayingSlot, kRecentPlayingSlots> g_recentPlaying{};

struct BodyTransformGateSlot {
    std::atomic<std::uintptr_t> body{0};
    std::atomic<std::uint64_t> tick{0};
};
std::array<BodyTransformGateSlot, 256> g_bodyTransformGate{};

struct RenderGateSlot {
    std::atomic<std::uintptr_t> context{0};
    std::atomic<std::uint64_t> tick{0};
};
std::array<RenderGateSlot, kRenderGateSlots> g_renderGate{};

struct MatrixBindGateSlot {
    std::atomic<std::uintptr_t> context{0};
    std::atomic<std::uint64_t> tick{0};
};
std::array<MatrixBindGateSlot, kMatrixBindGateSlots> g_matrixBindGate{};


struct RenderSnapshot {
    std::uint64_t tick = 0;
    std::uint32_t tid = 0;
    std::uint32_t eventId = 0;
    std::uintptr_t node = 0;
    std::uintptr_t wrapper = 0;
    std::uintptr_t context = 0;
    std::uintptr_t eventObject = 0;
    std::uint32_t nodeBytes = 0;
    std::uint32_t wrapperBytes = 0;
    std::uint32_t contextBytes = 0;
    std::array<std::uint8_t, kRenderNodeBytes> nodeData{};
    std::array<std::uint8_t, kRenderWrapperBytes> wrapperData{};
    std::array<std::uint8_t, kRenderContextBytes> contextData{};
};

struct RenderSnapshotSlot {
    std::atomic<std::uint64_t> publishedSequence{0};
    RenderSnapshot payload{};
};
std::array<RenderSnapshotSlot, kRenderSnapshotSlots> g_renderSnapshots{};
std::atomic<std::uint64_t> g_renderSnapshotWrite{0};
std::atomic<std::uint64_t> g_renderSnapshotRead{0};
std::atomic<std::uint64_t> g_renderSnapshotDropped{0};

// Bridge synchronous Fox and Wwise posts on the same thread.
// The source handle at body+0x80 may be zero before the Fox call returns.
constexpr std::size_t kPendingFoxDepth = 8;
struct PendingFoxPost {
    std::uintptr_t body = 0;
    std::uint32_t eventId = 0;
    std::uint32_t sourceBefore = 0;
    std::uint64_t matchingObjectKey = 0;
    std::int32_t matchingPostResult = 0;
    bool sawMatchingWwisePost = false;
};
thread_local std::array<PendingFoxPost, kPendingFoxDepth> g_pendingFoxPosts{};
thread_local std::size_t g_pendingFoxDepth = 0;

enum class TraceKind : std::uint32_t {
    SourceRecord = 1,
    SourceTransform = 2,
    WwisePost = 3,
    GameObjectLookup = 4,
    PlayAction = 5,
    PlayingEventPack = 6,
    MatrixDirectBind = 7,
    ActiveRenderBind = 8,
    MatrixRouteCoverage = 9,
    LowLevelRoute = 10,
};

struct TracePayload {
    TraceKind kind = TraceKind::SourceRecord;
    std::uint64_t tick = 0;
    std::uint32_t tid = 0;
    std::uint32_t eventId = 0;
    std::uint32_t foxEventId = 0;
    std::uint32_t source = 0;
    std::uint32_t sourceBefore = 0;
    std::uint32_t sourceAfter = 0;
    std::uintptr_t body = 0;
    std::uintptr_t record = 0;
    std::uintptr_t candidateRecord = 0;
    std::uint32_t candidateStoredSource = 0;
    std::uint32_t candidateStoredKey = 0;
    std::uint64_t candidateStoredKey64 = 0;
    std::uintptr_t tableBase = 0;
    std::uint64_t derivedObjectKey = 0;
    std::uint32_t derivedKeyMatch = 0;
    std::uint32_t packOut0 = 0;
    std::uint32_t packOut1 = 0;
    std::uint64_t objectKey = 0;
    std::uint64_t nestedObjectKey = 0;
    std::int32_t nestedPostResult = 0;
    std::uint32_t tlsMatch = 0;
    std::uint32_t recordMatches = 0;
    std::int32_t result = 0;
    std::uintptr_t object = 0;
    std::uintptr_t action = 0;
    std::uint32_t playingId = 0;
    std::uint32_t matchMode = 0; // 1=playing ID, 2=object fallback
    std::uintptr_t eventNode = 0;
    std::uintptr_t eventVtable = 0;
    std::uintptr_t executeV40 = 0;
    std::uint32_t nodeType = 0;
    std::uint32_t actionRaw44 = 0;
    std::uintptr_t caller = 0;
    std::uint32_t xBits = 0;
    std::uint32_t yBits = 0;
    std::uint32_t zBits = 0;
    // matrix insertion-point identity.
    std::uint32_t route = 0;
    std::uint32_t sourceMask = 0;
    std::uint32_t destinationMask = 0;
    std::uintptr_t node = 0;
    std::uintptr_t context = 0;
    std::uintptr_t contextObjectA8 = 0;
    std::uintptr_t contextObject148 = 0;
    std::uint32_t objectA8Match = 0;
    std::uint32_t object148Match = 0;
    std::uint32_t dualIdentityMatch = 0;
    std::uint32_t hrtfRequested = 0;
    std::uint32_t hrtfApplied = 0;
    std::uint32_t hrtfFrames = 0;
    std::uintptr_t destination = 0;
    std::uint32_t dryRequested = 0;
    std::uint32_t dryApplied = 0;
    std::uint32_t sourcePeakBits = 0;
    std::uint32_t leftPeakBits = 0;
    std::uint32_t rightPeakBits = 0;
    std::uint32_t azimuthBits = 0;
    std::uint32_t elevationBits = 0;
    std::uint32_t distanceBits = 0;
    // coverage-only fields.
    std::uint32_t renderMatchMask = 0;
    std::uint32_t fromActiveRender = 0;
    std::uintptr_t matrixCaller = 0;
    std::uintptr_t lowCaller = 0;
    std::uint32_t lowFrames = 0;
    std::uint32_t lowViaMatrix = 0;
    std::uint32_t gainStartBits = 0;
    std::uint32_t gainDeltaBits = 0;
};

struct TraceSlot {
    std::atomic<std::uint64_t> publishedSequence{0};
    TracePayload payload{};
};

std::array<TraceSlot, kTraceSlots> g_trace{};
std::atomic<std::uint64_t> g_traceWrite{0};
std::atomic<std::uint64_t> g_traceRead{0};
std::atomic<bool> g_flushBusy{false};

struct IdentityMeta {
    std::uint64_t key = 0;
    std::uint32_t eventId = 0;
    std::uint32_t source = 0;
    std::uintptr_t body = 0;
    std::uintptr_t record = 0;
    std::uint32_t recordMatches = 0;
    std::int32_t postResult = 0;
};


struct RenderTlsScope {
    bool active = false;
    IdentityMeta meta{};
    std::uint32_t playingId = 0;
    std::uintptr_t node = 0;
    std::uintptr_t wrapper = 0;
    std::uintptr_t context = 0;
    std::uint32_t matchMask = 0;
};

struct MatrixTlsScope {
    bool active = false;
    IdentityMeta meta{};
    std::uint32_t playingId = 0;
    std::uint32_t route = 0;
    std::uint32_t sourceMask = 0;
    std::uint32_t destinationMask = 0;
    std::uintptr_t caller = 0;
    std::uintptr_t node = 0;
    std::uintptr_t context = 0;
};

thread_local RenderTlsScope g_renderTls{};
thread_local MatrixTlsScope g_matrixTls{};

std::size_t Hash32(std::uint32_t value, std::size_t mask) {
    return static_cast<std::size_t>(
        (static_cast<std::uint64_t>(value) * 2654435761ull) & mask);
}

std::size_t Hash64(std::uint64_t value, std::size_t mask) {
    value ^= value >> 33;
    value *= 0xff51afd7ed558ccdULL;
    value ^= value >> 33;
    return static_cast<std::size_t>(value) & mask;
}

std::size_t HashPtr(std::uintptr_t value, std::size_t mask) {
    return Hash64(static_cast<std::uint64_t>(value), mask);
}


std::uint64_t CoverageSignature(std::uintptr_t body, std::uint32_t eventId) {
    std::uint64_t v = static_cast<std::uint64_t>(body);
    v ^= (static_cast<std::uint64_t>(eventId) << 32) | eventId;
    v ^= v >> 33;
    v *= 0xff51afd7ed558ccdULL;
    v ^= v >> 33;
    if (v == 0) v = 1;
    return v;
}

CoverageSlot* FindCoverageSlot(
    std::uintptr_t body,
    std::uint32_t eventId,
    bool create)
{
    if (body == 0) return nullptr;
    const auto sig = CoverageSignature(body, eventId);
    const auto start = Hash64(sig, kCoverageSlots - 1);
    for (std::size_t probe = 0; probe < 32; ++probe) {
        auto& slot = g_coverage[(start + probe) & (kCoverageSlots - 1)];
        auto existing = slot.signature.load(std::memory_order_acquire);
        if (existing == sig) {
            const auto existingBody = slot.body.load(std::memory_order_acquire);
            const auto existingEvent = slot.eventId.load(std::memory_order_relaxed);
            if ((existingBody == 0 || existingBody == body) &&
                (existingEvent == 0 || existingEvent == eventId))
            {
                if (existingBody == 0) slot.body.store(body, std::memory_order_release);
                if (existingEvent == 0) slot.eventId.store(eventId, std::memory_order_release);
                return &slot;
            }
        }
        if (existing == 0 && create) {
            std::uint64_t expected = 0;
            if (slot.signature.compare_exchange_strong(
                    expected, sig,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire))
            {
                slot.body.store(body, std::memory_order_release);
                slot.eventId.store(eventId, std::memory_order_release);
                return &slot;
            }
        }
    }
    return nullptr;
}

template <typename T, std::size_t N>
void RememberUniqueAtomic(std::array<std::atomic<T>, N>& values, T value) {
    if (value == 0) return;
    for (auto& cell : values) {
        auto existing = cell.load(std::memory_order_acquire);
        if (existing == value) return;
        if (existing == 0) {
            T expected = 0;
            if (cell.compare_exchange_strong(
                    expected, value,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire) || expected == value)
            {
                return;
            }
        }
    }
}

void ObserveCaller(
    std::array<CallerCensusSlot, kCallerCensusSlots>& census,
    std::uintptr_t caller,
    bool tracked)
{
    if (caller == 0) return;
    const auto start = HashPtr(caller, kCallerCensusSlots - 1);
    for (std::size_t probe = 0; probe < 16; ++probe) {
        auto& slot = census[(start + probe) & (kCallerCensusSlots - 1)];
        auto existing = slot.caller.load(std::memory_order_acquire);
        if (existing == caller) {
            slot.calls.fetch_add(1, std::memory_order_relaxed);
            if (tracked) slot.tracked.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        if (existing == 0) {
            std::uintptr_t expected = 0;
            if (slot.caller.compare_exchange_strong(
                    expected, caller,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire) || expected == caller)
            {
                slot.calls.fetch_add(1, std::memory_order_relaxed);
                if (tracked) slot.tracked.fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }
    }
}

void CoverageObserveSource(
    std::uintptr_t body,
    std::uint32_t eventId,
    std::uint32_t source,
    std::uint64_t key,
    std::uint32_t playingId,
    std::uint64_t now)
{
    auto* slot = FindCoverageSlot(body, eventId, true);
    if (!slot) return;
    if (slot->firstTick.load(std::memory_order_relaxed) == 0)
        slot->firstTick.store(now, std::memory_order_relaxed);
    slot->lastTick.store(now, std::memory_order_relaxed);
    if (source != 0) slot->source.store(source, std::memory_order_relaxed);
    if (key != 0) slot->key.store(key, std::memory_order_relaxed);
    if (playingId != 0) slot->latestPlaying.store(playingId, std::memory_order_relaxed);
    slot->sourcePosts.fetch_add(1, std::memory_order_relaxed);
}

void CoverageObserveRender(
    std::uintptr_t body,
    std::uint32_t eventId,
    std::uint32_t source,
    std::uint64_t key,
    std::uint32_t playingId,
    std::uint32_t matchMask,
    std::uint64_t now)
{
    auto* slot = FindCoverageSlot(body, eventId, true);
    if (!slot) return;
    if (slot->firstTick.load(std::memory_order_relaxed) == 0)
        slot->firstTick.store(now, std::memory_order_relaxed);
    slot->lastTick.store(now, std::memory_order_relaxed);
    if (source != 0) slot->source.store(source, std::memory_order_relaxed);
    if (key != 0) slot->key.store(key, std::memory_order_relaxed);
    if (playingId != 0) slot->latestPlaying.store(playingId, std::memory_order_relaxed);
    slot->renderCalls.fetch_add(1, std::memory_order_relaxed);
    slot->renderMatchMask.fetch_or(matchMask, std::memory_order_relaxed);
}

void CoverageObserveMatrix(
    std::uintptr_t body,
    std::uint32_t eventId,
    std::uint32_t source,
    std::uint64_t key,
    std::uint32_t playingId,
    std::uint32_t route,
    std::uint32_t sourceMask,
    std::uint32_t destinationMask,
    std::uintptr_t caller,
    std::uint64_t now)
{
    auto* slot = FindCoverageSlot(body, eventId, true);
    if (!slot) return;
    if (slot->firstTick.load(std::memory_order_relaxed) == 0)
        slot->firstTick.store(now, std::memory_order_relaxed);
    slot->lastTick.store(now, std::memory_order_relaxed);
    if (source != 0) slot->source.store(source, std::memory_order_relaxed);
    if (key != 0) slot->key.store(key, std::memory_order_relaxed);
    if (playingId != 0) slot->latestPlaying.store(playingId, std::memory_order_relaxed);
    slot->matrixCalls.fetch_add(1, std::memory_order_relaxed);
    const auto routeBit = route <= 3 ? (1u << route) : 1u;
    slot->matrixRouteMask.fetch_or(routeBit, std::memory_order_relaxed);
    RememberUniqueAtomic(slot->sourceMasks, sourceMask);
    RememberUniqueAtomic(slot->destinationMasks, destinationMask);
    RememberUniqueAtomic(slot->matrixCallers, caller);
}

void CoverageObserveLowLevel(
    std::uintptr_t body,
    std::uint32_t eventId,
    std::uint32_t source,
    std::uint64_t key,
    std::uint32_t playingId,
    std::uintptr_t caller,
    bool viaMatrix,
    std::uint64_t now)
{
    auto* slot = FindCoverageSlot(body, eventId, true);
    if (!slot) return;
    if (slot->firstTick.load(std::memory_order_relaxed) == 0)
        slot->firstTick.store(now, std::memory_order_relaxed);
    slot->lastTick.store(now, std::memory_order_relaxed);
    if (source != 0) slot->source.store(source, std::memory_order_relaxed);
    if (key != 0) slot->key.store(key, std::memory_order_relaxed);
    if (playingId != 0) slot->latestPlaying.store(playingId, std::memory_order_relaxed);
    slot->lowLevelCalls.fetch_add(1, std::memory_order_relaxed);
    if (viaMatrix) slot->lowViaMatrix.fetch_add(1, std::memory_order_relaxed);
    else slot->lowViaRender.fetch_add(1, std::memory_order_relaxed);
    RememberUniqueAtomic(slot->lowCallers, caller);
}

bool ShouldTraceCoverageTick(std::atomic<std::uint64_t>& cell, std::uint64_t now) {
    auto prior = cell.load(std::memory_order_relaxed);
    for (;;) {
        if (prior != 0 && now >= prior && now - prior < kCoverageTraceIntervalMs)
            return false;
        if (cell.compare_exchange_weak(
                prior, now,
                std::memory_order_relaxed,
                std::memory_order_relaxed))
            return true;
    }
}

bool ShouldTraceCoverageRender(std::uintptr_t body, std::uint32_t eventId, std::uint64_t now) {
    auto* slot = FindCoverageSlot(body, eventId, true);
    return slot && ShouldTraceCoverageTick(slot->renderTraceTick, now);
}

bool ShouldTraceCoverageMatrix(std::uintptr_t body, std::uint32_t eventId, std::uint64_t now) {
    auto* slot = FindCoverageSlot(body, eventId, true);
    return slot && ShouldTraceCoverageTick(slot->matrixTraceTick, now);
}

bool ShouldTraceCoverageLow(std::uintptr_t body, std::uint32_t eventId, std::uint64_t now) {
    auto* slot = FindCoverageSlot(body, eventId, true);
    return slot && ShouldTraceCoverageTick(slot->lowTraceTick, now);
}

bool CanLog() {
    const auto n = g_logRecords.fetch_add(1, std::memory_order_relaxed);
    if (n < kMaxLogRecords) return true;
    if (!g_logLimitReported.exchange(true, std::memory_order_relaxed) && g_log) {
        g_log->warn("LIMIT,record_cap={}", kMaxLogRecords);
        g_log->flush();
    }
    return false;
}

bool IsInsideExe(std::uintptr_t p) {
    return p >= g_exeBase && p < g_exeBase + g_imageSize;
}

bool IsReadable(const void* ptr, std::size_t bytes) {
    if (ptr == nullptr || bytes == 0) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if ((mbi.Protect & PAGE_GUARD) != 0) return false;
    const DWORD baseProtect = mbi.Protect & 0xffu;
    if (baseProtect == PAGE_NOACCESS) return false;
    const auto begin = reinterpret_cast<std::uintptr_t>(ptr);
    const auto end = begin + bytes;
    const auto regionEnd =
        reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return end >= begin && end <= regionEnd;
}

// Reject inaccessible and guard pages first. Catch access violations if the
// game frees an object between the page check and the copy.
std::atomic<std::uint64_t> g_readFaults054{0};
#if defined(_MSC_VER)
bool GuardedCopy054(void* destination, const void* source, std::size_t bytes) {
    __try {
        std::memcpy(destination, source, bytes);
        return true;
    }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return false;
    }
}
#else
bool GuardedCopy054(void* destination, const void* source, std::size_t bytes) {
    std::memcpy(destination, source, bytes);
    return true;
}
#endif

template <typename T>
bool SafeReadValue(std::uintptr_t address, T& out) {
    if (address == 0 ||
        !IsReadable(reinterpret_cast<const void*>(address), sizeof(T))) {
        return false;
    }
    T temp{};
    if (!GuardedCopy054(&temp, reinterpret_cast<const void*>(address), sizeof(T))) {
        ++g_readFaults054;
        return false;
    }
    std::memcpy(&out, &temp, sizeof(T)); // T may be an array (float[3])
    return true;
}

bool CheckExactExecutable() {
    const auto module = GetModuleHandleW(nullptr);
    if (!module) return false;

    g_exeBase = reinterpret_cast<std::uintptr_t>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_exeBase);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        g_exeBase + static_cast<std::uintptr_t>(dos->e_lfanew));
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    g_imageSize = nt->OptionalHeader.SizeOfImage;
    if (nt->FileHeader.TimeDateStamp != kExpectedPeTimestamp) {
        if (g_log) {
            g_log->error(
                "BUILD_MISMATCH,expected_timestamp=0x{:08X},actual_timestamp=0x{:08X}",
                kExpectedPeTimestamp,
                nt->FileHeader.TimeDateStamp);
        }
        return false;
    }

    if (g_log) {
        g_log->info(
            "BUILD_OK,base=0x{:016X},image_size=0x{:X},timestamp=0x{:08X}",
            g_exeBase,
            g_imageSize,
            nt->FileHeader.TimeDateStamp);
        g_log->info(
            "EXPECTED_SHA256,085c2f82d1c963c40b3d2d55786661dfee2b18cbbf388a710c00fa76c5e9bb45");
        g_log->info(
            "STATIC_CANDIDATE,registered_table_ptr_slot=0x{:016X},record_size=0x{:X},record_count={},record_source_off=0x30,record_key_off=0x00",
            g_exeBase + kRvaRegisteredSourceTablePtr,
            kRegisteredSourceRecordSize,
            kRegisteredSourceCount);
    }
    return true;
}

bool InstallOne(std::uintptr_t rva, void* hook, void** original, const char* name) {
    const auto targetValue = g_exeBase + rva;
    if (!IsInsideExe(targetValue)) {
        if (g_log) g_log->error("HOOK_RANGE_FAIL,{},rva=0x{:X}", name, rva);
        return false;
    }
    void* target = reinterpret_cast<void*>(targetValue);
    const auto created = MH_CreateHook(target, hook, original);
    if (created != MH_OK && created != MH_ERROR_ALREADY_CREATED) {
        if (g_log) g_log->error(
            "HOOK_CREATE_FAIL,{},status={}", name, static_cast<int>(created));
        return false;
    }
    const auto enabled = MH_EnableHook(target);
    if (enabled != MH_OK && enabled != MH_ERROR_ENABLED) {
        if (g_log) g_log->error(
            "HOOK_ENABLE_FAIL,{},status={}", name, static_cast<int>(enabled));
        return false;
    }
    if (g_log) g_log->info("HOOK_OK,{},address=0x{:016X}", name, targetValue);
    return true;
}

// Source-voice submission diagnostics. Leave Wwise PCM storage unchanged.
struct Buffer040 {
    std::uintptr_t header=0, pcm=0, node=0, wrapper=0, context=0, a8=0, a148=0;
    std::uint32_t mask=0, playing=0, reads=0;
    std::uint16_t stride=0, frames=0;
};
struct Event040 {
    std::uint64_t seq=0, call=0, tick=0, session=0, group=0;
    std::uint32_t tid=0, kind=0, phase=0, matches=0;
    std::uintptr_t caller=0, owner=0, body=0;
    Buffer040 src{}, dst{};
    std::uintptr_t input=0, ring=0, gate=0;
    std::uint32_t channels=0, ready=0, bytes=0, processed=0;
    std::uint16_t write=0, read=0, frames=0;
    long result=0;
};
std::atomic<bool> g_capture040{false};
std::atomic<std::uint64_t> g_session040{0}, g_call040{0}, g_seq040{0}, g_drop040{0}, g_budget040{0};
std::atomic_flag g_queueLock040=ATOMIC_FLAG_INIT;
constexpr std::size_t kQueue040=16384;
std::array<Event040,kQueue040> g_queue040{};
std::size_t g_head040=0, g_tail040=0, g_count040=0;
Buffer040 ReadBuffer040(std::uintptr_t h, bool identity=true) {
    Buffer040 b{}; b.header=h; if (!h) return b;
    if (SafeReadValue(h,b.pcm)) b.reads|=1;
    if (SafeReadValue(h+8,b.mask)) b.reads|=2;
    if (SafeReadValue(h+0x10,b.stride)) b.reads|=4;
    if (SafeReadValue(h+0x12,b.frames)) b.reads|=8;
    if (!identity) return b;
    if (SafeReadValue(h+0x40,b.node)) b.reads|=16;
    if (b.node && SafeReadValue(b.node+0x10,b.wrapper)) b.reads|=32;
    if (b.wrapper && SafeReadValue(b.wrapper+0x18,b.context)) b.reads|=64;
    if (b.context && SafeReadValue(b.context+0x70,b.playing)) b.reads|=128;
    if (b.context && SafeReadValue(b.context+0xA8,b.a8)) b.reads|=256;
    if (b.context && SafeReadValue(b.context+0x148,b.a148)) b.reads|=512;
    return b;
}
void Queue040(Event040 e) {
    LARGE_INTEGER q{}; QueryPerformanceCounter(&q); e.tick=q.QuadPart;
    e.tid=GetCurrentThreadId(); e.seq=g_seq040.fetch_add(1)+1;
    if (g_queueLock040.test_and_set(std::memory_order_acquire)) { ++g_drop040; return; }
    if (g_count040==kQueue040) ++g_drop040;
    else { g_queue040[g_head040]=e; g_head040=(g_head040+1)%kQueue040; ++g_count040; }
    g_queueLock040.clear(std::memory_order_release);
}
thread_local std::uint64_t g_outputGroup041=0;
struct Scope040 {
    Event040 e{}; std::uintptr_t src=0,dst=0; bool enabled=false;
    Scope040(std::uint32_t kind,std::uintptr_t caller,std::uintptr_t owner,
        std::uintptr_t source=0,std::uintptr_t destination=0):src(source),dst(destination) {
        if (!g_capture040.load(std::memory_order_relaxed)) return;
        if (g_budget040.fetch_add(1)>=100000) { g_capture040.store(false); return; }
        enabled=true; e.kind=kind; e.caller=caller; e.owner=owner;
        e.session=g_session040.load(); e.call=g_call040.fetch_add(1)+1; e.group=g_outputGroup041;
    }
    void Emit(std::uint32_t phase) {
        if (!enabled) return;
        e.phase=phase; e.src=ReadBuffer040(src,e.kind==1 || e.kind==2); e.dst=ReadBuffer040(dst,false); Queue040(e);
    }
};
void Drain040() {
    if (!g_log) return;
    // Fixed work per listener update; no lock held while formatting/writing.
    for (unsigned i=0;i<4096;++i) {
        Event040 e{};
        if (g_queueLock040.test_and_set(std::memory_order_acquire)) break;
        const bool found=g_count040!=0;
        if (found) { e=g_queue040[g_tail040]; g_tail040=(g_tail040+1)%kQueue040; --g_count040; }
        g_queueLock040.clear(std::memory_order_release);
        if (!found) break;
        g_log->info("B41,seq={},call={},session={},qpc={},tid={},kind={},phase={},caller=0x{:X},owner=0x{:X},body=0x{:X},matches={},group={}",
            e.seq,e.call,e.session,e.tick,e.tid,e.kind,e.phase,e.caller,e.owner,e.body,e.matches,e.group);
        for (unsigned side=0;side<2;++side) {
            const auto& b=side?e.dst:e.src;
            if (!b.header) continue;
            g_log->info("B41_BUFFER,seq={},side={},header=0x{:X},pcm=0x{:X},mask={},stride={},frames={},reads={},node=0x{:X},wrapper=0x{:X},context=0x{:X},playing={},a8=0x{:X},a148=0x{:X}",
                e.seq,side,b.header,b.pcm,b.mask,b.stride,b.frames,b.reads,b.node,b.wrapper,b.context,b.playing,b.a8,b.a148);
        }
        if (e.kind>=4) g_log->info("B41_SINK,seq={},input=0x{:X},ring=0x{:X},gate=0x{:X},channels={},ready={},write={},read={},frames={},processed={},bytes={},result={}",
            e.seq,e.input,e.ring,e.gate,e.channels,e.ready,e.write,e.read,e.frames,e.processed,e.bytes,e.result);
    }
}
void Control040() {
    static bool prior=false, reported=false;
    static ULONGLONG until=0;
    const bool down=AudioKey062(VK_F6);
    const auto now=GetTickCount64();
    if (down && !prior) {
        if (g_capture040.load()) g_capture040.store(false);
        else if (!reported) {
            ++g_session040; g_budget040.store(0); until=now+20000;
            g_capture040.store(true); reported=true;
            LARGE_INTEGER hz{}; QueryPerformanceFrequency(&hz);
            if(g_log) g_log->info("B41_START,session={},qpc_hz={},duration_ms=20000",g_session040.load(),hz.QuadPart);
        }
    }
    prior=down;
    if (reported && now>=until) g_capture040.store(false);
    Drain040();
    if (reported && !g_capture040.load()) {
        if(g_log) { g_log->info("B41_STOP,session={},calls={},queue_drops_total={}",g_session040.load(),g_budget040.load(),g_drop040.load()); g_log->flush(); }
        reported=false;
    }
}
using Producer040=std::uint64_t(__fastcall*)(std::int64_t);
Producer040 g_producer040=nullptr, g_silenceProducer040=nullptr;
void ReadSink040(Event040& e,std::uintptr_t sink,bool retainRing) {
    SafeReadValue(sink+0x20,e.input); SafeReadValue(sink+0x32,e.frames);
    SafeReadValue(sink+0x58,e.channels); SafeReadValue(sink+0x80,e.write);
    SafeReadValue(sink+0x82,e.read); SafeReadValue(sink+0xC8,e.ready);
    SafeReadValue(sink+8,e.processed); SafeReadValue(g_exeBase+0x2B9FA28,e.gate);
    if (!retainRing && e.write<8) SafeReadValue(sink+0x88+8*e.write,e.ring);
}
std::uint64_t RunProducer040(std::int64_t sink,Producer040 original,std::uint32_t kind,std::uintptr_t caller) {
    Scope040 t(kind,caller,static_cast<std::uintptr_t>(sink));
    if(t.enabled) { ReadSink040(t.e,t.e.owner,false); t.Emit(0); }
    const auto result=original(sink);
    if(t.enabled) { ReadSink040(t.e,t.e.owner,true); t.Emit(1); }
    return result;
}
std::uint64_t __fastcall ProducerHook040(std::int64_t sink) {
    // Do not write the final engine mix buffer. Apply peak protection per voice.
    return RunProducer040(sink,g_producer040,4,reinterpret_cast<std::uintptr_t>(_ReturnAddress()));
}
std::uint64_t __fastcall SilenceProducerHook040(std::int64_t sink) {
    return RunProducer040(sink,g_silenceProducer040,5,reinterpret_cast<std::uintptr_t>(_ReturnAddress()));
}

// Caller 0x1403687A0 passes (bus object, sink + 0x20).
// The candidate header offset +0x420 is unverified. Preserve integer return bits.
using Transfer041 = std::uint64_t(__fastcall*)(std::uintptr_t,std::uintptr_t);
using OutputStage041 = void(__fastcall*)(std::uintptr_t);
Transfer041 g_transfer041=nullptr;
OutputStage041 g_outputStage041=nullptr;
std::uint64_t __fastcall TransferHook041(std::uintptr_t bus,std::uintptr_t destinationHeader) {
    Scope040 t(7,reinterpret_cast<std::uintptr_t>(_ReturnAddress()),bus,
        bus ? bus+0x420 : 0,destinationHeader);
    t.Emit(0);
    const auto result=g_transfer041(bus,destinationHeader);
    t.Emit(1);
    return result;
}
void __fastcall OutputStageHook041(std::uintptr_t entry) {
    Scope040 t(8,reinterpret_cast<std::uintptr_t>(_ReturnAddress()),entry);
    const auto prior=g_outputGroup041;
    std::uintptr_t bus=0,sink=0;
    if (t.enabled) {
        SafeReadValue(entry,bus); SafeReadValue(entry+8,sink);
        t.src=bus ? bus+0x420 : 0; t.dst=sink ? sink+0x20 : 0;
        t.e.group=t.e.call; g_outputGroup041=t.e.call;
        if(sink) ReadSink040(t.e,sink,false);
        t.Emit(0);
    }
    g_outputStage041(entry);
    if (t.enabled) {
        if(sink) ReadSink040(t.e,sink,true);
        t.Emit(1);
    }
    g_outputGroup041=prior;
}

struct SubmitBuffer039 {
    std::uint32_t flags;
    std::uint32_t audioBytes;
    const unsigned char* audioData;
    std::uint32_t playBegin;
    std::uint32_t playLength;
    std::uint32_t loopBegin;
    std::uint32_t loopLength;
    std::uint32_t loopCount;
    void* context;
};
static_assert(sizeof(SubmitBuffer039) == 48, "Expected x64 XAUDIO2_BUFFER layout");
static_assert(offsetof(SubmitBuffer039, audioData) == 8, "PCM pointer offset");
static_assert(offsetof(SubmitBuffer039, context) == 40, "Context pointer offset");
using SubmitFn039 = long (__fastcall*)(void*, const SubmitBuffer039*, const void*);
std::atomic<SubmitFn039> g_submitOriginal039{nullptr};
std::atomic<std::uintptr_t> g_submitTarget039{0};
std::atomic<int> g_submitHookState039{0}; // 0 waiting; 1 installing; 2 active; -1 failed
std::array<std::atomic<std::uintptr_t>, 16> g_observedSinks039{};
std::atomic<std::uint64_t> g_gateZero039{0}, g_gateNonzero039{0}, g_gateUnreadable039{0};
std::atomic<std::uint64_t> g_submitCalls039{0}, g_submitEligible039{0}, g_submitOther039{0};
std::atomic<std::uint64_t> g_muteAttempts039{0}, g_muteAccepted039{0}, g_submitFailed039{0};
std::atomic<std::uint64_t> g_muteEnergy039{0}, g_probeBadPcm039{0};
std::atomic<std::uint32_t> g_mutePeakMicro039{0}, g_lastBytes039{0}, g_lastResult039{0};
std::atomic<std::uintptr_t> g_lastVoice039{0};
// Keep zero PCM alive across asynchronous source-buffer submissions.
alignas(64) const unsigned char g_silence039[65536] = {};

void RememberSink039(std::uintptr_t sink) {
    for (auto& slot : g_observedSinks039) {
        auto current = slot.load(std::memory_order_acquire);
        if (current == sink) return;
        if (current == 0 && slot.compare_exchange_strong(current, sink)) return;
    }
}

bool IsOurRingBuffer039(void* voice, const SubmitBuffer039& b, const void* wma) {
    if (wma || b.audioBytes == 0 || b.audioBytes > sizeof(g_silence039) ||
        b.audioData == nullptr || b.flags != 0 || b.playBegin != 0 ||
        b.playLength != 0 || b.loopBegin != 0 || b.loopLength != 0 || b.loopCount != 0) return false;
    for (auto& slot : g_observedSinks039) {
        const auto sink = slot.load(std::memory_order_acquire);
        if (!sink) continue;
        std::uintptr_t vt = 0, sourceVoice = 0;
        std::uint32_t channels = 0;
        std::uint16_t blockAlign = 0;
        if (!SafeReadValue(sink, vt) || vt != g_exeBase + 0x21358F0ull ||
            !SafeReadValue(sink + 0x70, sourceVoice) || sourceVoice != reinterpret_cast<std::uintptr_t>(voice) ||
            !SafeReadValue(sink + 0x58, channels) || channels == 0 || channels > 8 ||
            !SafeReadValue(sink + 0xCC, blockAlign) || blockAlign != channels * sizeof(float) ||
            b.audioBytes != static_cast<std::uint32_t>(blockAlign) * 1024u) continue;
        for (unsigned i = 0; i < 8; ++i) {
            std::uintptr_t pcm = 0;
            if (SafeReadValue(sink + 0x88 + i * 8u, pcm) &&
                pcm == reinterpret_cast<std::uintptr_t>(b.audioData)) return true;
        }
    }
    return false;
}

// Separate POD-only SEH helper: a stale buffer must not crash the diagnostic.
bool SamplePeak039(const unsigned char* pcm, std::uint32_t bytes, std::uint32_t* peakMicro) {
    if (!IsReadable(pcm, bytes) || bytes < sizeof(float)) return false;
    __try {
        const auto count = bytes / sizeof(float);
        const auto* samples = reinterpret_cast<const float*>(pcm);
        float peak = 0.0f;
        for (std::uint32_t i = 0; i < count; ++i) {
            const float value = samples[i];
            if (!std::isfinite(value)) return false;
            const float magnitude = std::fabs(value);
            if (magnitude > peak) peak = magnitude;
        }
        *peakMicro = static_cast<std::uint32_t>((std::min)(peak, 16.0f) * 1000000.0f);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

long __fastcall SubmitHook039(void* voice, const SubmitBuffer039* input, const void* wma) {
    g_submitCalls039.fetch_add(1, std::memory_order_relaxed);
    // Published before MH_EnableHook; no fallback fabricated success is allowed.
    const auto original = g_submitOriginal039.load(std::memory_order_acquire);
    SubmitBuffer039 local{};
    const bool eligible = SafeReadValue(reinterpret_cast<std::uintptr_t>(input), local) &&
        IsOurRingBuffer039(voice, local, wma);
    if (eligible) {
        ++g_submitEligible039;
        g_lastVoice039.store(reinterpret_cast<std::uintptr_t>(voice), std::memory_order_relaxed);
        g_lastBytes039.store(local.audioBytes, std::memory_order_relaxed);
    } else ++g_submitOther039;
    Scope040 t(6,reinterpret_cast<std::uintptr_t>(_ReturnAddress()),reinterpret_cast<std::uintptr_t>(voice));
    t.e.input=reinterpret_cast<std::uintptr_t>(local.audioData); t.e.bytes=local.audioBytes;
    t.e.matches=eligible?1u:0u; t.Emit(0);
    const long result = original(voice, input, wma);
    t.e.result=result; t.Emit(1);
    if (eligible) {
        g_lastResult039.store(static_cast<std::uint32_t>(result), std::memory_order_relaxed);
        if (result < 0) g_submitFailed039.fetch_add(1, std::memory_order_relaxed);

    }
    return result;
}

// Drain from the camera/listener bridge, outside the submission callback.
void EnsureSubmitHook039() {
    if (g_submitHookState039.load(std::memory_order_acquire) != 0) return;
    for (auto& slot : g_observedSinks039) {
        const auto sink = slot.load(std::memory_order_acquire);
        if (!sink) continue;
        std::uintptr_t vt = 0, voice = 0, voiceVt = 0, target = 0;
        if (!SafeReadValue(sink, vt) || vt != g_exeBase + 0x21358F0ull ||
            !SafeReadValue(sink + 0x70, voice) || !voice ||
            !SafeReadValue(voice, voiceVt) || !voiceVt ||
            !SafeReadValue(voiceVt + 0xA8, target) || !target) continue;
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<void*>(target), &mbi, sizeof(mbi)) ||
            mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD)) continue;
        const auto protect = mbi.Protect & 0xFFu;
        if (protect != PAGE_EXECUTE && protect != PAGE_EXECUTE_READ &&
            protect != PAGE_EXECUTE_READWRITE && protect != PAGE_EXECUTE_WRITECOPY) continue;
        int expected = 0;
        if (!g_submitHookState039.compare_exchange_strong(expected, 1)) return;
        char module[MAX_PATH]{};
        GetModuleFileNameA(static_cast<HMODULE>(mbi.AllocationBase), module, MAX_PATH);
        const char* leaf = std::strrchr(module, 0x5c);
        if (g_log) g_log->info("SUBMIT_DISCOVERY,sink=0x{:X},voice=0x{:X},voice_vtable=0x{:X},target=0x{:X},module={}",
            sink, voice, voiceVt, target, leaf ? leaf + 1 : module);
        void* trampoline = nullptr;
        const auto created = MH_CreateHook(reinterpret_cast<void*>(target),
            reinterpret_cast<void*>(&SubmitHook039), &trampoline);
        if (created != MH_OK || !trampoline) {
            if (g_log) { g_log->error("SUBMIT_HOOK_CREATE_FAILED,status={}", static_cast<int>(created)); g_log->flush(); }
            g_submitHookState039.store(-1, std::memory_order_release);
            return;
        }
        g_submitOriginal039.store(reinterpret_cast<SubmitFn039>(trampoline), std::memory_order_release);
        g_submitTarget039.store(target, std::memory_order_release);
        const auto enabled = MH_EnableHook(reinterpret_cast<void*>(target));
        g_submitHookState039.store(enabled == MH_OK ? 2 : -1, std::memory_order_release);
        if (g_log) { g_log->info("SUBMIT_HOOK_INSTALL,state={},enable_status={}",
            enabled == MH_OK ? 2 : -1, static_cast<int>(enabled)); g_log->flush(); }
        return;
    }
}

void LogSubmitSummary039() {
    if (!g_log) return;
    g_log->info("SUBMIT_SUMMARY,hook_state={},calls={},eligible={},other={},mute_attempts={},mute_accepted={},submit_failed={},mute_input_nonzero_blocks={},mute_input_peak_micro={},pcm_probe_failed={},last_bytes={},last_result=0x{:08X},last_voice=0x{:X},gate_zero_calls={},gate_nonzero_calls={},gate_unreadable_calls={}",
        g_submitHookState039.load(), g_submitCalls039.load(), g_submitEligible039.load(),
        g_submitOther039.load(), g_muteAttempts039.load(), g_muteAccepted039.load(),
        g_submitFailed039.load(), g_muteEnergy039.load(), g_mutePeakMicro039.load(),
        g_probeBadPcm039.load(), g_lastBytes039.load(), g_lastResult039.load(), g_lastVoice039.load(),
        g_gateZero039.load(), g_gateNonzero039.load(), g_gateUnreadable039.load());
}

bool ReadU32At(std::uintptr_t address, std::uint32_t& value) {
    value = 0;
    if (address == 0 || !IsReadable(reinterpret_cast<const void*>(address), sizeof(value))) {
        return false;
    }
    std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value));
    return true;
}

bool ReadU64At(std::uintptr_t address, std::uint64_t& value) {
    value = 0;
    if (address == 0 || !IsReadable(reinterpret_cast<const void*>(address), sizeof(value))) {
        return false;
    }
    std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value));
    return true;
}

bool ReadPtrAt(std::uintptr_t address, std::uintptr_t& value) {
    value = 0;
    if (address == 0 || !IsReadable(reinterpret_cast<const void*>(address), sizeof(value))) {
        return false;
    }
    std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value));
    return true;
}

bool ReadBodySource(std::uintptr_t body, std::uint32_t& source) {
    return body != 0 && ReadU32At(body + 0x80, source);
}

std::uintptr_t RegisteredTableBase() {
    if (g_exeBase == 0) return 0;
    // This pointer slot is inside the executable image.
    return *reinterpret_cast<const std::uintptr_t*>(
        g_exeBase + kRvaRegisteredSourceTablePtr);
}

bool InspectRecordCandidate(
    std::uint32_t source,
    std::uintptr_t& tableBase,
    std::uintptr_t& candidate,
    std::uint32_t& storedSource,
    std::uint64_t& storedKey)
{
    tableBase = 0;
    candidate = 0;
    storedSource = 0;
    storedKey = 0;
    if (source == 0 || g_exeBase == 0) return false;

    tableBase = RegisteredTableBase();
    if (tableBase == 0) return false;
    candidate = tableBase +
        static_cast<std::uintptr_t>(source & 0xffu) * kRegisteredSourceRecordSize;

    if (!IsReadable(reinterpret_cast<const void*>(candidate), 0x34)) return false;
    std::uint32_t storedKey32 = 0;
    std::memcpy(&storedKey32, reinterpret_cast<const void*>(candidate + 0x00), sizeof(storedKey32));
    std::memcpy(&storedSource, reinterpret_cast<const void*>(candidate + 0x30), sizeof(storedSource));
    storedKey = static_cast<std::uint64_t>(storedKey32);
    return true;
}

bool ResolveRecordForSource(
    std::uint32_t source,
    std::uintptr_t& record,
    std::uint64_t& objectKey)
{
    record = 0;
    objectKey = 0;
    std::uintptr_t tableBase = 0;
    std::uintptr_t candidate = 0;
    std::uint32_t storedSource = 0;
    std::uint64_t storedKey = 0;
    if (!InspectRecordCandidate(source, tableBase, candidate, storedSource, storedKey)) {
        return false;
    }
    if (storedSource != source) return false;

    record = candidate;
    objectKey = storedKey;
    return true;
}

std::uint32_t FindRecordsByObjectKey(
    std::uint64_t objectKey,
    std::uint32_t& source,
    std::uintptr_t& record)
{
    source = 0;
    record = 0;
    if (objectKey == 0 || g_exeBase == 0) return 0;

    const auto base = RegisteredTableBase();
    if (base == 0 || !IsReadable(
            reinterpret_cast<const void*>(base),
            kRegisteredSourceCount * kRegisteredSourceRecordSize)) return 0;

    std::uint32_t matches = 0;
    for (std::size_t i = 0; i < kRegisteredSourceCount; ++i) {
        const auto candidate =
            base + static_cast<std::uintptr_t>(i) * kRegisteredSourceRecordSize;
        std::uint32_t key = 0;
        std::uint32_t candidateSource = 0;
        std::memcpy(&key, reinterpret_cast<const void*>(candidate + 0x00), sizeof(key));
        if (key != static_cast<std::uint32_t>(objectKey)) continue;
        std::memcpy(&candidateSource, reinterpret_cast<const void*>(candidate + 0x30), sizeof(candidateSource));
        if (candidateSource == 0) continue;

        ++matches;
        if (matches == 1) {
            source = candidateSource;
            record = candidate;
        }
    }
    return matches;
}

RecentFoxSlot* FindFoxSlot(std::uint32_t source, bool create) {
    if (source == 0) return nullptr;
    const auto start = Hash32(source, kRecentFoxSlots - 1);
    RecentFoxSlot* fallback = nullptr;
    std::uint64_t oldest = UINT64_MAX;

    for (std::size_t probe = 0; probe < 8; ++probe) {
        auto& slot = g_recentFox[(start + probe) & (kRecentFoxSlots - 1)];
        auto existing = slot.source.load(std::memory_order_acquire);
        if (existing == source) return &slot;
        if (existing == 0 && create) {
            std::uint32_t expected = 0;
            if (slot.source.compare_exchange_strong(
                    expected, source,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire))
            {
                return &slot;
            }
            if (expected == source) return &slot;
        }
        if (create) {
            const auto activity = slot.eventTick.load(std::memory_order_relaxed);
            if (activity < oldest) {
                oldest = activity;
                fallback = &slot;
            }
        }
    }

    if (create && fallback) {
        fallback->body.store(0, std::memory_order_relaxed);
        fallback->eventId.store(0, std::memory_order_relaxed);
        fallback->eventTick.store(0, std::memory_order_relaxed);
        fallback->transformTick.store(0, std::memory_order_relaxed);
        fallback->transformLogTick.store(0, std::memory_order_relaxed);
        fallback->source.store(source, std::memory_order_release);
        return fallback;
    }
    return nullptr;
}

void RememberFoxEvent(
    std::uint32_t source,
    std::uintptr_t body,
    std::uint32_t eventId,
    std::uint64_t tick)
{
    auto* slot = FindFoxSlot(source, true);
    if (!slot) return;
    slot->body.store(body, std::memory_order_relaxed);
    slot->eventId.store(eventId, std::memory_order_relaxed);
    slot->eventTick.store(tick, std::memory_order_release);
}

bool LookupFox(
    std::uint32_t source,
    std::uintptr_t& body,
    std::uint32_t& eventId,
    std::uint64_t now)
{
    body = 0;
    eventId = 0;
    auto* slot = FindFoxSlot(source, false);
    if (!slot) return false;
    const auto tick = slot->eventTick.load(std::memory_order_acquire);
    if (tick == 0 || (now > tick && now - tick > kRecentIdentityTtlMs)) {
        return false;
    }
    body = slot->body.load(std::memory_order_relaxed);
    eventId = slot->eventId.load(std::memory_order_relaxed);
    return true;
}

void RememberFoxTransform(
    std::uint32_t source,
    std::uintptr_t body,
    const std::uint32_t (&payload)[8],
    std::uint64_t tick)
{
    auto* slot = FindFoxSlot(source, true);
    if (!slot) return;
    slot->body.store(body, std::memory_order_relaxed);
    for (std::size_t i = 0; i < 8; ++i) {
        slot->transformBits[i].store(payload[i], std::memory_order_relaxed);
    }
    slot->transformTick.store(tick, std::memory_order_release);
}

bool ShouldEmitTransform(std::uint32_t source, std::uint64_t now) {
    auto* slot = FindFoxSlot(source, false);
    if (!slot) return false;
    auto prior = slot->transformLogTick.load(std::memory_order_relaxed);
    for (;;) {
        if (now >= prior && now - prior < kTransformLogIntervalMs) return false;
        if (slot->transformLogTick.compare_exchange_weak(
                prior, now,
                std::memory_order_relaxed,
                std::memory_order_relaxed))
        {
            return true;
        }
    }
}


bool ShouldEmitBodyTransform(std::uintptr_t body, std::uint64_t now) {
    if (body == 0) return false;
    const auto start = HashPtr(body, g_bodyTransformGate.size() - 1);
    for (std::size_t probe = 0; probe < 8; ++probe) {
        auto& slot = g_bodyTransformGate[(start + probe) & (g_bodyTransformGate.size() - 1)];
        auto existing = slot.body.load(std::memory_order_acquire);
        if (existing == body) {
            auto prior = slot.tick.load(std::memory_order_relaxed);
            for (;;) {
                if (now >= prior && now - prior < kTransformLogIntervalMs) return false;
                if (slot.tick.compare_exchange_weak(
                        prior, now,
                        std::memory_order_relaxed,
                        std::memory_order_relaxed)) return true;
            }
        }
        if (existing == 0) {
            std::uintptr_t expected = 0;
            if (slot.body.compare_exchange_strong(
                    expected, body,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire) || expected == body)
            {
                slot.tick.store(now, std::memory_order_relaxed);
                return true;
            }
        }
    }
    return false;
}

RecentKeySlot* FindKeySlot(std::uint64_t key, bool create) {
    if (key == 0) return nullptr;
    const auto start = Hash64(key, kRecentKeySlots - 1);
    RecentKeySlot* fallback = nullptr;
    std::uint64_t oldest = UINT64_MAX;

    for (std::size_t probe = 0; probe < 8; ++probe) {
        auto& slot = g_recentKeys[(start + probe) & (kRecentKeySlots - 1)];
        auto existing = slot.key.load(std::memory_order_acquire);
        if (existing == key) return &slot;
        if (existing == 0 && create) {
            std::uint64_t expected = 0;
            if (slot.key.compare_exchange_strong(
                    expected, key,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire))
            {
                return &slot;
            }
            if (expected == key) return &slot;
        }
        if (create) {
            const auto tick = slot.tick.load(std::memory_order_relaxed);
            if (tick < oldest) {
                oldest = tick;
                fallback = &slot;
            }
        }
    }

    if (create && fallback) {
        fallback->tick.store(0, std::memory_order_relaxed);
        fallback->eventId.store(0, std::memory_order_relaxed);
        fallback->source.store(0, std::memory_order_relaxed);
        fallback->body.store(0, std::memory_order_relaxed);
        fallback->record.store(0, std::memory_order_relaxed);
        fallback->recordMatches.store(0, std::memory_order_relaxed);
        fallback->postResult.store(0, std::memory_order_relaxed);
        fallback->lookupTraceObject.store(0, std::memory_order_relaxed);
        fallback->key.store(key, std::memory_order_release);
        return fallback;
    }
    return nullptr;
}

void RememberKey(
    std::uint64_t key,
    std::uint32_t eventId,
    std::uint32_t source,
    std::uintptr_t body,
    std::uintptr_t record,
    std::uint32_t recordMatches,
    std::uint64_t tick)
{
    auto* slot = FindKeySlot(key, true);
    if (!slot) return;
    slot->eventId.store(eventId, std::memory_order_relaxed);
    slot->source.store(source, std::memory_order_relaxed);
    slot->body.store(body, std::memory_order_relaxed);
    slot->record.store(record, std::memory_order_relaxed);
    slot->recordMatches.store(recordMatches, std::memory_order_relaxed);
    slot->lookupTraceObject.store(0, std::memory_order_relaxed);
    slot->tick.store(tick, std::memory_order_release);
}

bool LookupKey(std::uint64_t key, IdentityMeta& meta, std::uint64_t now) {
    auto* slot = FindKeySlot(key, false);
    if (!slot) return false;
    const auto tick = slot->tick.load(std::memory_order_acquire);
    if (tick == 0 || (now > tick && now - tick > kRecentIdentityTtlMs)) {
        return false;
    }
    meta.key = key;
    meta.eventId = slot->eventId.load(std::memory_order_relaxed);
    meta.source = slot->source.load(std::memory_order_relaxed);
    meta.body = slot->body.load(std::memory_order_relaxed);
    meta.record = slot->record.load(std::memory_order_relaxed);
    meta.recordMatches = slot->recordMatches.load(std::memory_order_relaxed);
    meta.postResult = slot->postResult.load(std::memory_order_relaxed);
    return true;
}

void UpdateKeyPostResult(std::uint64_t key, std::int32_t result) {
    auto* slot = FindKeySlot(key, false);
    if (slot) slot->postResult.store(result, std::memory_order_release);
}

PendingFoxPost* FindPendingFoxPost(std::uint32_t eventId) {
    for (std::size_t i = g_pendingFoxDepth; i > 0; --i) {
        auto& pending = g_pendingFoxPosts[i - 1];
        if (pending.eventId == eventId && pending.body != 0) return &pending;
    }
    return nullptr;
}

bool ShouldTraceFirstLookup(std::uint64_t key, std::uintptr_t object) {
    if (key == 0 || object == 0) return false;
    auto* slot = FindKeySlot(key, false);
    if (!slot) return false;
    std::uintptr_t expected = 0;
    if (slot->lookupTraceObject.compare_exchange_strong(
            expected, object,
            std::memory_order_acq_rel,
            std::memory_order_acquire))
    {
        g_lookupTraceRows.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    return false;
}

RecentObjectSlot* FindObjectSlot(std::uintptr_t object, bool create) {
    if (object == 0) return nullptr;
    const auto start = HashPtr(object, kRecentObjectSlots - 1);
    RecentObjectSlot* fallback = nullptr;
    std::uint64_t oldest = UINT64_MAX;

    for (std::size_t probe = 0; probe < 8; ++probe) {
        auto& slot = g_recentObjects[(start + probe) & (kRecentObjectSlots - 1)];
        auto existing = slot.object.load(std::memory_order_acquire);
        if (existing == object) return &slot;
        if (existing == 0 && create) {
            std::uintptr_t expected = 0;
            if (slot.object.compare_exchange_strong(
                    expected, object,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire))
            {
                return &slot;
            }
            if (expected == object) return &slot;
        }
        if (create) {
            const auto tick = slot.tick.load(std::memory_order_relaxed);
            if (tick < oldest) {
                oldest = tick;
                fallback = &slot;
            }
        }
    }

    if (create && fallback) {
        fallback->tick.store(0, std::memory_order_relaxed);
        fallback->key.store(0, std::memory_order_relaxed);
        fallback->eventId.store(0, std::memory_order_relaxed);
        fallback->source.store(0, std::memory_order_relaxed);
        fallback->body.store(0, std::memory_order_relaxed);
        fallback->record.store(0, std::memory_order_relaxed);
        fallback->object.store(object, std::memory_order_release);
        return fallback;
    }
    return nullptr;
}

void RememberObject(
    std::uintptr_t object,
    const IdentityMeta& meta,
    std::uint64_t tick)
{
    auto* slot = FindObjectSlot(object, true);
    if (!slot) return;
    slot->key.store(meta.key, std::memory_order_relaxed);
    slot->eventId.store(meta.eventId, std::memory_order_relaxed);
    slot->source.store(meta.source, std::memory_order_relaxed);
    slot->body.store(meta.body, std::memory_order_relaxed);
    slot->record.store(meta.record, std::memory_order_relaxed);
    slot->tick.store(tick, std::memory_order_release);
}

bool LookupObject(
    std::uintptr_t object,
    IdentityMeta& meta,
    std::uint64_t now)
{
    auto* slot = FindObjectSlot(object, false);
    if (!slot) return false;
    const auto tick = slot->tick.load(std::memory_order_acquire);
    if (tick == 0 || (now > tick && now - tick > kRecentIdentityTtlMs)) {
        return false;
    }
    meta.key = slot->key.load(std::memory_order_relaxed);
    meta.eventId = slot->eventId.load(std::memory_order_relaxed);
    meta.source = slot->source.load(std::memory_order_relaxed);
    meta.body = slot->body.load(std::memory_order_relaxed);
    meta.record = slot->record.load(std::memory_order_relaxed);
    return true;
}

RecentPlayingSlot* FindPlayingSlot(std::uint32_t playingId, bool create) {
    if (playingId == 0) return nullptr;
    const auto start = Hash32(playingId, kRecentPlayingSlots - 1);
    RecentPlayingSlot* fallback = nullptr;
    std::uint64_t oldest = UINT64_MAX;

    for (std::size_t probe = 0; probe < 8; ++probe) {
        auto& slot = g_recentPlaying[(start + probe) & (kRecentPlayingSlots - 1)];
        auto existing = slot.playingId.load(std::memory_order_acquire);
        if (existing == playingId) return &slot;
        if (existing == 0 && create) {
            std::uint32_t expected = 0;
            if (slot.playingId.compare_exchange_strong(
                    expected, playingId,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire))
            {
                return &slot;
            }
            if (expected == playingId) return &slot;
        }
        if (create) {
            const auto tick = slot.tick.load(std::memory_order_relaxed);
            if (tick < oldest) {
                oldest = tick;
                fallback = &slot;
            }
        }
    }

    if (create && fallback) {
        fallback->tick.store(0, std::memory_order_relaxed);
        fallback->key.store(0, std::memory_order_relaxed);
        fallback->eventId.store(0, std::memory_order_relaxed);
        fallback->source.store(0, std::memory_order_relaxed);
        fallback->body.store(0, std::memory_order_relaxed);
        fallback->record.store(0, std::memory_order_relaxed);
        fallback->playingId.store(playingId, std::memory_order_release);
        return fallback;
    }
    return nullptr;
}

void RememberPlaying(
    std::uint32_t playingId,
    const IdentityMeta& meta,
    std::uint64_t tick)
{
    auto* slot = FindPlayingSlot(playingId, true);
    if (!slot) return;
    slot->key.store(meta.key, std::memory_order_relaxed);
    slot->eventId.store(meta.eventId, std::memory_order_relaxed);
    slot->source.store(meta.source, std::memory_order_relaxed);
    slot->body.store(meta.body, std::memory_order_relaxed);
    slot->record.store(meta.record, std::memory_order_relaxed);
    slot->tick.store(tick, std::memory_order_release);
}

bool LookupPlaying(
    std::uint32_t playingId,
    IdentityMeta& meta,
    std::uint64_t now)
{
    auto* slot = FindPlayingSlot(playingId, false);
    if (!slot) return false;
    const auto tick = slot->tick.load(std::memory_order_acquire);
    if (tick == 0 || (now > tick && now - tick > kRecentIdentityTtlMs)) {
        return false;
    }
    meta.key = slot->key.load(std::memory_order_relaxed);
    meta.eventId = slot->eventId.load(std::memory_order_relaxed);
    meta.source = slot->source.load(std::memory_order_relaxed);
    meta.body = slot->body.load(std::memory_order_relaxed);
    meta.record = slot->record.load(std::memory_order_relaxed);
    return true;
}


bool SameIdentity(const IdentityMeta& a, const IdentityMeta& b) {
    if (a.key == 0 || b.key == 0) return false;
    return a.key == b.key &&
           a.eventId == b.eventId &&
           a.source == b.source &&
           a.body == b.body &&
           a.record == b.record;
}


float FloatFromBits(std::uint32_t bits) {
    float value = 0.0f;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

std::uint32_t FloatBits(float value) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

bool PublishLatestListenerTransform(std::int64_t ownerValue) {
    const auto owner = static_cast<std::uintptr_t>(ownerValue);
    if (owner == 0 ||
        !IsReadable(reinterpret_cast<const void*>(owner + 0x60),
                    sizeof(std::uintptr_t)))
    {
        return false;
    }

    std::uintptr_t listener = 0;
    std::memcpy(&listener,
                reinterpret_cast<const void*>(owner + 0x60),
                sizeof(listener));
    if (listener == 0 ||
        !IsReadable(reinterpret_cast<const void*>(listener + 0x40),
                    8 * sizeof(std::uint32_t)))
    {
        return false;
    }

    std::uint32_t payload[8]{};
    std::memcpy(payload,
                reinterpret_cast<const void*>(listener + 0x40),
                sizeof(payload));
    for (std::size_t i = 0; i < 8; ++i) {
        g_latestListenerTransformBits[i].store(
            payload[i], std::memory_order_relaxed);
    }
    g_latestListenerTransformTick.store(
        GetTickCount64(), std::memory_order_release);
    return true;
}

bool ReadLatestListenerTransform(std::uint32_t (&payload)[8]) {
    const auto tick =
        g_latestListenerTransformTick.load(std::memory_order_acquire);
    if (tick == 0) return false;
    const auto now = GetTickCount64();
    if (now > tick && now - tick > kListenerFreshMs) return false;

    for (std::size_t i = 0; i < 8; ++i) {
        payload[i] =
            g_latestListenerTransformBits[i].load(std::memory_order_relaxed);
    }
    return true;
}

bool ReadFoxTransformForIdentity(
    const IdentityMeta& meta,
    std::uint32_t (&payload)[8])
{
    if (meta.source == 0 || meta.body == 0) return false;
    auto* slot = FindFoxSlot(meta.source, false);
    if (!slot) return false;
    if (slot->body.load(std::memory_order_acquire) != meta.body) return false;
    if (slot->transformTick.load(std::memory_order_acquire) == 0) return false;

    for (std::size_t i = 0; i < 8; ++i) {
        payload[i] =
            slot->transformBits[i].load(std::memory_order_relaxed);
    }
    return true;
}

bool ComputeDirectGeometry(
    const IdentityMeta& meta,
    float& outAzimuthDeg,
    float& outElevationDeg,
    float& outDistance,
    const float* nativeWorld050=nullptr)
{
    std::uint32_t listener[8]{};
    if (!ReadLatestListenerTransform(listener)) {
        g_directHrtfNoListener.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    std::uint32_t source[8]{};
    if(nativeWorld050) {
        for(unsigned i=0;i<3;++i)source[4+i]=FloatBits(nativeWorld050[i]);
    } else if (!ReadFoxTransformForIdentity(meta, source)) {
        g_directHrtfNoTransform.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    double qx = FloatFromBits(listener[0]);
    double qy = FloatFromBits(listener[1]);
    double qz = FloatFromBits(listener[2]);
    double qw = FloatFromBits(listener[3]);
    const double qnorm =
        std::sqrt(qx*qx + qy*qy + qz*qz + qw*qw);
    if (!std::isfinite(qnorm) || qnorm < 0.5 || qnorm > 1.5) {
        g_directHrtfNoListener.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    qx /= qnorm; qy /= qnorm; qz /= qnorm; qw /= qnorm;

    const double lx = FloatFromBits(listener[4]);
    const double ly = FloatFromBits(listener[5]);
    const double lz = FloatFromBits(listener[6]);
    const double sx = FloatFromBits(source[4]);
    const double sy = FloatFromBits(source[5]);
    const double sz = FloatFromBits(source[6]);

    const double dx = sx - lx;
    const double dy = sy - ly;
    const double dz = sz - lz;

    // Inverse listener rotation: -localX is right, -localZ is forward.
    const double ix = -qx, iy = -qy, iz = -qz;
    const double tx = 2.0 * (iy*dz - iz*dy);
    const double ty = 2.0 * (iz*dx - ix*dz);
    const double tz = 2.0 * (ix*dy - iy*dx);
    const double localX = dx + qw*tx + (iy*tz - iz*ty);
    const double localY = dy + qw*ty + (iz*tx - ix*tz);
    const double localZ = dz + qw*tz + (ix*ty - iy*tx);

    const double right = -localX;
    const double forward = -localZ;
    const double horizontal =
        std::sqrt(right*right + forward*forward);
    if (!std::isfinite(horizontal) || horizontal < 1.0e-9) {
        return false;
    }

    outAzimuthDeg = static_cast<float>(
        std::atan2(right, forward) * kRadiansToDegrees);
    outElevationDeg = static_cast<float>(
        std::atan2(localY, horizontal) * kRadiansToDegrees);
    outDistance = static_cast<float>(
        std::sqrt(dx*dx + dy*dy + dz*dz));
    return std::isfinite(outAzimuthDeg) &&
           std::isfinite(outElevationDeg) &&
           std::isfinite(outDistance);
}

BinauralHistoryState& GetBinauralHistory(
    std::uintptr_t node,
    std::uintptr_t destination)
{
    // Hash both pointers to avoid collisions from regularly spaced render nodes.
    const std::uint64_t key =
        ((static_cast<std::uint64_t>(node >> 4) * 0x9E3779B97F4A7C15ull) ^
         (static_cast<std::uint64_t>(destination >> 4) * 0xC2B2AE3D27D4EB4Full)) >> 54;
    // Probe eight slots and replace the least recently used.
    // Separate histories prevent unrelated voices from resetting each other.
    static thread_local std::uint64_t clock056 = 0;
    ++clock056;
    const std::size_t base056 = static_cast<std::size_t>(key) & (kBinauralStateSlots - 1);
    BinauralHistoryState* victim056 = nullptr;
    for (std::size_t probe = 0; probe < 8; ++probe) {
        auto& candidate = g_binauralHistory[(base056 + probe) & (kBinauralStateSlots - 1)];
        if (candidate.node == node && candidate.destination == destination) {
            candidate.lastUse056 = clock056;
            return candidate;
        }
        if (victim056 == nullptr || candidate.lastUse056 < victim056->lastUse056) victim056 = &candidate;
    }
    auto& state = *victim056;
    state.lastUse056 = clock056;

    if (state.node != node || state.destination != destination) {
        state.node = node;
        state.destination = destination;
        state.writeIndex = 0;
        state.priorAzimuthDeg = 0.0f;
        state.lowHrtfLeft = 0.0f;
        state.lowHrtfRight = 0.0f;
        state.lowDryLeft = 0.0f;
        state.lowDryRight = 0.0f;
        state.initialized = false;
        std::memset(state.history, 0, sizeof(state.history));
        g_binauralHistoryResets.fetch_add(1, std::memory_order_relaxed);
    }
    return state;
}

void BuildStereoEarCoefficientBlocks(
    const float* original,
    float* left,
    float* right)
{
    std::memcpy(left, original, 16 * sizeof(float));
    std::memcpy(right, original, 16 * sizeof(float));

    for (int pass = 0; pass < 2; ++pass) {
        const int half = pass * 8;
        const float l = original[half + 0];
        const float r = original[half + 1];
        const float centered =
            std::sqrt((l*l + r*r) * 0.5f);

        left[half + 0] = centered;
        left[half + 1] = 0.0f;
        right[half + 0] = 0.0f;
        right[half + 1] = centered;
    }
}

void BuildInterpolatedMeasuredHrir360(
    float angleDeg,
    float* leftFilter,
    float* rightFilter)
{
    while (angleDeg < -180.0f) angleDeg += 360.0f;
    while (angleDeg >  180.0f) angleDeg -= 360.0f;

    const float position =
        (angleDeg - KEMAR360::kMinAngleDeg) /
        KEMAR360::kStepDeg;
    std::uint32_t low =
        static_cast<std::uint32_t>(std::floor(position));
    if (low >= KEMAR360::kDirectionCount - 1) {
        low = static_cast<std::uint32_t>(KEMAR360::kDirectionCount - 1);
    }
    const std::uint32_t high =
        (low + 1u < KEMAR360::kDirectionCount) ? low + 1u : low;
    float alpha = position - static_cast<float>(low);
    if (high == low) alpha = 0.0f;
    const float oneMinus = 1.0f - alpha;

    for (std::size_t tap = 0; tap < KEMAR360::kTapCount; ++tap) {
        leftFilter[tap] =
            KEMAR360::kHrir[low][0][tap] * oneMinus +
            KEMAR360::kHrir[high][0][tap] * alpha;
        rightFilter[tap] =
            KEMAR360::kHrir[low][1][tap] * oneMinus +
            KEMAR360::kHrir[high][1][tap] * alpha;
    }
}

// Interpolate azimuth within each ring, then between elevation rings.
void AccumulateRing059(std::size_t ring,float az360,float weight,float* leftFilter,float* rightFilter,float emphasis) {
    if(weight<=0.0f) return;
    const std::size_t off=HRIRSET::kRingOffset[ring], n=HRIRSET::kRingSize[ring];
    std::size_t j=n-1, next=0; float t=0.0f;
    if(n>1){
        for(std::size_t k=0;k<n;++k){ if(HRIRSET::kAzimuth[off+k]<=az360) j=k; else break; }
        next=(j+1)%n;
        const float a0=HRIRSET::kAzimuth[off+j];
        const float a1=next==0?HRIRSET::kAzimuth[off]+360.0f:HRIRSET::kAzimuth[off+next];
        float a=az360; if(a<a0) a+=360.0f;
        t=(a1>a0)?(a-a0)/(a1-a0):0.0f; t=(std::min)(1.0f,(std::max)(0.0f,t));
    } else { j=0; next=0; }
    const float wa=weight*(1.0f-t), wb=weight*t;
    const float s=(std::min)(1.0f,(std::max)(0.0f,emphasis));
    const float* l0=HRIRSET::kHrir[off+j][0]; const float* r0=HRIRSET::kHrir[off+j][1];
    const float* l1=HRIRSET::kHrir[off+next][0]; const float* r1=HRIRSET::kHrir[off+next][1];
    for(std::size_t tap=0;tap<HRIRSET::kTapCount;++tap){
        leftFilter[tap]+=wa*l0[tap]+wb*l1[tap];
        rightFilter[tap]+=wa*r0[tap]+wb*r1[tap];
    }
    if(s>0.0f){
        // cue emphasis: blend towards the emphasised table (same timing, same average tone).
        const float* el0=HRIRSET::kHrirEmphasis[off+j][0]; const float* er0=HRIRSET::kHrirEmphasis[off+j][1];
        const float* el1=HRIRSET::kHrirEmphasis[off+next][0]; const float* er1=HRIRSET::kHrirEmphasis[off+next][1];
        const float pa=wa*s, pb=wb*s;
        for(std::size_t tap=0;tap<HRIRSET::kTapCount;++tap){
            leftFilter[tap]+=pa*(el0[tap]-l0[tap])+pb*(el1[tap]-l1[tap]);
            rightFilter[tap]+=pa*(er0[tap]-r0[tap])+pb*(er1[tap]-r1[tap]);
        }
    }
}
// Use configured emphasis for positioned sounds and base filters for beds.
void BuildHrirWithEmphasis064(float azimuthDeg,float elevationDeg,float emphasis,float* leftFilter,float* rightFilter);
void BuildInterpolatedMeasuredHrir3D(float azimuthDeg,float elevationDeg,float* leftFilter,float* rightFilter) {
    BuildHrirWithEmphasis064(azimuthDeg,elevationDeg,g_emphasis062.load(std::memory_order_relaxed),leftFilter,rightFilter);
}
void BuildHrirWithEmphasis064(float azimuthDeg,float elevationDeg,float emphasis,float* leftFilter,float* rightFilter) {
    float a=std::fmod(azimuthDeg,360.0f); if(a<0.0f) a+=360.0f; if(a>=360.0f) a=0.0f;
    if(!std::isfinite(elevationDeg)) elevationDeg=0.0f;
    constexpr std::size_t rings=HRIRSET::kRingCount;
    const float e=(std::min)(HRIRSET::kRingElevation[rings-1],(std::max)(HRIRSET::kRingElevation[0],elevationDeg));
    std::size_t r0=0; while(r0+2<rings && HRIRSET::kRingElevation[r0+1]<=e) ++r0;
    const float e0=HRIRSET::kRingElevation[r0], e1=HRIRSET::kRingElevation[r0+1];
    const float w=(e1>e0)?(std::min)(1.0f,(std::max)(0.0f,(e-e0)/(e1-e0))):0.0f;
    std::memset(leftFilter,0,HRIRSET::kTapCount*sizeof(float));
    std::memset(rightFilter,0,HRIRSET::kTapCount*sizeof(float));
    AccumulateRing059(r0,a,1.0f-w,leftFilter,rightFilter,emphasis);
    AccumulateRing059(r0+1,a,w,leftFilter,rightFilter,emphasis);
}

bool PrepareDirectMeasuredHrir(
    const float* source,
    std::uint32_t frames,
    std::uintptr_t node,
    std::uintptr_t destination,
    float azimuthDeg,
    bool pure046=false,
    float elevationDeg=0.0f)
{
    if (source == nullptr || frames == 0 ||
        frames > static_cast<std::uint32_t>(kBinauralMaxFrames))
    {
        return false;
    }
    for (std::uint32_t i = 0; i < frames; ++i) {
        if (!std::isfinite(source[i])) return false; // never feed NaN/inf into filter history
    }

    auto& state = GetBinauralHistory(node, destination);
    if (!state.initialized) {
        state.priorAzimuthDeg = azimuthDeg;
        state.lowHrtfLeft = 0.0f;
        state.lowHrtfRight = 0.0f;
        state.lowDryLeft = 0.0f;
        state.lowDryRight = 0.0f;
        state.limiterGain = 1.0f;
        state.peakGuard066 = 1.0f;
        state.priorElevationDeg = (g_elevation059.load(std::memory_order_relaxed) && std::isfinite(elevationDeg))
            ? (std::min)(90.0f, (std::max)(-90.0f, elevationDeg)) : 0.0f;
        state.initialized = true;
        std::memset(state.history, 0, sizeof(state.history));
    }

    float delta = azimuthDeg - state.priorAzimuthDeg;
    while (delta >  180.0f) delta -= 360.0f;
    while (delta < -180.0f) delta += 360.0f;
    float smoothedAngle =
        state.priorAzimuthDeg + delta * 0.35f;
    while (smoothedAngle >  180.0f) smoothedAngle -= 360.0f;
    while (smoothedAngle < -180.0f) smoothedAngle += 360.0f;

    // elevation smoothed like azimuth; 0 when elevation is switched off.
    const float targetElevation = g_elevation059.load(std::memory_order_relaxed) && std::isfinite(elevationDeg)
        ? (std::min)(90.0f, (std::max)(-90.0f, elevationDeg)) : 0.0f;
    const float smoothedElevation = state.priorElevationDeg + (targetElevation - state.priorElevationDeg) * 0.35f;
    if (smoothedElevation < -20.0f) g_elevBelow059.fetch_add(1, std::memory_order_relaxed);
    else if (smoothedElevation > 20.0f) g_elevAbove059.fetch_add(1, std::memory_order_relaxed);
    else g_elevLevel059.fetch_add(1, std::memory_order_relaxed);

    alignas(16) float leftFilter[KEMAR360::kTapCount];
    alignas(16) float rightFilter[KEMAR360::kTapCount];
    BuildInterpolatedMeasuredHrir3D(
        smoothedAngle, smoothedElevation, leftFilter, rightFilter);
    // Crossfade filter changes across the block to avoid discontinuities.
    alignas(16) float priorLeftFilter[KEMAR360::kTapCount];
    alignas(16) float priorRightFilter[KEMAR360::kTapCount];
    float angleStep = smoothedAngle - state.priorAzimuthDeg;
    while (angleStep >  180.0f) angleStep -= 360.0f;
    while (angleStep < -180.0f) angleStep += 360.0f;
    const bool crossfade056 = std::fabs(angleStep) > 0.01f ||
        std::fabs(smoothedElevation - state.priorElevationDeg) > 0.01f;
    if (crossfade056) {
        BuildInterpolatedMeasuredHrir3D(state.priorAzimuthDeg, state.priorElevationDeg, priorLeftFilter, priorRightFilter);
        g_filterCrossfades056.fetch_add(1, std::memory_order_relaxed);
    }
    const float invFrames056 = 1.0f / static_cast<float>(frames);

    constexpr std::uint32_t historyMask =
        static_cast<std::uint32_t>(kBinauralHistorySamples - 1);

    // Use each ear's dominant arrival tap to align the low-band replacement.
    std::uint32_t leftDelay = 0;
    std::uint32_t rightDelay = 0;
    float leftDelayPeak = 0.0f;
    float rightDelayPeak = 0.0f;
    for (std::uint32_t tap = 0;
         tap < static_cast<std::uint32_t>(KEMAR360::kTapCount);
         ++tap)
    {
        const float l = std::fabs(leftFilter[tap]);
        const float r = std::fabs(rightFilter[tap]);
        if (l > leftDelayPeak) {
            leftDelayPeak = l;
            leftDelay = tap;
        }
        if (r > rightDelayPeak) {
            rightDelayPeak = r;
            rightDelay = tap;
        }
    }

    float blockPeak = 0.0f;

    for (std::uint32_t i = 0; i < frames; ++i) {
        state.history[state.writeIndex] = source[i];
        float left = 0.0f;
        float right = 0.0f;
        const std::uint32_t readIndex = state.writeIndex;

        if (crossfade056) {
            float oldLeft = 0.0f, oldRight = 0.0f;
            for (std::size_t tap = 0; tap < KEMAR360::kTapCount; ++tap) {
                const float x =
                    state.history[
                        (readIndex - static_cast<std::uint32_t>(tap)) &
                        historyMask];
                left += x * leftFilter[tap];
                right += x * rightFilter[tap];
                oldLeft += x * priorLeftFilter[tap];
                oldRight += x * priorRightFilter[tap];
            }
            const float t = (static_cast<float>(i) + 1.0f) * invFrames056;
            left = oldLeft + (left - oldLeft) * t;
            right = oldRight + (right - oldRight) * t;
        }
        else {
            for (std::size_t tap = 0; tap < KEMAR360::kTapCount; ++tap) {
                const float x =
                    state.history[
                        (readIndex - static_cast<std::uint32_t>(tap)) &
                        historyMask];
                left += x * leftFilter[tap];
                right += x * rightFilter[tap];
            }
        }

        const float delayedDryLeft =
            state.history[(readIndex - leftDelay) & historyMask];
        const float delayedDryRight =
            state.history[(readIndex - rightDelay) & historyMask];

        state.lowHrtfLeft +=
            kHybridLowpassAlpha * (left - state.lowHrtfLeft);
        state.lowHrtfRight +=
            kHybridLowpassAlpha * (right - state.lowHrtfRight);
        state.lowDryLeft +=
            kHybridLowpassAlpha * (delayedDryLeft - state.lowDryLeft);
        state.lowDryRight +=
            kHybridLowpassAlpha * (delayedDryRight - state.lowDryRight);

        const float hybridLeft =
            (left - state.lowHrtfLeft) + state.lowDryLeft;
        const float hybridRight =
            (right - state.lowHrtfRight) + state.lowDryRight;

        g_directLeftEar[i] = (pure046 ? left : hybridLeft) * kDirectHrtfOutputGain;
        g_directRightEar[i] = (pure046 ? right : hybridRight) * kDirectHrtfOutputGain;

        blockPeak = (std::max)(
            blockPeak,
            (std::max)(
                std::fabs(g_directLeftEar[i]),
                std::fabs(g_directRightEar[i])));

        state.writeIndex =
            (state.writeIndex + 1u) & historyMask;
    }

    // Do not limit pre-gain source PCM here. Reject invalid or extreme output;
    // apply peak protection after accounting for the game's gain.
    if (!std::isfinite(blockPeak) || blockPeak > 64.0f) {
        g_limiterEngaged056.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    state.priorAzimuthDeg = smoothedAngle;
    state.priorElevationDeg = smoothedElevation;
    return true;
}


bool PrepareWideWorldMono(
    std::uintptr_t sourceBuffer,
    std::uint32_t sourceMask,
    const float* coefficientBlock,
    std::uint32_t frames,
    float* monoCoefficients,
    float& sourcePeak)
{
    if (sourceBuffer == 0 || coefficientBlock == nullptr ||
        monoCoefficients == nullptr || frames == 0 ||
        frames > static_cast<std::uint32_t>(kBinauralMaxFrames))
    {
        return false;
    }

    // Supported world layouts: mono 0x4, stereo 0x3, quad 0x33.
    // PCM is planar, with uMaxFrames samples between channels.
    if (sourceMask != 0x00000003u && sourceMask != 0x00000033u) {
        return false;
    }

    const std::uint32_t channels =
        static_cast<std::uint32_t>(__popcnt(sourceMask));
    if (channels != 2u && channels != 4u) {
        return false;
    }

    // Validate every source-channel coefficient row.
    if (!IsReadable(
            coefficientBlock,
            static_cast<std::size_t>(channels) * 16u * sizeof(float)))
    {
        return false;
    }

    std::uintptr_t sourceData = 0;
    std::uint16_t maxFrames16 = 0;
    if (!SafeReadValue(sourceBuffer + 0x00, sourceData) ||
        !SafeReadValue(sourceBuffer + 0x10, maxFrames16))
    {
        return false;
    }

    const std::uint32_t maxFrames = maxFrames16;
    if (sourceData == 0 || maxFrames < frames ||
        maxFrames > static_cast<std::uint32_t>(kBinauralMaxFrames))
    {
        return false;
    }

    const std::size_t totalSamples =
        static_cast<std::size_t>(channels) * maxFrames;
    if (!IsReadable(
            reinterpret_cast<const void*>(sourceData),
            totalSamples * sizeof(float)))
    {
        return false;
    }

    const auto* base = reinterpret_cast<const float*>(sourceData);
    sourcePeak = 0.0f;

    // Average channels to mono, then restore aggregate matrix gain below.
    for (std::uint32_t i = 0; i < frames; ++i) {
        float sum = 0.0f;
        for (std::uint32_t ch = 0; ch < channels; ++ch) {
            const float x = base[
                static_cast<std::size_t>(ch) * maxFrames + i];
            if(!std::isfinite(x)) return false;
            sum += x;
            sourcePeak = (std::max)(sourcePeak, std::fabs(x));
        }
        g_wideMono[i] = sum / static_cast<float>(channels);
    }

    std::memset(monoCoefficients, 0, 16 * sizeof(float));

    // Each source channel has a 16-float coefficient row. Preserve aggregate
    // gain while replacing the original directional bias with the HRTF.
    for (int half : {0, 8}) {
        float aggregate = 0.0f;
        for (std::uint32_t ch = 0; ch < channels; ++ch) {
            const float* row = coefficientBlock +
                static_cast<std::size_t>(ch) * 16u;
            const float l = row[half + 0];
            const float r = row[half + 1];
            aggregate += std::sqrt((l*l + r*r) * 0.5f);
        }
        monoCoefficients[half + 0] = aggregate;
        monoCoefficients[half + 1] = aggregate;
    }

    return true;
}

// Mono-to-stereo bypass keeps the original pan and gain endpoints.
void BuildBypassEarCoefficients044(const float* original,float* left,float* right) {
    std::memcpy(left,original,16*sizeof(float));
    std::memcpy(right,original,16*sizeof(float));
    for(int half=0;half<16;half+=8) {
        left[half+1]=0.0f;
        right[half]=0.0f;
    }
}
std::atomic<std::uint32_t> g_inputPeak044{0},g_leftPeak044{0},g_rightPeak044{0};
std::atomic<std::uint32_t> g_inputRms044{0},g_leftRms044{0},g_rightRms044{0};
std::atomic<unsigned> g_metricsMode044{0};
void RecordEarMetrics044(const float* input,std::uint32_t frames,bool bypass) {
    double in=0,left=0,right=0;float ip=0,lp=0,rp=0;
    for(std::uint32_t i=0;i<frames;++i) {
        const float x=input[i],l=g_directLeftEar[i],r=g_directRightEar[i];
        in+=double(x)*x;left+=double(l)*l;right+=double(r)*r;
        ip=(std::max)(ip,std::fabs(x));lp=(std::max)(lp,std::fabs(l));rp=(std::max)(rp,std::fabs(r));
    }
    if(!frames) return;
    g_inputPeak044.store(FloatBits(ip));g_leftPeak044.store(FloatBits(lp));g_rightPeak044.store(FloatBits(rp));
    g_inputRms044.store(FloatBits(static_cast<float>(std::sqrt(in/frames))));
    g_leftRms044.store(FloatBits(static_cast<float>(std::sqrt(left/frames))));
    g_rightRms044.store(FloatBits(static_cast<float>(std::sqrt(right/frames))));
    g_metricsMode044.store(bypass?3u:2u);
}

bool ApplyWideWorldHrtf(
    std::int64_t destinationValue,
    std::int64_t sourceBufferValue,
    const float* coefficientBlock,
    std::uintptr_t node,
    std::uintptr_t destination,
    std::uint32_t sourceMask,
    const IdentityMeta& meta,
    float& sourcePeak,
    float& leftPeak,
    float& rightPeak,
    float& azimuthDeg,
    float& elevationDeg,
    float& distance,
    std::uint32_t& framesOut,
    bool bypass044=false,
    bool pure046=false,
    const float* nativeWorld050=nullptr)
{
    if (!bypass044 && !ComputeDirectGeometry(
            meta, azimuthDeg, elevationDeg, distance,nativeWorld050))
    {
        return false;
    }

    const auto sourceBuffer =
        static_cast<std::uintptr_t>(sourceBufferValue);
    if (sourceBuffer == 0 || coefficientBlock == nullptr) {
        g_directHrtfBadPcm.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    std::uintptr_t originalData = 0;
    std::uint16_t maxFrames16 = 0;
    std::uint16_t validFrames16 = 0;
    if (!SafeReadValue(sourceBuffer + 0x00, originalData) ||
        !SafeReadValue(sourceBuffer + 0x10, maxFrames16) ||
        !SafeReadValue(sourceBuffer + 0x12, validFrames16))
    {
        g_directHrtfBadPcm.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    const std::uint32_t frames =
        validFrames16 != 0 ? validFrames16 : maxFrames16;
    if (originalData == 0 || frames == 0 ||
        frames > static_cast<std::uint32_t>(kBinauralMaxFrames))
    {
        g_directHrtfBadPcm.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    const unsigned rows047=sourceMask==4?1u:(sourceMask==3?2u:(sourceMask==0x33?4u:0u));
    if(!rows047 || !IsReadable(coefficientBlock,rows047*16u*sizeof(float))) return false;
    for(unsigned i=0;i<rows047*16u;++i) if(!std::isfinite(coefficientBlock[i])) return false;

    alignas(16) float monoCoefficients[16]{};
    const float* hrtfSource = nullptr;
    bool multiSource = false;

    if (sourceMask == 0x00000004u) {
        if (!IsReadable(coefficientBlock, 16u * sizeof(float)) ||
            !IsReadable(
                reinterpret_cast<const void*>(originalData),
                static_cast<std::size_t>(frames) * sizeof(float)))
        {
            g_directHrtfBadPcm.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        std::memcpy(
            monoCoefficients, coefficientBlock,
            sizeof(monoCoefficients));
        hrtfSource = reinterpret_cast<const float*>(originalData);
        for (std::uint32_t i = 0; i < frames; ++i) {
            sourcePeak = (std::max)(
                sourcePeak, std::fabs(hrtfSource[i]));
            if(!std::isfinite(hrtfSource[i])) return false;
        }
    }
    else {
        multiSource = true;
        g_wideHrtfMultiAttempts.fetch_add(1, std::memory_order_relaxed);
        if (!PrepareWideWorldMono(
                sourceBuffer, sourceMask, coefficientBlock,
                frames, monoCoefficients, sourcePeak))
        {
            g_wideHrtfUnsupported.fetch_add(1, std::memory_order_relaxed);
            g_directHrtfBadPcm.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        hrtfSource = g_wideMono;
    }

    // Render stereo channels around the source direction.
    // The 1.5 m half-width narrows with distance.
    float spreadDeg056 = 0.0f;
    if (!bypass044 && sourceMask == 0x00000003u && g_stereoSpread056.load(std::memory_order_relaxed) &&
        std::isfinite(distance) && distance > 0.0f) {
        spreadDeg056 = (std::min)(40.0f, std::atan2(1.5f, distance) * 57.2957795f);
    }
    if(bypass044) {
        std::memcpy(g_directLeftEar,hrtfSource,frames*sizeof(float));
        std::memcpy(g_directRightEar,hrtfSource,frames*sizeof(float));
    }
    else if (spreadDeg056 >= 2.0f) {
        std::uint16_t maxFrames056 = 0;
        if (!SafeReadValue(sourceBuffer + 0x10, maxFrames056) || maxFrames056 < frames) return false;
        const float* channel0 = reinterpret_cast<const float*>(originalData);
        const float* channel1 = channel0 + maxFrames056;
        alignas(16) static thread_local float half056[kBinauralMaxFrames];
        alignas(16) static thread_local float accLeft056[kBinauralMaxFrames];
        alignas(16) static thread_local float accRight056[kBinauralMaxFrames];
        // 0.5 per channel: when the spread collapses this equals the (L+R)/2 fold.
        for (std::uint32_t i = 0; i < frames; ++i) half056[i] = channel0[i] * 0.5f;
        if (!PrepareDirectMeasuredHrir(half056, frames, node, destination, azimuthDeg - spreadDeg056, pure046, elevationDeg)) {
            g_directHrtfBadPcm.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        std::memcpy(accLeft056, g_directLeftEar, frames * sizeof(float));
        std::memcpy(accRight056, g_directRightEar, frames * sizeof(float));
        for (std::uint32_t i = 0; i < frames; ++i) half056[i] = channel1[i] * 0.5f;
        if (!PrepareDirectMeasuredHrir(half056, frames, node, destination ^ 0x4000000000000000ull, azimuthDeg + spreadDeg056, pure046, elevationDeg)) {
            g_directHrtfBadPcm.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        for (std::uint32_t i = 0; i < frames; ++i) {
            g_directLeftEar[i] += accLeft056[i];
            g_directRightEar[i] += accRight056[i];
        }
        g_stereoWide056.fetch_add(1, std::memory_order_relaxed);
    }
    else if (!PrepareDirectMeasuredHrir(
            hrtfSource, frames, node, destination, azimuthDeg,pure046,elevationDeg))
    {
        g_directHrtfBadPcm.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    alignas(16) float leftCoefficients[16];
    alignas(16) float rightCoefficients[16];
    if(bypass044) BuildBypassEarCoefficients044(monoCoefficients,leftCoefficients,rightCoefficients);
    else BuildStereoEarCoefficientBlocks(monoCoefficients,leftCoefficients,rightCoefficients);
    RecordEarMetrics044(hrtfSource,frames,bypass044);
    if(pure046) g_metricsMode044.store(4);

    for (std::uint32_t i = 0; i < frames; ++i) {
        leftPeak = (std::max)(
            leftPeak, std::fabs(g_directLeftEar[i]));
        rightPeak = (std::max)(
            rightPeak, std::fabs(g_directRightEar[i]));
    }

    // Compare processed peaks with the original mix estimate.
    // Apply bounded per-voice attenuation with a gradual release in owned buffers.
    if (!bypass044 && g_peakGuard066.load(std::memory_order_relaxed)) {
        const float originalGain = (std::max)((std::max)(std::fabs(monoCoefficients[0]), std::fabs(monoCoefficients[1])),
                                              (std::max)(std::fabs(monoCoefficients[8]), std::fabs(monoCoefficients[9])));
        const float originalPeak = sourcePeak * originalGain;
        const float binauralPeak = (std::max)(leftPeak * (std::max)(leftCoefficients[0], leftCoefficients[8]),
                                              rightPeak * (std::max)(rightCoefficients[1], rightCoefficients[9]));
        auto& guardState = GetBinauralHistory(node, destination);
        float target = 1.0f;
        if (binauralPeak > 0.3f && originalPeak > 0.0f && binauralPeak > originalPeak) {
            target = (std::max)(0.5f, originalPeak / binauralPeak);
            g_peakGuarded066.fetch_add(1, std::memory_order_relaxed);
        }
        if (target > guardState.peakGuard066) target = (std::min)(target, guardState.peakGuard066 + 0.02f);
        const float g0 = guardState.peakGuard066;
        if (g0 != 1.0f || target != 1.0f) {
            const float inv = 1.0f / static_cast<float>(frames);
            for (std::uint32_t i = 0; i < frames; ++i) {
                const float g = g0 + (target - g0) * ((static_cast<float>(i) + 1.0f) * inv);
                g_directLeftEar[i] *= g;
                g_directRightEar[i] *= g;
            }
        }
        guardState.peakGuard066 = target;
    }

    // Clone the source header instead of changing the live Wwise buffer.
    // The mixer reads through +0x40; preserve frame counts and the node pointer.
    alignas(16) std::array<std::uint8_t, 0x80> fakeBuffer{};
    if (!IsReadable(
            reinterpret_cast<const void*>(sourceBuffer),
            fakeBuffer.size()))
    {
        g_directHrtfBadPcm.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    std::memcpy(
        fakeBuffer.data(),
        reinterpret_cast<const void*>(sourceBuffer),
        fakeBuffer.size());

    const auto fakePtr =
        reinterpret_cast<std::uintptr_t>(fakeBuffer.data());
    *reinterpret_cast<std::uint32_t*>(
        fakeBuffer.data() + 0x08) = 0x00000004u;

    *reinterpret_cast<std::uintptr_t*>(
        fakeBuffer.data() + 0x00) =
        reinterpret_cast<std::uintptr_t>(g_directLeftEar);
    g_sourceToDestinationMixOriginal(
        destinationValue,
        static_cast<std::int64_t>(fakePtr),
        leftCoefficients);
    g_directHrtfLeftCalls.fetch_add(1, std::memory_order_relaxed);

    *reinterpret_cast<std::uintptr_t*>(
        fakeBuffer.data() + 0x00) =
        reinterpret_cast<std::uintptr_t>(g_directRightEar);
    g_sourceToDestinationMixOriginal(
        destinationValue,
        static_cast<std::int64_t>(fakePtr),
        rightCoefficients);
    g_directHrtfRightCalls.fetch_add(1, std::memory_order_relaxed);

    if (multiSource) {
        g_wideHrtfMultiApplied.fetch_add(1, std::memory_order_relaxed);
        if (sourceMask == 0x00000003u) {
            g_wideHrtfStereoApplied.fetch_add(1, std::memory_order_relaxed);
        }
        else if (sourceMask == 0x00000033u) {
            g_wideHrtfQuadApplied.fetch_add(1, std::memory_order_relaxed);
        }
    }

    framesOut = frames;
    g_directHrtfAppliedBlocks.fetch_add(1, std::memory_order_relaxed);
    return true;
}

void RenewVerifiedIdentity(
    std::uint32_t playingId,
    std::uintptr_t object,
    const IdentityMeta& meta,
    std::uint64_t now)
{
    if (playingId != 0) {
        if (auto* p = FindPlayingSlot(playingId, false)) {
            p->tick.store(now, std::memory_order_release);
        }
    }
    if (object != 0) {
        if (auto* o = FindObjectSlot(object, false)) {
            o->tick.store(now, std::memory_order_release);
        }
    }
    if (meta.key != 0) {
        if (auto* k = FindKeySlot(meta.key, false)) {
            k->tick.store(now, std::memory_order_release);
        }
    }
    if (meta.source != 0) {
        if (auto* f = FindFoxSlot(meta.source, false)) {
            f->eventTick.store(now, std::memory_order_release);
        }
    }
}

bool ShouldEmitMatrixBind(std::uintptr_t context, std::uint64_t now) {
    if (context == 0) return false;
    const auto start = HashPtr(context, kMatrixBindGateSlots - 1);
    for (std::size_t probe = 0; probe < 8; ++probe) {
        auto& slot = g_matrixBindGate[
            (start + probe) & (kMatrixBindGateSlots - 1)];
        auto existing = slot.context.load(std::memory_order_acquire);
        if (existing == context) {
            auto prior = slot.tick.load(std::memory_order_relaxed);
            for (;;) {
                if (now >= prior &&
                    now - prior < kMatrixBindLogIntervalMs) return false;
                if (slot.tick.compare_exchange_weak(
                        prior, now,
                        std::memory_order_relaxed,
                        std::memory_order_relaxed)) return true;
            }
        }
        if (existing == 0) {
            std::uintptr_t expected = 0;
            if (slot.context.compare_exchange_strong(
                    expected, context,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire) || expected == context)
            {
                slot.tick.store(now, std::memory_order_relaxed);
                return true;
            }
        }
    }
    return false;
}

bool IsRenderResearchEvent(std::uint32_t eventId) {
    return eventId == kEventGenerator ||
           eventId == kEventSteam ||
           eventId == kEventObservedA54F;
}

bool ShouldCaptureRenderContext(std::uintptr_t context, std::uint64_t now) {
    if (context == 0) return false;
    const auto start = HashPtr(context, kRenderGateSlots - 1);
    for (std::size_t probe = 0; probe < 8; ++probe) {
        auto& slot = g_renderGate[(start + probe) & (kRenderGateSlots - 1)];
        auto existing = slot.context.load(std::memory_order_acquire);
        if (existing == context) {
            auto prior = slot.tick.load(std::memory_order_relaxed);
            for (;;) {
                if (now >= prior && now - prior < kRenderSnapshotIntervalMs) return false;
                if (slot.tick.compare_exchange_weak(
                        prior, now,
                        std::memory_order_relaxed,
                        std::memory_order_relaxed)) return true;
            }
        }
        if (existing == 0) {
            std::uintptr_t expected = 0;
            if (slot.context.compare_exchange_strong(
                    expected, context,
                    std::memory_order_acq_rel,
                    std::memory_order_acquire) || expected == context)
            {
                slot.tick.store(now, std::memory_order_relaxed);
                return true;
            }
        }
    }
    return false;
}

template <std::size_t N>
std::uint32_t CopyRenderBytes(
    std::uintptr_t base,
    std::array<std::uint8_t, N>& out)
{
    if (base == 0 || !IsReadable(reinterpret_cast<const void*>(base), N)) {
        return 0;
    }
    std::memcpy(out.data(), reinterpret_cast<const void*>(base), N);
    return static_cast<std::uint32_t>(N);
}

void EnqueueRenderSnapshot(const RenderSnapshot& snapshot) {
    const auto sequence =
        g_renderSnapshotWrite.fetch_add(1, std::memory_order_relaxed) + 1;
    auto& slot = g_renderSnapshots[(sequence - 1) & (kRenderSnapshotSlots - 1)];
    slot.publishedSequence.store(0, std::memory_order_relaxed);
    slot.payload = snapshot;
    slot.publishedSequence.store(sequence, std::memory_order_release);
    g_renderSnapshotsQueued.fetch_add(1, std::memory_order_relaxed);
}

const char* RenderRegionName(std::uint32_t region) {
    switch (region) {
    case 1: return "node";
    case 2: return "wrapper";
    case 3: return "context";
    default: return "unknown";
    }
}

std::uint32_t FindRecentPlayingForIdentity(
    const IdentityMeta& meta,
    std::uint64_t now)
{
    std::uint32_t bestPlaying = 0;
    std::uint64_t bestTick = 0;
    for (const auto& slot : g_recentPlaying) {
        const auto playing = slot.playingId.load(std::memory_order_acquire);
        if (playing == 0) continue;
        const auto tick = slot.tick.load(std::memory_order_acquire);
        if (tick == 0 || (now > tick && now - tick > kRecentIdentityTtlMs)) continue;
        if (slot.eventId.load(std::memory_order_relaxed) != meta.eventId) continue;
        if (slot.key.load(std::memory_order_relaxed) != meta.key) continue;
        const auto body = slot.body.load(std::memory_order_relaxed);
        if (meta.body != 0 && body != meta.body) continue;
        if (tick >= bestTick) {
            bestTick = tick;
            bestPlaying = playing;
        }
    }
    return bestPlaying;
}

bool LogRenderIdentityMatch(
    const RenderSnapshot& snap,
    std::uint32_t region,
    std::uint32_t offset,
    const char* matchType,
    std::uint64_t rawValue,
    std::uint32_t playingId,
    const IdentityMeta& meta)
{
    if (meta.eventId != snap.eventId || meta.body == 0) return false;
    if (playingId == 0) {
        playingId = FindRecentPlayingForIdentity(meta, GetTickCount64());
    }
    g_renderIdentityMatches.fetch_add(1, std::memory_order_relaxed);
    if (g_log && CanLog()) {
        g_log->info(
            "RENDER_ID_MATCH,tick={},event=0x{:08X},region={},offset=0x{:03X},"
            "match_type={},raw=0x{:016X},playing=0x{:08X},key=0x{:016X},"
            "body=0x{:016X},source=0x{:08X},record=0x{:016X},"
            "node=0x{:016X},wrapper=0x{:016X},context=0x{:016X},event_object=0x{:016X}",
            snap.tick, snap.eventId, RenderRegionName(region), offset,
            matchType, rawValue, playingId, meta.key,
            static_cast<std::uint64_t>(meta.body), meta.source,
            static_cast<std::uint64_t>(meta.record),
            static_cast<std::uint64_t>(snap.node),
            static_cast<std::uint64_t>(snap.wrapper),
            static_cast<std::uint64_t>(snap.context),
            static_cast<std::uint64_t>(snap.eventObject));
    }
    return true;
}

void ScanRenderRegion(
    const RenderSnapshot& snap,
    std::uint32_t region,
    const std::uint8_t* bytes,
    std::size_t size,
    std::size_t& matches)
{
    if (bytes == nullptr || size < 4 || matches >= 16) return;
    const auto now = GetTickCount64();

    for (std::size_t off = 0; off + 4 <= size && matches < 16; off += 4) {
        std::uint32_t v32 = 0;
        std::memcpy(&v32, bytes + off, sizeof(v32));
        if (v32 != 0) {
            IdentityMeta meta{};
            if (LookupPlaying(v32, meta, now) &&
                LogRenderIdentityMatch(
                    snap, region, static_cast<std::uint32_t>(off),
                    "playing32", v32, v32, meta))
            {
                ++matches;
            }

            meta = IdentityMeta{};
            if (LookupKey(static_cast<std::uint64_t>(v32), meta, now) &&
                LogRenderIdentityMatch(
                    snap, region, static_cast<std::uint32_t>(off),
                    "key32", v32, meta.postResult > 0 ?
                        static_cast<std::uint32_t>(meta.postResult) : 0u, meta))
            {
                ++matches;
            }
        }

        if (off + 8 <= size && matches < 16) {
            std::uint64_t v64 = 0;
            std::memcpy(&v64, bytes + off, sizeof(v64));
            if (v64 != 0) {
                IdentityMeta meta{};
                if (LookupKey(v64, meta, now) &&
                    LogRenderIdentityMatch(
                        snap, region, static_cast<std::uint32_t>(off),
                        "key64", v64, meta.postResult > 0 ?
                            static_cast<std::uint32_t>(meta.postResult) : 0u, meta))
                {
                    ++matches;
                }

                meta = IdentityMeta{};
                if (LookupObject(static_cast<std::uintptr_t>(v64), meta, now) &&
                    LogRenderIdentityMatch(
                        snap, region, static_cast<std::uint32_t>(off),
                        "wwise_object", v64, meta.postResult > 0 ?
                            static_cast<std::uint32_t>(meta.postResult) : 0u, meta))
                {
                    ++matches;
                }

                const auto lo = static_cast<std::uint32_t>(v64 & 0xffffffffu);
                const auto hi = static_cast<std::uint32_t>(v64 >> 32);
                meta = IdentityMeta{};
                if (hi == snap.eventId && LookupPlaying(lo, meta, now) &&
                    LogRenderIdentityMatch(
                        snap, region, static_cast<std::uint32_t>(off),
                        "packed_playing_event", v64, lo, meta))
                {
                    ++matches;
                }
                meta = IdentityMeta{};
                if (lo == snap.eventId && LookupPlaying(hi, meta, now) &&
                    LogRenderIdentityMatch(
                        snap, region, static_cast<std::uint32_t>(off),
                        "packed_event_playing", v64, hi, meta))
                {
                    ++matches;
                }
            }
        }
    }
}

void ProcessRenderSnapshots() {
    auto read = g_renderSnapshotRead.load(std::memory_order_relaxed);
    const auto write = g_renderSnapshotWrite.load(std::memory_order_acquire);
    if (write > read + kRenderSnapshotSlots) {
        const auto lost = write - read - kRenderSnapshotSlots;
        g_renderSnapshotDropped.fetch_add(lost, std::memory_order_relaxed);
        read = write - kRenderSnapshotSlots;
    }

    std::size_t processed = 0;
    while (read < write && processed < kMaxRenderFlushPerBridge) {
        const auto sequence = read + 1;
        auto& slot = g_renderSnapshots[(sequence - 1) & (kRenderSnapshotSlots - 1)];
        const auto published = slot.publishedSequence.load(std::memory_order_acquire);
        if (published == 0) break;
        if (published != sequence) {
            if (published > sequence) {
                const auto skipped = published - sequence;
                g_renderSnapshotDropped.fetch_add(skipped, std::memory_order_relaxed);
                read += skipped;
                continue;
            }
            break;
        }

        const RenderSnapshot snap = slot.payload;
        std::size_t matches = 0;
        if (snap.nodeBytes != 0) {
            ScanRenderRegion(snap, 1, snap.nodeData.data(), snap.nodeBytes, matches);
        }
        if (snap.wrapperBytes != 0) {
            ScanRenderRegion(snap, 2, snap.wrapperData.data(), snap.wrapperBytes, matches);
        }
        if (snap.contextBytes != 0) {
            ScanRenderRegion(snap, 3, snap.contextData.data(), snap.contextBytes, matches);
        }

        if (matches == 0) {
            const auto n = g_renderNoMatchRows.fetch_add(1, std::memory_order_relaxed);
            if (n < 24 && g_log && CanLog()) {
                g_log->info(
                    "RENDER_SCAN_NO_MATCH,tick={},event=0x{:08X},node=0x{:016X},"
                    "wrapper=0x{:016X},context=0x{:016X},event_object=0x{:016X},"
                    "node_bytes={},wrapper_bytes={},context_bytes={}",
                    snap.tick, snap.eventId,
                    static_cast<std::uint64_t>(snap.node),
                    static_cast<std::uint64_t>(snap.wrapper),
                    static_cast<std::uint64_t>(snap.context),
                    static_cast<std::uint64_t>(snap.eventObject),
                    snap.nodeBytes, snap.wrapperBytes, snap.contextBytes);
            }
        }

        g_renderSnapshotsProcessed.fetch_add(1, std::memory_order_relaxed);
        read = sequence;
        ++processed;
    }
    g_renderSnapshotRead.store(read, std::memory_order_release);
}

// Bounded census. Audio callers try once; no allocation, disk I/O or waiting.
struct Census049 {
    std::uint64_t key1=0,key2=0,key3=0,first=0,last=0,calls=0,applied=0;
    std::uintptr_t body=0,node=0,object=0,caller=0;
    std::uint64_t objectKey=0;
    std::uint32_t kind=0,event=0,playing=0,source=0,routes=0,matches=0,srcMasks=0,dstMasks=0;
    std::uint32_t playingStages=0,objectStages=0;
    std::uint64_t emittedCalls=0,emittedAt=0;
    std::uint32_t xyzBits050[3]{};
};
constexpr std::size_t kCensus049=65536;
std::array<Census049,kCensus049> g_census049{};
std::atomic_flag g_censusLock049=ATOMIC_FLAG_INIT;
std::atomic<std::uint64_t> g_censusBusy049{0},g_censusFull049{0},g_censusUnique049{0};
std::uint64_t g_censusRows049=0;
bool CensusSame049(const Census049& a,const Census049& b) {
    return a.kind==b.kind && a.key1==b.key1 && a.key2==b.key2 && a.key3==b.key3;
}
void ObserveCensus049(Census049 x) {
    if(!g_debugLog063.load(std::memory_order_relaxed)) return; // v0.63
    if(g_censusLock049.test_and_set(std::memory_order_acquire)){++g_censusBusy049;return;}
    const auto hash=x.key1*0x9E3779B97F4A7C15ull ^ x.key2*0xBF58476D1CE4E5B9ull ^ x.key3*0x94D049BB133111EBull ^ x.kind;
    bool stored=false;
    for(unsigned n=0;n<128;++n){
        auto& c=g_census049[(hash+n)&(kCensus049-1)];
        if(!c.kind){c=x;c.first=x.last;c.calls=1; ++g_censusUnique049;stored=true;break;}
        if(CensusSame049(c,x)){
            if(x.last<c.first)c.first=x.last;
            if(x.last>c.last)c.last=x.last;
            ++c.calls;c.applied+=x.applied;
            c.routes|=x.routes;c.matches|=x.matches;c.srcMasks|=x.srcMasks;c.dstMasks|=x.dstMasks;
            c.playingStages|=x.playingStages;c.objectStages|=x.objectStages;
            if(x.body)c.body=x.body;
            if(x.event)c.event=x.event;
            if(x.source)c.source=x.source;
            if(x.objectKey)c.objectKey=x.objectKey;
            if(x.kind==4)for(unsigned i=0;i<3;++i)c.xyzBits050[i]=x.xyzBits050[i];
            stored=true;break;
        }
    }
    if(!stored)++g_censusFull049;
    g_censusLock049.clear(std::memory_order_release);
}
void FlushCensus049(bool final=false) {
    if(!g_log)return;
    static std::atomic_flag flushing=ATOMIC_FLAG_INIT;
    if(flushing.test_and_set(std::memory_order_acquire))return;
    struct FlushGuard049 {
        std::atomic_flag& flag;
        ~FlushGuard049(){flag.clear(std::memory_order_release);}
    } guard{flushing};
    static std::size_t cursor=0;
    const auto now=GetTickCount64();
    const auto limit=final?kCensus049:512;
    for(std::size_t i=0;i<limit;++i){
        Census049 out{};bool emit=false;
        if(g_censusLock049.test_and_set(std::memory_order_acquire)) break;
        auto& c=g_census049[cursor];cursor=(cursor+1)&(kCensus049-1);
        if(c.kind && c.calls!=c.emittedCalls && g_censusRows049<200000 &&
            (final || !c.emittedCalls || now-c.emittedAt>=60000 || (now>=c.last && now-c.last>=5000))) {
            out=c;c.emittedCalls=c.calls;c.emittedAt=now;emit=true;
        }
        g_censusLock049.clear(std::memory_order_release);
        if(emit){
            ++g_censusRows049;
            g_log->info("SOURCE049,kind={},a=0x{:X},b=0x{:X},c=0x{:X},first={},last={},calls={},applied={},event=0x{:X},playing={},key=0x{:X},body=0x{:X},source=0x{:X},node=0x{:X},object=0x{:X},caller=0x{:X},routes={},match_bits={},src_masks_or={},dst_masks_or={},playing_stage_bits={},object_stage_bits={}",
                out.kind,out.key1,out.key2,out.key3,out.first,out.last,out.calls,out.applied,out.event,out.playing,out.objectKey,out.body,out.source,
                out.node,out.object,out.caller,out.routes,out.matches,out.srcMasks,out.dstMasks,out.playingStages,out.objectStages);
            if(out.kind==4)g_log->info("POSITION050,a=0x{:X},b=0x{:X},c=0x{:X},key=0x{:X},x_bits={},y_bits={},z_bits={}",
                out.key1,out.key2,out.key3,out.objectKey,out.xyzBits050[0],out.xyzBits050[1],out.xyzBits050[2]);
        }
    }
    static std::uint64_t summary=0;
    static bool priorMarker=false;
    static unsigned marker=0;
    const bool down=AudioKey062(VK_F7);
    if(!final && down && !priorMarker) {
        g_log->info("MARK049,number={},tick={}",++marker,now);g_log->flush();
    }
    priorMarker=down;
    if(final || now-summary>=60000){
        g_log->info("CENSUS049,tick={},unique={},rows={},busy_drops={},table_drops={},row_cap={},final={}",now,
            g_censusUnique049.load(),g_censusRows049,g_censusBusy049.load(),g_censusFull049.load(),g_censusRows049>=200000?1:0,final?1:0);
        g_log->flush();summary=now;
    }
}

void EnqueueTrace(const TracePayload& p) {
    // Retain first-stage identity evidence; suppress old repeating snapshots.
    if(p.kind!=TraceKind::WwisePost && p.kind!=TraceKind::SourceRecord) return;
    Census049 c{};c.kind=p.kind==TraceKind::WwisePost?1u:2u;
    c.event=p.eventId;c.playing=p.kind==TraceKind::WwisePost?static_cast<std::uint32_t>(p.result):static_cast<std::uint32_t>(p.nestedPostResult);
    c.key1=p.eventId;c.key2=p.objectKey;c.key3=c.playing;
    if(c.kind==2){c.key2=p.body;c.key3=p.sourceAfter;}
    c.body=p.body;c.objectKey=p.objectKey;c.source=p.source;c.caller=p.caller;c.last=p.tick;
    ObserveCensus049(c);
}

bool CaptureNormalAudioTransform(
    std::int64_t body,
    std::uint32_t (&out)[8])
{
    const auto bodyPtr = static_cast<std::uintptr_t>(body);
    if (bodyPtr == 0) return false;

    std::uintptr_t link = 0;
    if (!IsReadable(reinterpret_cast<const void*>(bodyPtr + 0x38), sizeof(link))) {
        return false;
    }
    std::memcpy(&link, reinterpret_cast<const void*>(bodyPtr + 0x38), sizeof(link));
    if (link == 0 ||
        !IsReadable(reinterpret_cast<const void*>(link + 0x18), sizeof(std::uintptr_t)))
    {
        return false;
    }

    std::uintptr_t transform = 0;
    std::memcpy(&transform, reinterpret_cast<const void*>(link + 0x18), sizeof(transform));
    if (transform == 0 ||
        !IsReadable(reinterpret_cast<const void*>(transform + 0x110), sizeof(out)))
    {
        return false;
    }

    std::memcpy(out, reinterpret_cast<const void*>(transform + 0x110), sizeof(out));
    return true;
}

void FlushTraceRecords() {
    FlushCensus049();
    return; // replaces legacy repeating traces with bounded census rows.

    bool expected = false;
    if (!g_flushBusy.compare_exchange_strong(
            expected, true,
            std::memory_order_acq_rel,
            std::memory_order_relaxed))
    {
        return;
    }

    auto read = g_traceRead.load(std::memory_order_relaxed);
    const auto write = g_traceWrite.load(std::memory_order_acquire);

    if (write > read + kTraceSlots) {
        const auto lost = write - read - kTraceSlots;
        g_traceDropped.fetch_add(lost, std::memory_order_relaxed);
        read = write - kTraceSlots;
    }

    std::size_t flushed = 0;
    while (read < write && flushed < kMaxFlushPerBridge) {
        const auto sequence = read + 1;
        auto& slot = g_trace[(sequence - 1) & (kTraceSlots - 1)];
        const auto published =
            slot.publishedSequence.load(std::memory_order_acquire);

        if (published == 0) break;
        if (published != sequence) {
            // Slot was overwritten before this consumer got to it.
            if (published > sequence) {
                const auto skipped = published - sequence;
                g_traceDropped.fetch_add(skipped, std::memory_order_relaxed);
                read += skipped;
                continue;
            }
            break;
        }

        const TracePayload p = slot.payload;
        if (g_log && CanLog()) {
            switch (p.kind) {
            case TraceKind::SourceRecord:
                g_log->info(
                    "SOURCE_RECORD,tick={},tid={},event=0x{:08X},body=0x{:016X},"
                    "source_before=0x{:08X},source_after=0x{:08X},"
                    "table_base=0x{:016X},record=0x{:016X},record_key=0x{:016X},"
                    "candidate_record=0x{:016X},candidate_stored_source=0x{:08X},"
                    "candidate_stored_key=0x{:016X},derived_key=0x{:016X},derived_key_match={},"
                    "nested_key=0x{:016X},nested_result=0x{:08X},nested_match={},"
                    "status=0x{:08X},valid={}",
                    p.tick, p.tid, p.eventId,
                    static_cast<std::uint64_t>(p.body),
                    p.sourceBefore, p.sourceAfter,
                    static_cast<std::uint64_t>(p.tableBase),
                    static_cast<std::uint64_t>(p.record), p.objectKey,
                    static_cast<std::uint64_t>(p.candidateRecord),
                    p.candidateStoredSource, p.candidateStoredKey64,
                    p.derivedObjectKey, p.derivedKeyMatch,
                    p.nestedObjectKey, static_cast<std::uint32_t>(p.nestedPostResult),
                    p.tlsMatch, static_cast<std::uint32_t>(p.result),
                    p.record != 0 ? 1 : 0);
                break;

            case TraceKind::SourceTransform: {
                float x = 0.0f, y = 0.0f, z = 0.0f;
                std::memcpy(&x, &p.xBits, sizeof(x));
                std::memcpy(&y, &p.yBits, sizeof(y));
                std::memcpy(&z, &p.zBits, sizeof(z));
                g_log->info(
                    "SOURCE_XFORM,tick={},tid={},body=0x{:016X},source=0x{:08X},"
                    "x={:.6f},y={:.6f},z={:.6f}",
                    p.tick, p.tid,
                    static_cast<std::uint64_t>(p.body), p.source,
                    x, y, z);
                break;
            }

            case TraceKind::WwisePost:
                g_log->info(
                    "WWISE_POST,tick={},tid={},event=0x{:08X},fox_event=0x{:08X},event_match={},object_key=0x{:016X},"
                    "result=0x{:08X},record_matches={},source=0x{:08X},"
                    "body=0x{:016X},record=0x{:016X},tls_match={},caller=0x{:016X}",
                    p.tick, p.tid, p.eventId, p.foxEventId,
                    (p.foxEventId != 0 && p.foxEventId == p.eventId) ? 1 : 0,
                    p.objectKey, static_cast<std::uint32_t>(p.result),
                    p.recordMatches, p.source,
                    static_cast<std::uint64_t>(p.body),
                    static_cast<std::uint64_t>(p.record), p.tlsMatch,
                    static_cast<std::uint64_t>(p.caller));
                break;

            case TraceKind::GameObjectLookup:
                g_log->info(
                    "GAME_OBJECT_LOOKUP,tick={},tid={},object_key=0x{:016X},"
                    "object=0x{:016X},event=0x{:08X},source=0x{:08X},"
                    "body=0x{:016X},record=0x{:016X},post_result=0x{:08X},"
                    "caller=0x{:016X}",
                    p.tick, p.tid, p.objectKey,
                    static_cast<std::uint64_t>(p.object),
                    p.eventId, p.source,
                    static_cast<std::uint64_t>(p.body),
                    static_cast<std::uint64_t>(p.record),
                    static_cast<std::uint32_t>(p.result),
                    static_cast<std::uint64_t>(p.caller));
                break;

            case TraceKind::PlayAction:
                g_log->info(
                    "PLAY_ACTION,tick={},tid={},action=0x{:016X},playing=0x{:08X},"
                    "match_mode={},object=0x{:016X},object_key=0x{:016X},"
                    "event=0x{:08X},source=0x{:08X},body=0x{:016X},record=0x{:016X},"
                    "event_node=0x{:016X},event_vtable=0x{:016X},execute_v40=0x{:016X},"
                    "node_type=0x{:04X},raw44=0x{:08X},caller=0x{:016X}",
                    p.tick, p.tid,
                    static_cast<std::uint64_t>(p.action), p.playingId,
                    p.matchMode,
                    static_cast<std::uint64_t>(p.object), p.objectKey,
                    p.eventId, p.source,
                    static_cast<std::uint64_t>(p.body),
                    static_cast<std::uint64_t>(p.record),
                    static_cast<std::uint64_t>(p.eventNode),
                    static_cast<std::uint64_t>(p.eventVtable),
                    static_cast<std::uint64_t>(p.executeV40),
                    p.nodeType,
                    p.actionRaw44,
                    static_cast<std::uint64_t>(p.caller));
                break;

            case TraceKind::PlayingEventPack:
                g_log->info(
                    "PLAYING_EVENT_PACK,tick={},tid={},playing=0x{:08X},event=0x{:08X},"
                    "out0=0x{:08X},out1=0x{:08X},tracked={},key=0x{:016X},"
                    "body=0x{:016X},source=0x{:08X},caller=0x{:016X}",
                    p.tick, p.tid, p.playingId, p.eventId,
                    p.packOut0, p.packOut1, p.matchMode, p.objectKey,
                    static_cast<std::uint64_t>(p.body), p.source,
                    static_cast<std::uint64_t>(p.caller));
                break;

            case TraceKind::MatrixDirectBind:
                g_log->info(
                    "MATRIX_DIRECT_BIND,tick={},tid={},route={},playing=0x{:08X},"
                    "event=0x{:08X},key=0x{:016X},source=0x{:08X},body=0x{:016X},"
                    "record=0x{:016X},node=0x{:016X},context=0x{:016X},"
                    "context_obj_a8=0x{:016X},context_obj_148=0x{:016X},"
                    "obj_a8_match={},obj_148_match={},dual_match={},"
                    "source_mask=0x{:08X},destination_mask=0x{:08X},destination=0x{:016X},"
                    "hrtf_requested={},hrtf_applied={},hrtf_frames={},"
                    "mute_requested={},mute_applied={},source_peak={:.5f},left_peak={:.5f},right_peak={:.5f},"
                    "azimuth_deg={:.3f},elevation_deg={:.3f},distance={:.3f},"
                    "caller=0x{:016X}",
                    p.tick, p.tid, p.route, p.playingId,
                    p.eventId, p.objectKey, p.source,
                    static_cast<std::uint64_t>(p.body),
                    static_cast<std::uint64_t>(p.record),
                    static_cast<std::uint64_t>(p.node),
                    static_cast<std::uint64_t>(p.context),
                    static_cast<std::uint64_t>(p.contextObjectA8),
                    static_cast<std::uint64_t>(p.contextObject148),
                    p.objectA8Match, p.object148Match, p.dualIdentityMatch,
                    p.sourceMask, p.destinationMask,
                    static_cast<std::uint64_t>(p.destination),
                    p.hrtfRequested, p.hrtfApplied, p.hrtfFrames,
                    p.dryRequested, p.dryApplied,
                    FloatFromBits(p.sourcePeakBits),
                    FloatFromBits(p.leftPeakBits),
                    FloatFromBits(p.rightPeakBits),
                    FloatFromBits(p.azimuthBits),
                    FloatFromBits(p.elevationBits),
                    FloatFromBits(p.distanceBits),
                    static_cast<std::uint64_t>(p.caller));
                break;

            case TraceKind::ActiveRenderBind:
                g_log->info(
                    "ACTIVE_RENDER_BIND,tick={},tid={},playing=0x{:08X},event=0x{:08X},"
                    "key=0x{:016X},source=0x{:08X},body=0x{:016X},record=0x{:016X},"
                    "node=0x{:016X},context=0x{:016X},context_obj_a8=0x{:016X},"
                    "context_obj_148=0x{:016X},match_mask=0x{:X}",
                    p.tick, p.tid, p.playingId, p.eventId, p.objectKey, p.source,
                    static_cast<std::uint64_t>(p.body),
                    static_cast<std::uint64_t>(p.record),
                    static_cast<std::uint64_t>(p.node),
                    static_cast<std::uint64_t>(p.context),
                    static_cast<std::uint64_t>(p.contextObjectA8),
                    static_cast<std::uint64_t>(p.contextObject148),
                    p.renderMatchMask);
                break;

            case TraceKind::MatrixRouteCoverage:
                g_log->info(
                    "MATRIX_ROUTE,tick={},tid={},playing=0x{:08X},event=0x{:08X},"
                    "key=0x{:016X},source=0x{:08X},body=0x{:016X},route={},"
                    "source_mask=0x{:08X},destination_mask=0x{:08X},from_active_render={},"
                    "node=0x{:016X},context=0x{:016X},match_mask=0x{:X},caller=0x{:016X}",
                    p.tick, p.tid, p.playingId, p.eventId, p.objectKey, p.source,
                    static_cast<std::uint64_t>(p.body), p.route,
                    p.sourceMask, p.destinationMask, p.fromActiveRender,
                    static_cast<std::uint64_t>(p.node),
                    static_cast<std::uint64_t>(p.context), p.renderMatchMask,
                    static_cast<std::uint64_t>(p.matrixCaller));
                break;

            case TraceKind::LowLevelRoute:
                g_log->info(
                    "LOWLEVEL_ROUTE,tick={},tid={},playing=0x{:08X},event=0x{:08X},"
                    "key=0x{:016X},source=0x{:08X},body=0x{:016X},via_matrix={},route={},"
                    "source_mask=0x{:08X},destination_mask=0x{:08X},frames={},"
                    "gain_start={:.6f},gain_delta={:.6f},matrix_caller=0x{:016X},low_caller=0x{:016X}",
                    p.tick, p.tid, p.playingId, p.eventId, p.objectKey, p.source,
                    static_cast<std::uint64_t>(p.body), p.lowViaMatrix, p.route,
                    p.sourceMask, p.destinationMask, p.lowFrames,
                    FloatFromBits(p.gainStartBits), FloatFromBits(p.gainDeltaBits),
                    static_cast<std::uint64_t>(p.matrixCaller),
                    static_cast<std::uint64_t>(p.lowCaller));
                break;
            }
        }

        read = sequence;
        ++flushed;
    }

    g_traceRead.store(read, std::memory_order_release);

    const auto now = GetTickCount64();
    auto prior = g_summaryTick.load(std::memory_order_relaxed);
    if (g_log && now - prior >= kSummaryIntervalMs &&
        g_summaryTick.compare_exchange_strong(
            prior, now,
            std::memory_order_relaxed,
            std::memory_order_relaxed))
    {
        g_log->info(
            "COVERAGE_SUMMARY,tick={},source_events={},source_valid={},source_invalid={},"
            "tls_matches={},playing_matches={},render_calls={},render_tracked={},"
            "render_playing={},render_object={},render_dual={},render_unidentified={},"
            "matrix_calls={},matrix_active={},matrix_tracked={},route1={},route2={},route3={},route_other={},"
            "low_calls={},low_tracked={},low_via_matrix={},low_via_render={},"
            "trace_queued={},trace_flushed={},trace_dropped={}",
            now,
            g_sourceEvents.load(std::memory_order_relaxed),
            g_sourceRecordsValid.load(std::memory_order_relaxed),
            g_sourceRecordsInvalid.load(std::memory_order_relaxed),
            g_tlsEventMatches.load(std::memory_order_relaxed),
            g_playingIdMatches.load(std::memory_order_relaxed),
            g_renderNodeCalls.load(std::memory_order_relaxed),
            g_renderTrackedCalls.load(std::memory_order_relaxed),
            g_renderPlayingIdentity.load(std::memory_order_relaxed),
            g_renderObjectIdentity.load(std::memory_order_relaxed),
            g_renderDualIdentity.load(std::memory_order_relaxed),
            g_renderUnidentifiedCalls.load(std::memory_order_relaxed),
            g_matrixCalls.load(std::memory_order_relaxed),
            g_matrixActiveCalls.load(std::memory_order_relaxed),
            g_matrixTrackedCalls.load(std::memory_order_relaxed),
            g_matrixTrackedRoute1.load(std::memory_order_relaxed),
            g_matrixTrackedRoute2.load(std::memory_order_relaxed),
            g_matrixTrackedRoute3.load(std::memory_order_relaxed),
            g_matrixTrackedOther.load(std::memory_order_relaxed),
            g_lowLevelCalls.load(std::memory_order_relaxed),
            g_lowLevelTrackedCalls.load(std::memory_order_relaxed),
            g_lowLevelTrackedViaMatrix.load(std::memory_order_relaxed),
            g_lowLevelTrackedViaRender.load(std::memory_order_relaxed),
            g_traceWrite.load(std::memory_order_relaxed),
            g_traceRead.load(std::memory_order_relaxed),
            g_traceDropped.load(std::memory_order_relaxed));
        g_log->info(
            "SINK_OBSERVER_SUMMARY,tick={},f7_hold={},f8_disabled={},"
            "sink_calls={},sink_forced_silence={},sink_skipped={},sink=0x{:016X},sink_vtable=0x{:016X},sink_frames={},"
            "primary_calls={},alternate_calls={}",
            now,
            g_holdWorldAuditionMute.load(std::memory_order_relaxed) ? 1 : 0,
            g_holdDirectHrtf.load(std::memory_order_relaxed) ? 1 : 0,
            g_sinkPumpCalls.load(std::memory_order_relaxed),
            g_sinkForcedSilenceCalls.load(std::memory_order_relaxed),
            g_sinkSkippedCalls.load(std::memory_order_relaxed),
            static_cast<std::uint64_t>(g_lastSinkObject.load(std::memory_order_relaxed)),
            static_cast<std::uint64_t>(g_lastSinkVtable.load(std::memory_order_relaxed)),
            g_lastSinkFrames.load(std::memory_order_relaxed),
            g_primaryFamilyCalls.load(std::memory_order_relaxed),
            g_alternateFamilyCalls.load(std::memory_order_relaxed));
        LogSubmitSummary039();
        g_log->flush();
    }

    g_flushBusy.store(false, std::memory_order_release);
}

int* __fastcall SourcePostEventHook(
    std::int64_t body,
    int* outResult,
    std::uint32_t eventId)
{
    g_sourceEvents.fetch_add(1, std::memory_order_relaxed);

    const auto bodyPtr = static_cast<std::uintptr_t>(body);
    std::uint32_t sourceBefore = 0;
    ReadBodySource(bodyPtr, sourceBefore);

    PendingFoxPost* pending = nullptr;
    if (bodyPtr != 0 && g_pendingFoxDepth < kPendingFoxDepth) {
        pending = &g_pendingFoxPosts[g_pendingFoxDepth++];
        *pending = PendingFoxPost{};
        pending->body = bodyPtr;
        pending->eventId = eventId;
        pending->sourceBefore = sourceBefore;
    }

    // Use an existing handle when available; nested posts can bridge without it.
    if (sourceBefore != 0) {
        RememberFoxEvent(sourceBefore, bodyPtr, eventId, GetTickCount64());
    }

    int* result = g_sourcePostOriginal(body, outResult, eventId);

    std::uint32_t sourceAfter = 0;
    ReadBodySource(bodyPtr, sourceAfter);
    if (sourceBefore == 0 && sourceAfter != 0) {
        g_sourceZeroBeforeNonzeroAfter.fetch_add(1, std::memory_order_relaxed);
    }
    if (sourceBefore != sourceAfter) {
        g_sourceChangedAcrossCall.fetch_add(1, std::memory_order_relaxed);
    }
    if (sourceAfter != 0) {
        RememberFoxEvent(sourceAfter, bodyPtr, eventId, GetTickCount64());
    }

    PendingFoxPost pendingCopy{};
    bool hadPending = false;
    if (pending != nullptr) {
        pendingCopy = *pending;
        hadPending = true;
        if (g_pendingFoxDepth != 0) --g_pendingFoxDepth;
    }

    std::int32_t status = 0x7fffffff;
    if (result && IsReadable(result, sizeof(status))) {
        std::memcpy(&status, result, sizeof(status));
    }

    const std::uint32_t sourceForRecord = sourceAfter != 0 ? sourceAfter : sourceBefore;
    std::uintptr_t record = 0;
    std::uint64_t objectKey = 0;
    const bool valid = ResolveRecordForSource(sourceForRecord, record, objectKey);
    if (valid) {
        g_sourceRecordsValid.fetch_add(1, std::memory_order_relaxed);
    } else {
        g_sourceRecordsInvalid.fetch_add(1, std::memory_order_relaxed);
    }

    std::uintptr_t tableBase = 0;
    std::uintptr_t candidateRecord = 0;
    std::uint32_t candidateStoredSource = 0;
    std::uint64_t candidateStoredKey = 0;
    InspectRecordCandidate(
        sourceForRecord,
        tableBase,
        candidateRecord,
        candidateStoredSource,
        candidateStoredKey);

    if (sourceForRecord != 0 && candidateStoredSource == sourceForRecord) {
        g_tableSourceMatches.fetch_add(1, std::memory_order_relaxed);
    }
    if (hadPending && pendingCopy.sawMatchingWwisePost &&
        candidateStoredKey == pendingCopy.matchingObjectKey && candidateStoredKey != 0)
    {
        g_tableKeyMatches.fetch_add(1, std::memory_order_relaxed);
    }

    const std::uint64_t derivedKey = sourceForRecord != 0
        ? static_cast<std::uint64_t>((sourceForRecord >> 8) + 1u)
        : 0ull;
    const bool derivedKeyMatch = hadPending && pendingCopy.sawMatchingWwisePost &&
        derivedKey != 0 && derivedKey == pendingCopy.matchingObjectKey;
    if (derivedKeyMatch) {
        g_sourceDerivedKeyMatches.fetch_add(1, std::memory_order_relaxed);
    }

    const std::uint32_t coveragePlaying =
        hadPending && pendingCopy.matchingPostResult > 0
            ? static_cast<std::uint32_t>(pendingCopy.matchingPostResult)
            : 0u;
    const std::uint64_t coverageKey =
        hadPending && pendingCopy.sawMatchingWwisePost
            ? pendingCopy.matchingObjectKey
            : objectKey;
    CoverageObserveSource(
        bodyPtr, eventId, sourceForRecord, coverageKey, coveragePlaying,
        GetTickCount64());

    TracePayload trace{};
    trace.kind = TraceKind::SourceRecord;
    trace.tick = GetTickCount64();
    trace.tid = GetCurrentThreadId();
    trace.eventId = eventId;
    trace.source = sourceForRecord;
    trace.sourceBefore = sourceBefore;
    trace.sourceAfter = sourceAfter;
    trace.body = bodyPtr;
    trace.record = valid ? record : 0;
    trace.objectKey = valid ? static_cast<std::uint64_t>(objectKey) : 0;
    trace.tableBase = tableBase;
    trace.candidateRecord = candidateRecord;
    trace.candidateStoredSource = candidateStoredSource;
    trace.candidateStoredKey = static_cast<std::uint32_t>(candidateStoredKey);
    trace.candidateStoredKey64 = candidateStoredKey;
    trace.derivedObjectKey = derivedKey;
    trace.derivedKeyMatch = derivedKeyMatch ? 1u : 0u;
    if (hadPending && pendingCopy.sawMatchingWwisePost) {
        trace.nestedObjectKey = pendingCopy.matchingObjectKey;
        trace.nestedPostResult = pendingCopy.matchingPostResult;
        trace.tlsMatch = 1;
    }
    trace.result = status;
    EnqueueTrace(trace);

    return result;
}

void __fastcall SourceTransformSyncHook(std::int64_t body) {
    const auto bodyPtr = static_cast<std::uintptr_t>(body);
    std::uint32_t source = 0;
    if (bodyPtr != 0) ReadBodySource(bodyPtr, source);

    std::uint32_t payload[8]{};
    const auto now = GetTickCount64();

    // Update every transform; limit SOURCE_XFORM logging to once per 500 ms.
    const bool havePayload =
        bodyPtr != 0 && CaptureNormalAudioTransform(body, payload);
    if (havePayload && source != 0) {
        RememberFoxTransform(source, bodyPtr, payload, now);
    }

    const bool emitTransform =
        havePayload && ShouldEmitBodyTransform(bodyPtr, now);
    if (emitTransform) {
        g_sourceTransforms.fetch_add(1, std::memory_order_relaxed);
    }

    g_transformOriginal(body);

    if (emitTransform) {
        TracePayload trace{};
        trace.kind = TraceKind::SourceTransform;
        trace.tick = now;
        trace.tid = GetCurrentThreadId();
        trace.source = source;
        trace.body = bodyPtr;
        trace.xBits = payload[4];
        trace.yBits = payload[5];
        trace.zBits = payload[6];
        EnqueueTrace(trace);
    }
}

int __fastcall WwisePostGatewayHook(
    std::uint32_t eventId,
    std::uint64_t objectKey,
    std::uint32_t param3,
    std::uint64_t param4,
    std::uint64_t param5,
    int param6,
    std::uint64_t param7,
    std::uint32_t param8)
{
    g_wwisePosts.fetch_add(1, std::memory_order_relaxed);

    const auto now = GetTickCount64();
    const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());

    std::uint32_t source = 0;
    std::uintptr_t record = 0;
    const auto recordMatches = FindRecordsByObjectKey(
        objectKey, source, record);

    std::uintptr_t body = 0;
    std::uint32_t foxEvent = 0;
    PendingFoxPost* pendingFox = FindPendingFoxPost(eventId);
    if (pendingFox != nullptr) {
        // Match a nested Wwise post to the current Fox body and event,
        // even before body+0x80 has been assigned.
        body = pendingFox->body;
        foxEvent = pendingFox->eventId;
        if (source == 0 && pendingFox->sourceBefore != 0) {
            source = pendingFox->sourceBefore;
        }
        pendingFox->matchingObjectKey = objectKey;
        pendingFox->sawMatchingWwisePost = true;
        g_tlsEventMatches.fetch_add(1, std::memory_order_relaxed);
    } else if (recordMatches == 1 && source != 0) {
        LookupFox(source, body, foxEvent, now);
        g_wwisePostsWithRecord.fetch_add(1, std::memory_order_relaxed);
    }

    // Publish before the original call queues work for the audio thread.
    RememberKey(
        objectKey, eventId, source, body, record, recordMatches, now);

    const int result = g_wwisePostOriginal(
        eventId, objectKey, param3, param4, param5, param6, param7, param8);

    if (pendingFox != nullptr) {
        pendingFox->matchingPostResult = result;
    }

    UpdateKeyPostResult(objectKey, result);

    IdentityMeta meta{};
    meta.key = objectKey;
    meta.eventId = eventId;
    meta.source = source;
    meta.body = body;
    meta.record = record;
    meta.recordMatches = recordMatches;
    meta.postResult = result;

    // Record the post return value separately to check against action+0x38.
    if (result != 0) {
        RememberPlaying(static_cast<std::uint32_t>(result), meta, GetTickCount64());
    }

    // Census includes posts without a known Fox body.
    {
        TracePayload trace{};
        trace.kind = TraceKind::WwisePost;
        trace.tick = GetTickCount64();
        trace.tid = GetCurrentThreadId();
        trace.eventId = eventId;
        trace.foxEventId = foxEvent;
        trace.source = source;
        trace.body = body;
        trace.record = record;
        trace.objectKey = objectKey;
        trace.recordMatches = recordMatches;
        trace.result = result;
        trace.tlsMatch = pendingFox != nullptr ? 1u : 0u;
        trace.caller = caller;
        EnqueueTrace(trace);
    }

    return result;
}

void __fastcall PlayingEventPackHook(
    std::uint32_t* outPair,
    std::uint32_t playingId,
    std::uint32_t eventId)
{
    g_playingEventPackCalls.fetch_add(1, std::memory_order_relaxed);
    g_playingEventPackOriginal(outPair, playingId, eventId);

    std::uint32_t out0 = 0;
    std::uint32_t out1 = 0;
    if (outPair != nullptr && IsReadable(outPair, sizeof(std::uint32_t) * 2)) {
        std::memcpy(&out0, outPair, sizeof(out0));
        std::memcpy(&out1, outPair + 1, sizeof(out1));
    }

    IdentityMeta meta{};
    const bool tracked = LookupPlaying(playingId, meta, GetTickCount64()) &&
                         meta.eventId == eventId;
    if (tracked) g_playingEventPackTracked.fetch_add(1, std::memory_order_relaxed);

    // Static callers strongly suggest {playing,event}; prove it at runtime.
    const bool outputMatches = out0 == playingId && out1 == eventId;
    if (outputMatches) {
        g_playingEventPackOutputMatches.fetch_add(1, std::memory_order_relaxed);
    }

    if (tracked && meta.body != 0) {
        TracePayload trace{};
        trace.kind = TraceKind::PlayingEventPack;
        trace.tick = GetTickCount64();
        trace.tid = GetCurrentThreadId();
        trace.eventId = eventId;
        trace.playingId = playingId;
        trace.packOut0 = out0;
        trace.packOut1 = out1;
        trace.matchMode = 1u;
        trace.objectKey = meta.key;
        trace.source = meta.source;
        trace.body = meta.body;
        trace.record = meta.record;
        trace.caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
        EnqueueTrace(trace);
    }
}

void __fastcall VoiceRenderNodeHook(std::int64_t audioBufferLike) {
    g_renderNodeCalls.fetch_add(1, std::memory_order_relaxed);

    const auto audioBuffer = static_cast<std::uintptr_t>(audioBufferLike);
    std::uintptr_t node = 0;
    std::uintptr_t wrapper = 0;
    std::uintptr_t context = 0;

    if (audioBuffer != 0 && SafeReadValue(audioBuffer + 0x40, node) && node != 0) {
        if (SafeReadValue(node + 0x10, wrapper) && wrapper != 0) {
            SafeReadValue(wrapper + 0x18, context);
        }
    }

    const auto now = GetTickCount64();
    std::uint32_t playingId = 0;
    std::uintptr_t objectA8 = 0;
    std::uintptr_t object148 = 0;
    if (context != 0) {
        SafeReadValue(context + 0x70, playingId);
        SafeReadValue(context + 0xA8, objectA8);
        SafeReadValue(context + 0x148, object148);
    }

    IdentityMeta playingMeta{};
    IdentityMeta objectMetaA8{};
    IdentityMeta objectMeta148{};
    const bool playingMatch =
        playingId != 0 && LookupPlaying(playingId, playingMeta, now) &&
        playingMeta.body != 0;
    const bool objectA8Match =
        objectA8 != 0 && LookupObject(objectA8, objectMetaA8, now) &&
        objectMetaA8.body != 0;
    const bool object148Match =
        object148 != 0 && LookupObject(object148, objectMeta148, now) &&
        objectMeta148.body != 0;

    IdentityMeta selected{};
    std::uint32_t matchMask = 0;
    if (playingMatch) {
        selected = playingMeta;
        matchMask |= 0x1u;
        g_renderPlayingIdentity.fetch_add(1, std::memory_order_relaxed);
        if (objectA8Match && SameIdentity(playingMeta, objectMetaA8)) {
            matchMask |= 0x2u;
        }
        if (object148Match && SameIdentity(playingMeta, objectMeta148)) {
            matchMask |= 0x4u;
        }
    }
    else if (objectA8Match) {
        selected = objectMetaA8;
        matchMask |= 0x2u;
        if (object148Match && SameIdentity(objectMetaA8, objectMeta148)) {
            matchMask |= 0x4u;
        }
    }
    else if (object148Match) {
        selected = objectMeta148;
        matchMask |= 0x4u;
    }

    if ((matchMask & 0x6u) != 0) {
        g_renderObjectIdentity.fetch_add(1, std::memory_order_relaxed);
    }
    if ((matchMask & 0x1u) != 0 && (matchMask & 0x6u) != 0) {
        g_renderDualIdentity.fetch_add(1, std::memory_order_relaxed);
    }

    if (selected.body != 0) {
        g_renderTrackedCalls.fetch_add(1, std::memory_order_relaxed);
        const auto selectedPlaying = playingId != 0
            ? playingId
            : (selected.postResult > 0
                ? static_cast<std::uint32_t>(selected.postResult) : 0u);
        CoverageObserveRender(
            selected.body, selected.eventId, selected.source, selected.key,
            selectedPlaying, matchMask, now);

        // Refresh identity while the live context still references the same object or playing ID.
        const std::uintptr_t verifiedObject =
            (playingMatch && objectA8Match && SameIdentity(selected, objectMetaA8))
                ? objectA8
                : ((playingMatch && object148Match && SameIdentity(selected, objectMeta148))
                    ? object148
                    : (objectA8Match ? objectA8 : (object148Match ? object148 : 0)));
        RenewVerifiedIdentity(selectedPlaying, verifiedObject, selected, now);

        if (ShouldTraceCoverageRender(selected.body, selected.eventId, now)) {
            TracePayload trace{};
            trace.kind = TraceKind::ActiveRenderBind;
            trace.tick = now;
            trace.tid = GetCurrentThreadId();
            trace.playingId = selectedPlaying;
            trace.eventId = selected.eventId;
            trace.objectKey = selected.key;
            trace.source = selected.source;
            trace.body = selected.body;
            trace.record = selected.record;
            trace.node = node;
            trace.context = context;
            trace.contextObjectA8 = objectA8;
            trace.contextObject148 = object148;
            trace.renderMatchMask = matchMask;
            EnqueueTrace(trace);
        }
    }
    else {
        g_renderUnidentifiedCalls.fetch_add(1, std::memory_order_relaxed);
    }

    Scope040 trace040(1,reinterpret_cast<std::uintptr_t>(_ReturnAddress()),audioBuffer,audioBuffer);
    trace040.e.body=selected.body; trace040.e.matches=matchMask; trace040.Emit(0);
    const auto priorTls = g_renderTls;
    if (selected.body != 0) {
        g_renderTls.active = true;
        g_renderTls.meta = selected;
        g_renderTls.playingId = playingId != 0
            ? playingId
            : (selected.postResult > 0
                ? static_cast<std::uint32_t>(selected.postResult) : 0u);
        g_renderTls.node = node;
        g_renderTls.wrapper = wrapper;
        g_renderTls.context = context;
        g_renderTls.matchMask = matchMask;
    }
    else {
        g_renderTls = RenderTlsScope{};
    }

    g_voiceRenderOriginal(audioBufferLike);
    trace040.Emit(1);
    g_renderTls = priorTls;
}

std::int64_t __fastcall WwiseGameObjectLookupHook(
    std::int64_t manager,
    std::uint64_t objectKey)
{
    g_gameObjectLookups.fetch_add(1, std::memory_order_relaxed);

    const auto now = GetTickCount64();
    IdentityMeta meta{};
    const bool tracked = LookupKey(objectKey, meta, now);

    const auto object = g_gameObjectLookupOriginal(manager, objectKey);

    if (!tracked) return object;

    g_gameObjectLookupsTracked.fetch_add(1, std::memory_order_relaxed);
    if (object != 0) {
        RememberObject(static_cast<std::uintptr_t>(object), meta, GetTickCount64());
    }

    // Log only the first successful lookup for each posted key.
    if (!ShouldTraceFirstLookup(objectKey, static_cast<std::uintptr_t>(object))) {
        return object;
    }

    TracePayload trace{};
    trace.kind = TraceKind::GameObjectLookup;
    trace.tick = GetTickCount64();
    trace.tid = GetCurrentThreadId();
    trace.eventId = meta.eventId;
    trace.source = meta.source;
    trace.body = meta.body;
    trace.record = meta.record;
    trace.objectKey = objectKey;
    trace.result = meta.postResult;
    trace.object = static_cast<std::uintptr_t>(object);
    trace.caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    EnqueueTrace(trace);

    return object;
}

void __fastcall PlaybackActionDispatchHook(
    std::int64_t runtime,
    std::int64_t actionValue)
{
    g_actionDispatches.fetch_add(1, std::memory_order_relaxed);

    const auto action = static_cast<std::uintptr_t>(actionValue);
    if (action == 0) {
        g_actionDispatchOriginal(runtime, actionValue);
        return;
    }

    // These fields are also read by FUN_140347E00 at entry.
    const auto eventNode =
        *reinterpret_cast<const std::uintptr_t*>(action + 0x08);
    const auto playingId =
        *reinterpret_cast<const std::uint32_t*>(action + 0x38);
    const auto actionRaw44 =
        *reinterpret_cast<const std::uint32_t*>(action + 0x44);
    const auto gameObject =
        *reinterpret_cast<const std::uintptr_t*>(action + 0x48);

    IdentityMeta meta{};
    std::uint32_t matchMode = 0;
    const auto now = GetTickCount64();

    if (LookupPlaying(playingId, meta, now)) {
        matchMode = 1;
        g_playingIdMatches.fetch_add(1, std::memory_order_relaxed);
    }
    else if (LookupObject(gameObject, meta, now)) {
        matchMode = 2;
        g_objectFallbackMatches.fetch_add(1, std::memory_order_relaxed);
    }

    if (matchMode != 0) {
        g_actionDispatchesTracked.fetch_add(1, std::memory_order_relaxed);

        std::uintptr_t eventVtable = 0;
        std::uintptr_t executeV40 = 0;
        std::uint32_t nodeType = 0;

        if (eventNode != 0) {
            eventVtable =
                *reinterpret_cast<const std::uintptr_t*>(eventNode + 0x00);
            nodeType = static_cast<std::uint32_t>(
                *reinterpret_cast<const std::uint16_t*>(eventNode + 0x34));
            if (eventVtable != 0) {
                executeV40 =
                    *reinterpret_cast<const std::uintptr_t*>(eventVtable + 0x40);
            }
        }

        TracePayload trace{};
        trace.kind = TraceKind::PlayAction;
        trace.tick = now;
        trace.tid = GetCurrentThreadId();
        trace.eventId = meta.eventId;
        trace.source = meta.source;
        trace.body = meta.body;
        trace.record = meta.record;
        trace.objectKey = meta.key;
        trace.object = gameObject;
        trace.action = action;
        trace.playingId = playingId;
        trace.matchMode = matchMode;
        trace.eventNode = eventNode;
        trace.eventVtable = eventVtable;
        trace.executeV40 = executeV40;
        trace.nodeType = nodeType;
        trace.actionRaw44 = actionRaw44;
        trace.caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
        EnqueueTrace(trace);
    }

    g_actionDispatchOriginal(runtime, actionValue);
}


void __fastcall SinkPumpHook(std::int64_t sinkValue) {
    const auto sink = static_cast<std::uintptr_t>(sinkValue);
    g_sinkPumpCalls.fetch_add(1, std::memory_order_relaxed);
    g_lastSinkObject.store(sink, std::memory_order_relaxed);
    std::uintptr_t vt = 0, gate = 0;
    std::uint16_t frames = 0;
    if (SafeReadValue(sink, vt) && vt == g_exeBase + 0x21358F0ull) RememberSink039(sink);
    SafeReadValue(sink + 0x32, frames);
    g_lastSinkVtable.store(vt, std::memory_order_relaxed);
    g_lastSinkFrames.store(frames, std::memory_order_relaxed);
    if (!SafeReadValue(g_exeBase + 0x2B9FA28ull, gate)) g_gateUnreadable039.fetch_add(1);
    else if (gate == 0) g_gateZero039.fetch_add(1);
    else g_gateNonzero039.fetch_add(1);
    g_sinkPumpOriginal(sinkValue);
}

std::atomic<std::uint64_t> g_lastApplied048{0},g_lastAttempt048{0};
std::array<std::atomic<std::uint64_t>,5> g_playingStages048{},g_objectStages048{};
std::atomic<std::uint64_t> g_route2Seen048{0},g_route2Dual048{0};
// 0 missing key,1 no cache slot,2 expired/uninitialized,3 no Fox body,4 bound.
unsigned PlayingStage048(std::uint32_t id,std::uint64_t now) {
    if(!id) return 0;
    auto* p=FindPlayingSlot(id,false);if(!p) return 1;
    const auto t=p->tick.load();if(!t || (now>t && now-t>kRecentIdentityTtlMs)) return 2;
    return p->body.load()?4u:3u;
}
unsigned ObjectStage048(std::uintptr_t object,std::uint64_t now) {
    if(!object) return 0;
    auto* p=FindObjectSlot(object,false);if(!p) return 1;
    const auto t=p->tick.load();if(!t || (now>t && now-t>kRecentIdentityTtlMs)) return 2;
    return p->body.load()?4u:3u;
}
// Shared with the HUD: 0=native,1=recent processing,2=recent fallback,3=no recent eligible source.
unsigned Activity048(unsigned mode,std::uint64_t now,std::uint64_t applied,std::uint64_t attempted) {
    if(!mode) return 0;
    if(applied && now>=applied && now-applied<=1500) return 1;
    if(attempted && now>=attempted && now-attempted<=1500) return 2;
    return 3;
}

// global world-source trial. 0=native, 1=hybrid, 2=pure HRIR.
std::atomic<unsigned> g_worldMode047{2}; // default: pure (DF-EQ filters make the hybrid crossover unnecessary)
std::atomic<std::uint64_t> g_worldEpoch047{1},g_worldAttempts047{0},g_worldApplied047{0},g_worldFallback047{0};
std::atomic<std::uint64_t> g_worldMono047{0},g_worldStereo047{0},g_worldQuad047{0},g_worldLayout047{0};
bool WorldEligible047(bool dual,std::uintptr_t body,std::uint32_t playing,
    unsigned route,unsigned sourceMask,unsigned destinationMask,std::uint16_t frames) {
    return dual && body && playing && route==2 && destinationMask==3 && frames &&
        (sourceMask==4 || sourceMask==3 || sourceMask==0x33);
}
void PrepareWorldHistory047(BinauralHistoryState& history,std::uintptr_t body,std::uint32_t playing,
    std::uint64_t epoch,std::uint64_t now) {
    if(history.ownerBody047!=body || history.ownerPlaying047!=playing ||
        history.ownerEpoch047!=epoch || now-history.lastTick047>250) {
        history.initialized=false;history.writeIndex=0;
        history.ownerBody047=body;history.ownerPlaying047=playing;history.ownerEpoch047=epoch;
    }
    history.lastTick047=now;
}
void Control047() {
    static bool prior8=false,prior9=false,prior11=false;
    static unsigned preferred=2;
    static std::uint64_t last=0;
    const bool f8=AudioKey062(VK_F8);
    const bool f9=AudioKey062(VK_F9);
    const bool f11=AudioKey062(VK_F11);
    unsigned mode=g_worldMode047.load();const auto old=mode;
    if(f9 && !prior9) mode=0;
    else if(f11 && !prior11) { preferred=preferred==1?2:1;mode=preferred; }
    else if(f8 && !prior8) mode=mode?0:preferred;
    if(mode!=old) { ++g_worldEpoch047;g_worldMode047.store(mode); }
    const auto now=GetTickCount64();
    if(g_log && (mode!=old || now-last>=60000)) {
        g_log->info("WORLD049,mode={},attempts={},applied={},fallback={},mono={},stereo={},quad={},unsupported_layout={},history_resets={}",
            mode,g_worldAttempts047.load(),g_worldApplied047.load(),g_worldFallback047.load(),
            g_worldMono047.load(),g_worldStereo047.load(),g_worldQuad047.load(),g_worldLayout047.load(),g_binauralHistoryResets.load());
        g_log->info("COVERAGE048,tick={},route2={},dual={},playing_missing_key={},playing_no_slot={},playing_expired={},playing_no_body={},playing_bound={},object_missing_key={},object_no_slot={},object_expired={},object_no_body={},object_bound={},activity={}",
            now,g_route2Seen048.load(),g_route2Dual048.load(),
            g_playingStages048[0].load(),g_playingStages048[1].load(),g_playingStages048[2].load(),g_playingStages048[3].load(),g_playingStages048[4].load(),
            g_objectStages048[0].load(),g_objectStages048[1].load(),g_objectStages048[2].load(),g_objectStages048[3].load(),g_objectStages048[4].load(),
            Activity048(mode,now,g_lastApplied048.load(),g_lastAttempt048.load()));
        g_log->flush();last=now;
    }
    prior8=f8;prior9=f9;prior11=f11;
}

// Track consumed positions by native object. Constructor key is at +0x70.
struct NativePosition050 {
    std::uintptr_t object=0;
    std::uint64_t key=0,generation=0,epoch=0;
    float xyz[3]{};
    bool valid=false;
};
std::array<NativePosition050,4096> g_nativePositions050{};
std::atomic_flag g_nativeLock050=ATOMIC_FLAG_INIT;
std::atomic<std::uint64_t> g_nativeEpoch050{1},g_nativeGeneration050{1};
std::atomic<std::uint64_t> g_nativeUpdates050{0},g_nativeValid050{0},g_nativeDrops050{0},g_nativeMulti050{0};
std::atomic<std::uint64_t> g_nativeCandidates050{0},g_nativeApplied050{0},g_nativeMuted050{0},g_nativeFallback050{0},g_nativeAmbiguous050{0};
// Native processing also accepts stereo 0x3 and quad 0x33 layouts.
std::atomic<bool> g_nativeWide051{true}; // default: MONO+STEREO
std::atomic<std::uint64_t> g_nativeCandMono051{0},g_nativeCandStereo051{0},g_nativeCandQuad051{0};
std::atomic<std::uint64_t> g_nativeAppliedMono051{0},g_nativeAppliedStereo051{0},g_nativeAppliedQuad051{0};
std::atomic<bool> g_nativeEnabled050{true},g_nativeReady050{false}; // default ON
std::atomic<bool> g_nativeMute050{false};
// Native position rejection counters.
std::atomic<std::uint64_t> g_setOutOfScope052{0},g_setKeyMismatch052{0},g_setMode052{0},
    g_setStorage052{0},g_setNonFinite052{0},g_setCountZero052{0};
// Out-of-scope setter callers (return addresses), bounded table.
std::array<std::atomic<std::uintptr_t>,8> g_oosCaller052{};
std::array<std::atomic<std::uint64_t>,8> g_oosCallerHits052{};
std::atomic<std::uint64_t> g_oosCallerOverflow052{0};
// Bounded samples of out-of-scope positions so we can see if they are real world positions.
std::atomic<std::uint32_t> g_oosSamples052{0};
struct OosSample052 { std::uintptr_t caller=0,object=0; std::uint64_t key=0; std::uint32_t mode=0; std::uint16_t count=0; float xyz[3]{}; };
std::array<OosSample052,48> g_oosSampleRows052{};
// Lookup states: 1 null, 2 unseen, 3 invalid, 4 stale or changed.
std::array<std::atomic<std::uint64_t>,5> g_singleFail052{};   // one object: by state
std::array<std::atomic<std::uint64_t>,5> g_pairA8Fail052{};   // pair, A8 missing (148 ok): by A8 state
std::array<std::atomic<std::uint64_t>,5> g_pair148Fail052{};  // pair, 148 missing (A8 ok): by 148 state
std::atomic<std::uint64_t> g_pairBothFail052{0},g_pairKeyDiff052{0};
std::array<std::atomic<std::uint64_t>,4> g_pairPosDiff052{}; // distance <0.5, <5, <50, >=50
// Gate rejections before lookup, for route-2 non-Fox voices.
std::atomic<std::uint64_t> g_gateNoPlaying052{0},g_gateDest052{0},g_gateLayout052{0},g_gateLfe052{0};
std::atomic<std::uint64_t> g_foxMuted052{0};
// Surround-bed state and counters.
std::atomic<bool> g_bedSkip71_057{false},g_bedLevelMatch057{true};
std::atomic<bool> g_bedImplicitFold058{true};
std::atomic<std::uint64_t> g_bedImplicit058{0};
std::atomic<std::uint64_t> g_bedMakeupLarge057{0};
std::atomic<bool> g_bedEnabled055{true};
std::atomic<std::uint64_t> g_bedApplied055{0},g_bedMuted055{0},g_bedFail055{0},g_bedBusy055{0},g_bedPeakGuard055{0};
std::atomic<std::uint64_t> g_bedQuad055{0},g_bedFive055{0},g_bedSeven055{0},g_bedOther055{0};
void NoteOosCaller052(std::uintptr_t caller) {
    for(auto i=0u;i<g_oosCaller052.size();++i){
        auto cur=g_oosCaller052[i].load(std::memory_order_relaxed);
        if(cur==caller){++g_oosCallerHits052[i];return;}
        if(cur==0){
            std::uintptr_t expected=0;
            if(g_oosCaller052[i].compare_exchange_strong(expected,caller)||expected==caller){++g_oosCallerHits052[i];return;}
        }
    }
    ++g_oosCallerOverflow052;
}
thread_local bool g_nativeScope050=false;
#if defined(_MSC_VER)
#define NATIVE_CALLER052() reinterpret_cast<std::uintptr_t>(_ReturnAddress())
#else
#define NATIVE_CALLER052() reinterpret_cast<std::uintptr_t>(__builtin_return_address(0))
#endif
thread_local std::uint64_t g_nativeScopeKey050=0;
using NativeCtor050=std::uintptr_t(__fastcall*)(std::uintptr_t,std::uint64_t);
using NativeSet050=void(__fastcall*)(std::uintptr_t,const float*,std::uint16_t,std::uint32_t);
using NativeDispatch050=std::uint64_t(__fastcall*)(std::uintptr_t,std::uint64_t,const float*,std::uint16_t,std::uint32_t);
NativeCtor050 g_nativeCtorOriginal050=nullptr;
NativeSet050 g_nativeSetOriginal050=nullptr;
NativeDispatch050 g_nativeDispatchOriginal050=nullptr;
std::size_t NativeIndex050(std::uintptr_t object) { return ((object>>4)^(object>>16))&4095; }
void StoreNative050(std::uintptr_t object,std::uint64_t key,const float* xyz,bool reset) {
    if(g_nativeLock050.test_and_set(std::memory_order_acquire)) {
        ++g_nativeDrops050; ++g_nativeEpoch050; return; // invalidate old observations on a lost update
    }
    auto& slot=g_nativePositions050[NativeIndex050(object)];
    if(reset || slot.object!=object || slot.key!=key) {
        slot=NativePosition050{};slot.generation=++g_nativeGeneration050;
    }
    slot.object=object;slot.key=key;slot.epoch=g_nativeEpoch050.load();
    slot.valid=xyz!=nullptr;
    if(xyz)for(unsigned i=0;i<3;++i)slot.xyz[i]=xyz[i];
    g_nativeLock050.clear(std::memory_order_release);
}
bool CopyNative050(std::uintptr_t object,NativePosition050& out) {
    if(!object || g_nativeLock050.test_and_set(std::memory_order_acquire))return false;
    out=g_nativePositions050[NativeIndex050(object)];
    const bool ok=out.object==object && out.valid && out.epoch==g_nativeEpoch050.load();
    g_nativeLock050.clear(std::memory_order_release);
    return ok;
}
std::uintptr_t __fastcall NativeCtorHook050(std::uintptr_t object,std::uint64_t key) {
    StoreNative050(object,key,nullptr,true);
    return g_nativeCtorOriginal050(object,key);
}
void __fastcall NativeSetHook050(std::uintptr_t object,const float* positions,std::uint16_t count,std::uint32_t mode) {
    // Capture from the consumer, not the producer queue, so position order matches playback.
    float xyz[3]{};
    const bool captured=count==1 && positions && SafeReadValue(reinterpret_cast<std::uintptr_t>(positions),xyz);
    g_nativeSetOriginal050(object,positions,count,mode);
    ++g_nativeUpdates050;
    if(count>1)++g_nativeMulti050;
    std::uint64_t key=0;std::uint16_t storedCount=0;std::uintptr_t data=0;
    float stored[3]{};
    bool valid=captured && mode<=2 && g_nativeScope050 &&
        SafeReadValue(object+0x70,key) && key && key==g_nativeScopeKey050 &&
        SafeReadValue(object+0x10,storedCount) && storedCount==1 &&
        SafeReadValue(object+8,data) && data && SafeReadValue(data,stored);
    for(unsigned i=0;i<3 && valid;++i)
        valid=std::isfinite(xyz[i]) && std::fabs(xyz[i])<1000000.0f && stored[i]==xyz[i];
    if(!valid) {
        if(count==0) ++g_setCountZero052;
        else if(count>1) {} // already counted as multi_updates
        else if(!g_nativeScope050) {
            ++g_setOutOfScope052;
            const auto caller=NATIVE_CALLER052();
            NoteOosCaller052(caller);
            if(captured && count==1) {
                const auto n=g_oosSamples052.fetch_add(1);
                if(n<g_oosSampleRows052.size()) {
                    auto& r=g_oosSampleRows052[n];
                    std::uint64_t k=0;SafeReadValue(object+0x70,k);
                    r.caller=caller;r.object=object;r.key=k;r.mode=mode;r.count=count;
                    for(unsigned i=0;i<3;++i)r.xyz[i]=xyz[i];
                }
            }
        }
        else if(mode>2) ++g_setMode052;
        else if(!key || key!=g_nativeScopeKey050) ++g_setKeyMismatch052;
        else if(captured && !(std::isfinite(xyz[0])&&std::isfinite(xyz[1])&&std::isfinite(xyz[2]))) ++g_setNonFinite052;
        else ++g_setStorage052;
    }
    // Flip native Z to match Fox world coordinates.
    xyz[2]=-xyz[2];
    if(valid)++g_nativeValid050;
    StoreNative050(object,key,valid?xyz:nullptr,false);
}
std::uint64_t __fastcall NativeDispatchHook050(std::uintptr_t manager,std::uint64_t key,const float* positions,std::uint16_t count,std::uint32_t mode) {
    const bool prior=g_nativeScope050;const auto priorKey=g_nativeScopeKey050;
    g_nativeScope050=true;g_nativeScopeKey050=key;
    const auto result=g_nativeDispatchOriginal050(manager,key,positions,count,mode);
    g_nativeScope050=prior;g_nativeScopeKey050=priorKey;
    return result;
}
bool ReadNative050(std::uintptr_t object,NativePosition050& out) {
    if(!CopyNative050(object,out))return false;
    std::uint64_t key=0;std::uint16_t count=0;
    return SafeReadValue(object+0x70,key) && key==out.key && SafeReadValue(object+0x10,count) && count==1;
}
unsigned ClassifyNative052(std::uintptr_t object) {
    if(!object) return 1;
    if(g_nativeLock050.test_and_set(std::memory_order_acquire)) return 4;
    const auto slot=g_nativePositions050[NativeIndex050(object)];
    g_nativeLock050.clear(std::memory_order_release);
    if(slot.object!=object) return 2;
    if(!slot.valid) return 3;
    return 4;
}
// Read native storage when no cache entry exists.
// Layout: +0x08 position array, +0x10 count, +0x13 mode bits, +0x70 key.
// Verified against setter captures.
std::atomic<std::uint64_t> g_nativeDirect053{0},g_pairA8Preferred053{0};
bool ReadDirect053(std::uintptr_t object,NativePosition050& out) {
    if(!object) return false;
    std::uint64_t key=0;std::uint16_t count=0;std::uint8_t flags13=0;std::uintptr_t data=0;float xyz[3]{};
    if(!SafeReadValue(object+0x70,key) || !key ||
       !SafeReadValue(object+0x10,count) || count!=1 ||
       !SafeReadValue(object+0x13,flags13) || (flags13&7u)>2u ||
       !SafeReadValue(object+8,data) || !data || !SafeReadValue(data,xyz)) return false;
    for(unsigned i=0;i<3;++i) if(!std::isfinite(xyz[i]) || std::fabs(xyz[i])>=1000000.0f) return false;
    if(xyz[0]==0.0f && xyz[1]==0.0f && xyz[2]==0.0f) return false; // default pose is not evidence
    out=NativePosition050{};
    out.object=object;out.key=key;out.valid=true;out.epoch=g_nativeEpoch050.load();
    out.generation=(key*0x9E3779B97F4A7C15ull)^static_cast<std::uint64_t>(object)^0x8000000000000000ull;
    out.xyz[0]=xyz[0];out.xyz[1]=xyz[1];out.xyz[2]=-xyz[2]; // native Z is flipped
    return true;
}
bool ReadAny053(std::uintptr_t object,NativePosition050& out,bool& direct) {
    direct=false;
    if(ReadNative050(object,out)) return true;
    if(ReadDirect053(object,out)) {direct=true;return true;}
    return false;
}
bool ChooseNative050(std::uintptr_t a,std::uintptr_t b,NativePosition050& out) {
    if(!g_nativeReady050.load())return false;
    NativePosition050 x{},y{};
    bool dx=false,dy=false;
    const bool ax=ReadAny053(a,x,dx),by=b && b!=a && ReadAny053(b,y,dy);
    if(a && b && a!=b) {
        if(ax && by) {
            if(x.key!=y.key) {++g_pairKeyDiff052;++g_nativeAmbiguous050;return false;}
            for(unsigned i=0;i<3;++i)if(x.xyz[i]!=y.xyz[i]) {
                const float ex=x.xyz[0]-y.xyz[0],ey=x.xyz[1]-y.xyz[1],ez=x.xyz[2]-y.xyz[2];
                const float d=std::sqrt(ex*ex+ey*ey+ez*ez);
                ++g_pairPosDiff052[d<0.5f?0:(d<5.0f?1:(d<50.0f?2:3))];
                ++g_nativeAmbiguous050;return false;
            }
        }
        else if(ax) {
            // Context+0xA8 is the registered object. An unpositioned +0x148 object is not a conflict.
            ++g_pair148Fail052[ClassifyNative052(b)];++g_pairA8Preferred053;
        }
        else if(by) {++g_pairA8Fail052[ClassifyNative052(a)];++g_nativeAmbiguous050;return false;}
        else {++g_pairBothFail052;return false;}
    }
    if(ax){if(dx)++g_nativeDirect053;out=x;return true;}
    if(by){if(dy)++g_nativeDirect053;out=y;return true;}
    ++g_singleFail052[ClassifyNative052(a?a:b)];
    return false;
}
void ControlNative050() {
    static bool prior10=false;static std::uint64_t last=0;
    const bool f10=AudioKey062(VK_F10);
    bool enabled=g_nativeEnabled050.load();bool changed=false;
    if(f10 && !prior10){
        const bool wide=g_nativeWide051.load();
        if(!enabled){enabled=true;g_nativeWide051.store(false);}
        else if(!wide){g_nativeWide051.store(true);}
        else {enabled=false;g_nativeWide051.store(false);}
        g_nativeEnabled050.store(enabled);++g_worldEpoch047;changed=true;
    }
    static bool prior4=false;
    const bool f4=AudioKey062(VK_F4) && (GetAsyncKeyState(VK_MENU)&0x8000)==0; // ignore Alt+F4
    if(f4 && !prior4){g_elevation059.store(!g_elevation059.load());changed=true;}
    prior4=f4;
    static bool prior5=false;
    const bool f5=AudioKey062(VK_F5);
    if(f5 && !prior5){
        if(g_bedEnabled055.load() && !g_bedSkip71_057.load()) g_bedSkip71_057.store(true);          // ALL -> AMBIENCE
        else if(g_bedEnabled055.load()) {g_bedEnabled055.store(false);g_bedSkip71_057.store(false);} // AMBIENCE -> OFF
        else {g_bedEnabled055.store(true);g_bedSkip71_057.store(false);}                           // OFF -> ALL
        changed=true;
    }
    prior5=f5;
    const bool mute=AudioKey062(VK_F7); // mutes Fox and native paths
    if(g_nativeMute050.exchange(mute)!=mute){++g_worldEpoch047;changed=true;}
    prior10=f10;const auto now=GetTickCount64();
    if(g_log && (changed || now-last>=10000)) {
        g_log->info("NATIVE050,tick={},ready={},enabled={},mute={},updates={},valid_updates={},multi_updates={},drops={},candidates={},applied={},muted={},fallback={},ambiguous={}",
            now,g_nativeReady050.load()?1:0,enabled?1:0,mute?1:0,g_nativeUpdates050.load(),g_nativeValid050.load(),g_nativeMulti050.load(),g_nativeDrops050.load(),g_nativeCandidates050.load(),g_nativeApplied050.load(),g_nativeMuted050.load(),g_nativeFallback050.load(),g_nativeAmbiguous050.load());
        g_log->info("NATIVE051,tick={},state={},cand_mono={},cand_stereo={},cand_quad={},applied_mono={},applied_stereo={},applied_quad={}",
            now,!enabled?"off":(g_nativeWide051.load()?"mono_stereo_quad":"mono"),
            g_nativeCandMono051.load(),g_nativeCandStereo051.load(),g_nativeCandQuad051.load(),
            g_nativeAppliedMono051.load(),g_nativeAppliedStereo051.load(),g_nativeAppliedQuad051.load());
        auto a5=[](const std::array<std::atomic<std::uint64_t>,5>& v){return fmt::format("{}/{}/{}/{}",v[1].load(),v[2].load(),v[3].load(),v[4].load());};
        g_log->info("DIAG052,tick={},set_oos={},set_keymis={},set_mode={},set_storage={},set_nan={},set_count0={},"
            "single_fail[null/unseen/invalid/stale]={},pair_a8_missing={},pair_148_missing={},pair_both_missing={},pair_keydiff={},"
            "pair_posdiff[<0.5/<5/<50/>=50]={}/{}/{}/{},gate_noplaying={},gate_dest={},gate_layout={},gate_lfe={},fox_muted={}",
            now,g_setOutOfScope052.load(),g_setKeyMismatch052.load(),g_setMode052.load(),g_setStorage052.load(),g_setNonFinite052.load(),g_setCountZero052.load(),
            a5(g_singleFail052),a5(g_pairA8Fail052),a5(g_pair148Fail052),g_pairBothFail052.load(),g_pairKeyDiff052.load(),
            g_pairPosDiff052[0].load(),g_pairPosDiff052[1].load(),g_pairPosDiff052[2].load(),g_pairPosDiff052[3].load(),
            g_gateNoPlaying052.load(),g_gateDest052.load(),g_gateLayout052.load(),g_gateLfe052.load(),g_foxMuted052.load());
        g_log->info("NATIVE053,tick={},direct_reads={},a8_preferred_over_unpositioned_148={}",
            now,g_nativeDirect053.load(),g_pairA8Preferred053.load());
        {
            static std::uint64_t reportedFaults=0;
            const auto faults=g_readFaults054.load();
            g_log->info("SAFETY054,tick={},read_faults_caught={}",now,faults);
            g_log->info("PEAK066,tick={},enabled={},guarded_blocks={}",now,g_peakGuard066.load()?1:0,g_peakGuarded066.load());
            g_log->info("BED057,tick={},state={},level_match={},makeup_over_3db_blocks={},implicit_fold_blocks={}",now,
                !g_bedEnabled055.load()?"off":(g_bedSkip71_057.load()?"ambience_only":"all"),g_bedLevelMatch057.load()?1:0,g_bedMakeupLarge057.load(),g_bedImplicit058.load());
            g_log->info("BED055,tick={},enabled={},applied={},quad={},five={},seven={},other={},muted={},fail={},order_mismatch={},peak_guard={}",
                now,g_bedEnabled055.load()?1:0,g_bedApplied055.load(),g_bedQuad055.load(),g_bedFive055.load(),g_bedSeven055.load(),
                g_bedOther055.load(),g_bedMuted055.load(),g_bedFail055.load(),g_bedOrderMismatch056.load(),g_bedPeakGuard055.load());
            g_log->info("ELEV059,tick={},enabled={},blocks_below_-20={},level={},above_+20={}",now,
                g_elevation059.load()?1:0,g_elevBelow059.load(),g_elevLevel059.load(),g_elevAbove059.load());
            g_log->info("MIX056,tick={},mode={},filter_crossfades={},nonfinite_rejects={},stereo_wide_blocks={},history_resets={}",
                now,g_worldMode047.load()==2?"pure":(g_worldMode047.load()==1?"hybrid":"native"),g_filterCrossfades056.load(),
                g_limiterEngaged056.load(),g_stereoWide056.load(),g_binauralHistoryResets.load());
            if(faults!=reportedFaults){g_log->warn("READ_FAULT054,tick={},total={}",now,faults);reportedFaults=faults;}
        }
        static std::uint64_t lastCallers=0;
        if(now-lastCallers>=60000 || changed) {
            lastCallers=now;
            for(auto i=0u;i<g_oosCaller052.size();++i) if(auto c=g_oosCaller052[i].load())
                g_log->info("CALLER052,slot={},caller=0x{:016X},hits={}",i,c,g_oosCallerHits052[i].load());
            if(g_oosCallerOverflow052.load()) g_log->info("CALLER052,overflow={}",g_oosCallerOverflow052.load());
            static std::uint32_t written=0;
            const auto have=(std::min)(g_oosSamples052.load(),static_cast<std::uint32_t>(g_oosSampleRows052.size()));
            for(;written<have;++written){
                const auto& r=g_oosSampleRows052[written];
                g_log->info("OOS052,n={},caller=0x{:016X},object=0x{:X},key=0x{:X},mode={},count={},x={:.3f},y={:.3f},z={:.3f}",
                    written,r.caller,r.object,r.key,r.mode,r.count,r.xyz[0],r.xyz[1],r.xyz[2]);
            }
        }
        g_log->flush();last=now;
    }
}

// diagnostic: choose one live, independently verified playing instance.
struct Candidate042 {
    IdentityMeta meta{};
    std::uint32_t playing=0;
    std::uint64_t last=0,hits=0,muted=0,route1=0,route2=0;
    std::uint64_t monoLast=0,monoHits=0;
    bool monoRoute=false;
};
bool Eligible045(const Candidate042& c,std::uint64_t now) {
    return c.monoRoute && c.monoHits>=32 && now>=c.monoLast && now-c.monoLast<=1000;
}
std::array<Candidate042,256> g_candidates042{};
std::atomic_flag g_candidateLock042=ATOMIC_FLAG_INIT;
std::atomic<bool> g_muteHeld042{false},g_hrtfHeld043{false},g_bypassHeld044{false},g_pureHeld046{false};
std::atomic<std::uint64_t> g_hrtfEpoch043{0},g_hrtfAttempts043{0},g_hrtfApplied043{0},g_hrtfFallback043{0},g_hrtfLayoutSkipped043{0};
std::atomic<std::uint64_t> g_bypassAttempts044{0},g_bypassApplied044{0},g_bypassFallback044{0};
std::atomic<std::uint64_t> g_pureAttempts046{0},g_pureApplied046{0},g_pureFallback046{0};
std::atomic<std::uint32_t> g_azimuth043{0},g_distance043{0};
std::atomic<std::uint64_t> g_candidateBusy042{0};
int g_selected042=-1;
std::size_t g_candidateCount042=0;
// 32 input rows, each 0x40 bytes: zero start AND end coefficients.
alignas(64) const std::array<float,32*16> g_zeroMatrix042{};
bool SameCandidate042(const Candidate042& c,const IdentityMeta& m,std::uint32_t playing) {
    return c.meta.body==m.body && c.meta.eventId==m.eventId &&
        c.meta.key==m.key && c.meta.source==m.source && c.playing==playing;
}
bool KnownLayout042(std::uint32_t mask) { return mask==3 || mask==4 || mask==0x33; }
unsigned Audition042(const IdentityMeta& meta,std::uint32_t playing,bool dual,
    std::uint32_t route,std::uint32_t sourceMask,std::uint32_t destinationMask,
    std::uint16_t frames,std::uint64_t now) {
    if (!dual || !meta.body || !playing || !frames || (route!=1 && route!=2) ||
        !KnownLayout042(sourceMask) || !KnownLayout042(destinationMask)) return false;
    if(g_candidateLock042.test_and_set(std::memory_order_acquire)) { ++g_candidateBusy042; return false; }
    std::size_t i=0;
    for(;i<g_candidateCount042;++i) if(SameCandidate042(g_candidates042[i],meta,playing)) break;
    if(i==g_candidateCount042 && i<g_candidates042.size()) {
        g_candidates042[i].meta=meta; g_candidates042[i].playing=playing; ++g_candidateCount042;
    }
    unsigned mode=0;
    if(i<g_candidates042.size()) {
        auto& c=g_candidates042[i]; c.last=now; ++c.hits;
        if(route==2) {
            c.monoRoute=sourceMask==4 && destinationMask==3;
            if(c.monoRoute) { c.monoLast=now; ++c.monoHits; }
        }
        if(static_cast<int>(i)==g_selected042) {
            if(g_muteHeld042.load(std::memory_order_relaxed)) mode=1;
            else if(g_bypassHeld044.load(std::memory_order_relaxed) || g_pureHeld046.load(std::memory_order_relaxed) || g_hrtfHeld043.load(std::memory_order_relaxed)) {
                if(route==2 && sourceMask==4 && destinationMask==3) mode=g_bypassHeld044.load()?3u:(g_pureHeld046.load()?4u:2u);
                else ++g_hrtfLayoutSkipped043;
            }
        }
        if(mode==1) { ++c.muted; if(route==1) ++c.route1; else ++c.route2; }
    }
    g_candidateLock042.clear(std::memory_order_release);
    return mode;
}
void Control042() {
    static bool priorNext=false,priorClear=false,priorMute=false,priorHrtf=false,priorBypass=false,priorPure=false;
    static std::uint64_t lastSummary=0;
    const bool next=AudioKey062(VK_F6);
    const bool clear=AudioKey062(VK_F9);
    const bool hrtf=AudioKey062(VK_F8);
    const bool bypass=AudioKey062(VK_F10);
    const bool pure=AudioKey062(VK_F11);
    const bool held=AudioKey062(VK_F7);
    const auto now=GetTickCount64();
    Candidate042 snapshot{}; int index=-1; unsigned live=0; bool changed=false;
    // Retry on the next listener update if the lock is busy.
    if(g_candidateLock042.test_and_set(std::memory_order_acquire)) { g_muteHeld042.store(false); g_hrtfHeld043.store(false); g_bypassHeld044.store(false); g_pureHeld046.store(false); return; }
    for(std::size_t i=0;i<g_candidateCount042;++i)
        if(Eligible045(g_candidates042[i],now)) ++live;
    if(clear && !priorClear) { g_selected042=-1; changed=true; }
    else if(next && !priorNext) {
        const int start=g_selected042;
        g_selected042=-1;
        for(std::size_t n=1;n<=g_candidateCount042;++n) {
            const auto i=static_cast<std::size_t>((start+static_cast<int>(n))%static_cast<int>(g_candidateCount042));
            const auto& c=g_candidates042[i];
            if(Eligible045(c,now)) { g_selected042=static_cast<int>(i); break; }
        }
        changed=true;
    }
    if(changed) { g_muteHeld042.store(false); g_hrtfHeld043.store(false); g_bypassHeld044.store(false); g_pureHeld046.store(false); ++g_hrtfEpoch043; }
    index=g_selected042;
    if(index>=0) snapshot=g_candidates042[static_cast<std::size_t>(index)];
    g_candidateLock042.clear(std::memory_order_release);
    // Keep the selected target while muted.
    static bool requireRelease=false;
    if(changed && (held || hrtf || bypass || pure)) requireRelease=true;
    if(!held && !hrtf && !bypass && !pure) requireRelease=false;
    g_muteHeld042.store(held && !requireRelease && index>=0,std::memory_order_release);
    const bool ready045=index>=0 && Eligible045(snapshot,now);
    const bool hrtfArmed=hrtf && !pure && !bypass && !held && !requireRelease && ready045;
    if(hrtfArmed!=g_hrtfHeld043.load()) ++g_hrtfEpoch043;
    g_hrtfHeld043.store(hrtfArmed);
    const bool pureArmed=pure && !bypass && !held && !requireRelease && ready045;
    if(pureArmed!=g_pureHeld046.load()) ++g_hrtfEpoch043;
    g_pureHeld046.store(pureArmed);
    g_bypassHeld044.store(bypass && !held && !requireRelease && ready045);
    if(g_log && (changed || held!=priorMute || hrtf!=priorHrtf || bypass!=priorBypass || pure!=priorPure || now-lastSummary>=2000)) {
        g_log->info("AUDITION046,changed={},selected={},live={},f7={},armed={},body=0x{:X},event=0x{:X},playing={},source=0x{:X},key=0x{:X},hits={},muted={},route1_muted={},route2_muted={},age_ms={},lock_busy={}",
            changed?1:0,index,live,held?1:0,g_muteHeld042.load()?1:0,
            snapshot.meta.body,snapshot.meta.eventId,snapshot.playing,snapshot.meta.source,snapshot.meta.key,
            snapshot.hits,snapshot.muted,snapshot.route1,snapshot.route2,
            index>=0?now-snapshot.last:0,g_candidateBusy042.load());
        g_log->info("SELECTION046,eligible={},mono_hits={},mono_age_ms={},available_mono={}",
            ready045?1:0,snapshot.monoHits,index>=0 && now>=snapshot.monoLast?now-snapshot.monoLast:0,live);
        g_log->info("HRTF046,f8={},armed={},attempts={},applied={},fallback={},layout_skipped={},azimuth_deg={},distance={}",
            hrtf?1:0,hrtfArmed?1:0,g_hrtfAttempts043.load(),g_hrtfApplied043.load(),g_hrtfFallback043.load(),
            g_hrtfLayoutSkipped043.load(),FloatFromBits(g_azimuth043.load()),FloatFromBits(g_distance043.load()));
        g_log->info("BYPASS046,f10={},armed={},attempts={},applied={},fallback={},metrics_mode={},input_peak={},left_peak={},right_peak={},input_rms={},left_rms={},right_rms={}",
            bypass?1:0,g_bypassHeld044.load()?1:0,g_bypassAttempts044.load(),g_bypassApplied044.load(),g_bypassFallback044.load(),g_metricsMode044.load(),
            FloatFromBits(g_inputPeak044.load()),FloatFromBits(g_leftPeak044.load()),FloatFromBits(g_rightPeak044.load()),
            FloatFromBits(g_inputRms044.load()),FloatFromBits(g_leftRms044.load()),FloatFromBits(g_rightRms044.load()));
        g_log->info("PURE046,f11={},armed={},attempts={},applied={},fallback={}",
            pure?1:0,pureArmed?1:0,g_pureAttempts046.load(),g_pureApplied046.load(),g_pureFallback046.load());
        g_log->flush(); lastSummary=now;
    }
    priorNext=next; priorClear=clear; priorMute=held; priorHrtf=hrtf; priorBypass=bypass; priorPure=pure;
}

// Render supported surround beds from fixed virtual speaker directions.
// Use the game's downmix gains. Channel order follows speaker bits, with LFE last.
constexpr unsigned kBedMaxChannels055=8;
constexpr unsigned kBedTaps055=static_cast<unsigned>(KEMAR360::kTapCount);
constexpr float kBedNormalise055=0.70710678f; // binaural pair carries ~2x the energy of a one-sided downmix row
struct BedState055 {
    std::uintptr_t node=0,destination=0; std::uint32_t mask=0; std::uint64_t lastTick=0;
    float limiterGain=1.0f;
    float makeupGain=1.0f; // loudness match to the game's own downmix
    float history[kBedMaxChannels055][kBedTaps055-1]{};
};
// Keep bed state per mixer thread to avoid lock-contention fallbacks.
thread_local std::array<BedState055,16> g_bedStates055{};
thread_local std::uint64_t g_bedClock055=0;
alignas(16) thread_local float g_bedOrigLeft057[kBinauralMaxFrames]{};
alignas(16) thread_local float g_bedOrigRight057[kBinauralMaxFrames]{};
std::array<std::atomic<std::uint64_t>,64> g_bedDiagTick057{};
alignas(16) thread_local float g_bedWork055[kBinauralMaxFrames+kBedTaps055]{};

bool BedLayout055(std::uint32_t mask) {
    const unsigned n=__popcnt(mask);
    return n>=4 && n<=kBedMaxChannels055 && (mask&~0x7FFu)==0 && (mask&0x3u)==0x3u;
}
// Returns the virtual speaker azimuth (0 front, +90 right, -90 left); false for LFE.
bool BedAngle055(unsigned bit,std::uint32_t mask,int& angle) {
    const bool hasSide=(mask&0x600u)!=0, hasBack=(mask&0x30u)!=0;
    switch(bit){
    case 0: angle=-30; return true;   case 1: angle=30; return true;
    case 2: angle=0; return true;     case 3: return false; // LFE
    case 4: angle=hasSide?-150:-110; return true;
    case 5: angle=hasSide?150:110; return true;
    case 6: angle=-15; return true;   case 7: angle=15; return true;
    case 8: angle=180; return true;
    case 9: angle=hasBack?-90:-110; return true;
    case 10: angle=hasBack?90:110; return true;
    default: return false;
    }
}
BedState055* FindBedState055(std::uintptr_t node,std::uintptr_t destination,std::uint32_t mask,std::uint64_t) {
    const std::uint64_t now=++g_bedClock055;
    BedState055* oldest=&g_bedStates055[0];
    for(auto& st:g_bedStates055){
        if(st.node==node && st.destination==destination && st.mask==mask){st.lastTick=now;return &st;}
        if(st.lastTick<oldest->lastTick) oldest=&st;
    }
    *oldest=BedState055{}; oldest->node=node;oldest->destination=destination;oldest->mask=mask;oldest->lastTick=now;
    return oldest;
}
bool ApplyBedVirtualizer055(std::int64_t destinationValue,std::int64_t sourceBufferValue,const float* coefficientBlock,
    std::uintptr_t node,std::uintptr_t destination,std::uint32_t sourceMask,std::uint64_t now,
    std::uint32_t eventId057=0,std::uint32_t playingId057=0)
{
    const auto sourceBuffer=static_cast<std::uintptr_t>(sourceBufferValue);
    std::uintptr_t data=0;std::uint16_t maxFrames16=0,validFrames16=0;
    if(!sourceBuffer || !coefficientBlock ||
       !SafeReadValue(sourceBuffer+0x00,data) || !SafeReadValue(sourceBuffer+0x10,maxFrames16) ||
       !SafeReadValue(sourceBuffer+0x12,validFrames16) || !data) return false;
    const std::uint32_t maxFrames=maxFrames16, frames=validFrames16?validFrames16:maxFrames16;
    const unsigned channels=__popcnt(sourceMask);
    if(!frames || frames>maxFrames || maxFrames>kBinauralMaxFrames) return false;
    if(!IsReadable(coefficientBlock,channels*16u*sizeof(float)) ||
       !IsReadable(reinterpret_cast<const void*>(data),static_cast<std::size_t>(channels)*maxFrames*sizeof(float))) return false;
    for(unsigned i=0;i<channels*16u;++i) if(!std::isfinite(coefficientBlock[i])) return false;

    // Buffer channel index -> speaker bit (increasing bit order, LFE moved last).
    unsigned bits[kBedMaxChannels055]{};unsigned n=0;
    for(unsigned b=0;b<11;++b) if(b!=3 && (sourceMask&(1u<<b))) bits[n++]=b;
    if(sourceMask&0x8u) bits[n++]=3;
    if(n!=channels) return false;

    // Check channel order against the left, right and centre downmix rows.
    for(unsigned ch=0;ch<channels;++ch){
        const float l=std::fabs(coefficientBlock[ch*16u]),r=std::fabs(coefficientBlock[ch*16u+1u]);
        if(l+r<1.0e-4f) continue;
        const unsigned bit=bits[ch];
        const bool leftBit=bit==0||bit==4||bit==6||bit==9, rightBit=bit==1||bit==5||bit==7||bit==10;
        if((leftBit && r>l*1.05f+1.0e-4f) || (rightBit && l>r*1.05f+1.0e-4f) ||
           (bit==2 && std::fabs(l-r)>0.25f*(std::max)(l,r))) { ++g_bedOrderMismatch056; return false; }
    }

    // The original mixer implicitly folds channels missing from the destination.
    // Rebuild zero centre/surround rows using the voice's front gain.
    float vol0=0.0f,vol1=0.0f;
    for(unsigned ch=0;ch<channels;++ch){
        if(bits[ch]!=0 && bits[ch]!=1) continue;
        const float* row=coefficientBlock+ch*16u;
        vol0=(std::max)(vol0,(std::max)(std::fabs(row[0]),std::fabs(row[1])));
        vol1=(std::max)(vol1,(std::max)(std::fabs(row[8]),std::fabs(row[9])));
    }
    float eff[kBedMaxChannels055][4]{}; // l0,r0,l1,r1
    bool implicitRow[kBedMaxChannels055]{};
    for(unsigned ch=0;ch<channels;++ch){
        const float* row=coefficientBlock+ch*16u;
        eff[ch][0]=row[0];eff[ch][1]=row[1];eff[ch][2]=row[8];eff[ch][3]=row[9];
        const unsigned bit=bits[ch];
        const bool zeroRow=std::fabs(row[0])+std::fabs(row[1])+std::fabs(row[8])+std::fabs(row[9])<1.0e-6f;
        if(!zeroRow || bit==0 || bit==1 || bit==3 || !g_bedImplicitFold058.load(std::memory_order_relaxed)) continue;
        float kl=0.0f,kr=0.0f;
        switch(bit){
        case 2: case 8: kl=kr=0.70710678f; break;                 // centre / back centre
        case 4: case 9: case 6: kl=0.70710678f; break;            // left surrounds / FLC
        case 5: case 10: case 7: kr=0.70710678f; break;           // right surrounds / FRC
        default: break;
        }
        eff[ch][0]=vol0*kl;eff[ch][1]=vol0*kr;eff[ch][2]=vol1*kl;eff[ch][3]=vol1*kr;
        implicitRow[ch]=(kl+kr)>0.0f;
    }
    bool anyImplicit=false; for(unsigned ch=0;ch<channels;++ch) anyImplicit|=implicitRow[ch];
    if(anyImplicit) ++g_bedImplicit058;

    BedState055* state=FindBedState055(node,destination,sourceMask,now);

    float* left=g_directLeftEar; float* right=g_directRightEar;
    std::memset(left,0,frames*sizeof(float));std::memset(right,0,frames*sizeof(float));
    // Reconstruct the original downmix for level matching and diagnostics.
    float* origLeft=g_bedOrigLeft057; float* origRight=g_bedOrigRight057;
    std::memset(origLeft,0,frames*sizeof(float));std::memset(origRight,0,frames*sizeof(float));
    double channelEnergy[kBedMaxChannels055]{};
    const float* base=reinterpret_cast<const float*>(data);
    const float invFrames=1.0f/static_cast<float>(frames);
    bool ok=true;
    for(unsigned ch=0;ch<channels && ok;++ch){
        const float* e=eff[ch]; // effective row: l0,r0,l1,r1
        const float* x=base+static_cast<std::size_t>(ch)*maxFrames;
        const unsigned bit=bits[ch];
        for(std::uint32_t i=0;i<frames;++i){
            const float xi=x[i]; if(!std::isfinite(xi)){ok=false;break;}
            const float t=(static_cast<float>(i)+1.0f)*invFrames;
            origLeft[i]+=xi*(e[0]+(e[2]-e[0])*t);
            origRight[i]+=xi*(e[1]+(e[3]-e[1])*t);
            channelEnergy[ch]+=static_cast<double>(xi)*xi;
        }
        if(!ok)break;
        int angle=0;
        if(bit==2 && g_bedCentreDirect064.load(std::memory_order_relaxed)) {
            // Delay direct centre audio to match the front HRIR arrival.
            const std::uint32_t d=g_bedCentreDelay064;
            float* w=g_bedWork055;
            std::memcpy(w,state->history[ch],(kBedTaps055-1)*sizeof(float));
            for(std::uint32_t i=0;i<frames;++i){
                const float t=(static_cast<float>(i)+1.0f)*invFrames;
                w[kBedTaps055-1+i]=x[i];
                const float xd=w[kBedTaps055-1+i-d];
                left[i]+=xd*(e[0]+(e[2]-e[0])*t);
                right[i]+=xd*(e[1]+(e[3]-e[1])*t);
            }
            std::memcpy(state->history[ch],w+frames,(kBedTaps055-1)*sizeof(float));
            continue;
        }
        if(!BedAngle055(bit,sourceMask,angle)) {
            // LFE: keep the game's own downmix gains, no HRTF (bass is not directional).
            for(std::uint32_t i=0;i<frames;++i){
                const float t=(static_cast<float>(i)+1.0f)*invFrames;
                const float xi=x[i]; if(!std::isfinite(xi)){ok=false;break;}
                left[i]+=xi*(e[0]+(e[2]-e[0])*t);
                right[i]+=xi*(e[1]+(e[3]-e[1])*t);
            }
            continue;
        }
        const float g0=std::sqrt(e[0]*e[0]+e[1]*e[1])*kBedNormalise055;
        const float g1=std::sqrt(e[2]*e[2]+e[3]*e[3])*kBedNormalise055;
        float* w=g_bedWork055;
        std::memcpy(w,state->history[ch],(kBedTaps055-1)*sizeof(float));
        for(std::uint32_t i=0;i<frames;++i){
            const float xi=x[i]; if(!std::isfinite(xi)){ok=false;break;}
            const float t=(static_cast<float>(i)+1.0f)*invFrames;
            w[kBedTaps055-1+i]=xi*(g0+(g1-g0)*t);
        }
        if(!ok)break;
        alignas(16) float bedLeft061[HRIRSET::kTapCount]; alignas(16) float bedRight061[HRIRSET::kTapCount];
        BuildHrirWithEmphasis064(static_cast<float>(angle),0.0f,0.0f,bedLeft061,bedRight061); // beds = plain filters
        const float* hl=bedLeft061;
        const float* hr=bedRight061;
        for(unsigned t=0;t<kBedTaps055;++t){
            const float a=hl[t],b=hr[t];
            const float* src=w+(kBedTaps055-1-t);
            for(std::uint32_t i=0;i<frames;++i){left[i]+=a*src[i];right[i]+=b*src[i];}
        }
        std::memcpy(state->history[ch],w+frames,(kBedTaps055-1)*sizeof(float));
    }
    if(!ok) return false;

    // Compare the binaural block energy with the original downmix.
    double origEnergy=0.0,outEnergy=0.0;
    for(std::uint32_t i=0;i<frames;++i){
        origEnergy+=static_cast<double>(origLeft[i])*origLeft[i]+static_cast<double>(origRight[i])*origRight[i];
        outEnergy+=static_cast<double>(left[i])*left[i]+static_cast<double>(right[i])*right[i];
    }
    const float makeup0=state->makeupGain;
    float makeup1=makeup0;
    // Avoid gain tracking during fades and near-silence.
    if(g_bedLevelMatch057.load(std::memory_order_relaxed) && origEnergy>1.0e-6*frames && outEnergy>1.0e-12){
        // Limit calibration to 0.05 dB per block and +/-3 dB.
        const float want=(std::min)(1.41f,(std::max)(0.71f,static_cast<float>(std::sqrt(origEnergy/outEnergy))));
        const float ratio=(std::min)(1.0058f,(std::max)(0.9943f,want/makeup0));
        makeup1=makeup0*ratio;
        if(want>1.41f) ++g_bedMakeupLarge057;
    }
    if(makeup0!=1.0f || makeup1!=1.0f)
        for(std::uint32_t i=0;i<frames;++i){const float g=makeup0+(makeup1-makeup0)*((static_cast<float>(i)+1.0f)*invFrames);left[i]*=g;right[i]*=g;}
    state->makeupGain=makeup1;

    {
        auto& last=g_bedDiagTick057[(node>>4)&63u];
        std::uint64_t prev=last.load(std::memory_order_relaxed);
        if(g_log && g_debugLog063.load(std::memory_order_relaxed) && now-prev>=2000 && last.compare_exchange_strong(prev,now)) {
            auto db=[](double e,std::uint32_t n){return e>1e-20?10.0*std::log10(e/n):-200.0;};
            std::string chans;
            for(unsigned ch=0;ch<channels;++ch){
                chans+=fmt::format("{}:b{}:{:.1f}dB:l{:.3f}:r{:.3f}{};",ch,bits[ch],db(channelEnergy[ch],frames),eff[ch][0],eff[ch][1],implicitRow[ch]?":fold":"");
            }
            double outAfter=0.0;
            for(std::uint32_t i=0;i<frames;++i) outAfter+=static_cast<double>(left[i])*left[i]+static_cast<double>(right[i])*right[i];
            g_log->info("BEDDIAG057,tick={},node=0x{:X},mask=0x{:X},event=0x{:08X},playing={},frames={},orig_db={:.1f},binaural_db={:.1f},after_makeup_db={:.1f},makeup={:.2f},ch={}",
                now,node,sourceMask,eventId057,playingId057,frames,db(origEnergy,frames),db(outEnergy,frames),db(outAfter,frames),makeup1,chans);
        }
    }

    // smoothed limiter (ramped from the previous block's gain, slow release).
    float peak=0.0f;
    for(std::uint32_t i=0;i<frames;++i) peak=(std::max)(peak,(std::max)(std::fabs(left[i]),std::fabs(right[i])));
    float target=1.0f;
    if(peak>kHybridPeakGuard){target=kHybridPeakGuard/peak;++g_bedPeakGuard055;}
    if(target>state->limiterGain) target=(std::min)(target,state->limiterGain+0.02f);
    const float g0=state->limiterGain;
    if(g0!=1.0f || target!=1.0f)
        for(std::uint32_t i=0;i<frames;++i){const float g=g0+(target-g0)*((static_cast<float>(i)+1.0f)*invFrames);left[i]*=g;right[i]*=g;}
    state->limiterGain=target;

    // Hand both ears back through the game's own mixer as unity mono voices.
    alignas(16) std::array<std::uint8_t,0x80> fakeBuffer{};
    if(!IsReadable(reinterpret_cast<const void*>(sourceBuffer),fakeBuffer.size())) return false;
    if(!GuardedCopy054(fakeBuffer.data(),reinterpret_cast<const void*>(sourceBuffer),fakeBuffer.size())) return false;
    *reinterpret_cast<std::uint32_t*>(fakeBuffer.data()+0x08)=0x00000004u;
    const auto fakePtr=static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(fakeBuffer.data()));
    alignas(16) float leftCoefficients[16]{};alignas(16) float rightCoefficients[16]{};
    leftCoefficients[0]=leftCoefficients[8]=1.0f;
    rightCoefficients[1]=rightCoefficients[9]=1.0f;
    *reinterpret_cast<std::uintptr_t*>(fakeBuffer.data())=reinterpret_cast<std::uintptr_t>(left);
    g_sourceToDestinationMixOriginal(destinationValue,fakePtr,leftCoefficients);
    *reinterpret_cast<std::uintptr_t*>(fakeBuffer.data())=reinterpret_cast<std::uintptr_t>(right);
    g_sourceToDestinationMixOriginal(destinationValue,fakePtr,rightCoefficients);

    ++g_bedApplied055;
    if(sourceMask==0x33u)++g_bedQuad055; else if(channels==6)++g_bedFive055; else if(channels==8)++g_bedSeven055; else ++g_bedOther055;
    return true;
}

void __fastcall SourceToDestinationMixHook(
    std::int64_t destinationValue,
    std::int64_t sourceBufferValue,
    const float* coefficientBlock)
{
    const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    g_matrixCalls.fetch_add(1, std::memory_order_relaxed);

    const std::uintptr_t activeRenderStart = g_exeBase + kRvaVoiceRenderNode;
    const std::uintptr_t activeRenderEnd = activeRenderStart + 1298ull;
    const bool fromActiveRender = caller >= activeRenderStart && caller < activeRenderEnd;
    if (fromActiveRender) {
        g_matrixActiveCalls.fetch_add(1, std::memory_order_relaxed);
    }

    std::uint32_t route = 0; // 0 = outside/other caller family
    if (caller == g_exeBase + 0x0035271Dull) route = 1;
    else if (caller == g_exeBase + 0x00352820ull) route = 2;
    else if (fromActiveRender) route = 3;

    const auto sourceBuffer = static_cast<std::uintptr_t>(sourceBufferValue);
    const auto destination = static_cast<std::uintptr_t>(destinationValue);

    std::uint32_t sourceMask = 0;
    std::uint32_t destinationMask = 0;
    std::uintptr_t node = 0;
    std::uintptr_t wrapper = 0;
    std::uintptr_t context = 0;
    if (sourceBuffer != 0) {
        SafeReadValue(sourceBuffer + 0x08, sourceMask);
        if (SafeReadValue(sourceBuffer + 0x40, node) && node != 0) {
            if (SafeReadValue(node + 0x10, wrapper) && wrapper != 0) {
                SafeReadValue(wrapper + 0x18, context);
            }
        }
    }
    if (destination != 0) {
        SafeReadValue(destination + 0x428, destinationMask);
    }

    if (route == 2 && __popcnt(sourceMask) == 1 && destinationMask == 0x3u) {
        g_matrixRouteBMonoStereo.fetch_add(1, std::memory_order_relaxed);
    }

    const auto now = GetTickCount64();
    std::uint32_t playingId = 0;
    std::uintptr_t objectA8 = 0;
    std::uintptr_t object148 = 0;
    if (context != 0) {
        SafeReadValue(context + 0x70, playingId);
        SafeReadValue(context + 0xA8, objectA8);
        SafeReadValue(context + 0x148, object148);
    }

    IdentityMeta playingMeta{};
    IdentityMeta objectMetaA8{};
    IdentityMeta objectMeta148{};
    const bool playingMatch =
        playingId != 0 && LookupPlaying(playingId, playingMeta, now) &&
        playingMeta.body != 0;
    const bool objectA8Match =
        objectA8 != 0 && LookupObject(objectA8, objectMetaA8, now) &&
        objectMetaA8.body != 0;
    const bool object148Match =
        object148 != 0 && LookupObject(object148, objectMeta148, now) &&
        objectMeta148.body != 0;

    IdentityMeta selected{};
    std::uint32_t matchMask = 0;
    if (playingMatch) {
        selected = playingMeta;
        matchMask |= 0x1u;
        if (objectA8Match && SameIdentity(playingMeta, objectMetaA8)) matchMask |= 0x2u;
        if (object148Match && SameIdentity(playingMeta, objectMeta148)) matchMask |= 0x4u;
    }
    else if (objectA8Match) {
        selected = objectMetaA8;
        matchMask |= 0x2u;
        if (object148Match && SameIdentity(objectMetaA8, objectMeta148)) matchMask |= 0x4u;
    }
    else if (object148Match) {
        selected = objectMeta148;
        matchMask |= 0x4u;
    }
    else if (g_renderTls.active && g_renderTls.meta.body != 0) {
        selected = g_renderTls.meta;
        playingId = g_renderTls.playingId;
        matchMask = g_renderTls.matchMask | 0x8u; // inherited from active-render TLS
    }

    Scope040 trace040(2,caller,destination,sourceBuffer,destination ? destination+0x420 : 0);
    trace040.e.body=selected.body; trace040.e.matches=matchMask; trace040.Emit(0);
    const bool tracked = selected.body != 0;
    ObserveCaller(g_matrixCallerCensus, caller, tracked);

    bool muteRequested = false;
    bool muteApplied = false;
    bool hrtfRequested = false;
    bool hrtfApplied = false;
    std::uint32_t hrtfFrames = 0;
    float sourcePeak = 0.0f;
    float leftPeak = 0.0f;
    float rightPeak = 0.0f;
    float azimuthDeg = 0.0f;
    float elevationDeg = 0.0f;
    float distance = 0.0f;


    // Retained mixer-path diagnostics.
    g_primaryFamilyCalls.fetch_add(1, std::memory_order_relaxed);

    if (tracked) {
        g_matrixTrackedCalls.fetch_add(1, std::memory_order_relaxed);
        if (route == 1) g_matrixTrackedRoute1.fetch_add(1, std::memory_order_relaxed);
        else if (route == 2) g_matrixTrackedRoute2.fetch_add(1, std::memory_order_relaxed);
        else if (route == 3) g_matrixTrackedRoute3.fetch_add(1, std::memory_order_relaxed);
        else g_matrixTrackedOther.fetch_add(1, std::memory_order_relaxed);

        if (playingMatch) g_matrixPlayingMatches.fetch_add(1, std::memory_order_relaxed);
        const bool dualMatch = playingMatch && ((matchMask & 0x6u) != 0);
        if (dualMatch) {
            g_matrixDualIdentityMatches.fetch_add(1, std::memory_order_relaxed);
            const auto verifiedObject = (matchMask & 0x2u) ? objectA8 : object148;
            RenewVerifiedIdentity(playingId, verifiedObject, selected, now);
            g_matrixIdentityRenewals.fetch_add(1, std::memory_order_relaxed);
        }

        // Legacy route selection: matched world voices on Route 2 with stereo output.
        const bool finalTrackedWorldRoute =
            dualMatch &&
            route == 2 &&
            destinationMask == 0x00000003u;

        // This diagnostic branch does not apply HRTF.
        hrtfRequested = false;
        hrtfApplied = false;

        CoverageObserveMatrix(
            selected.body, selected.eventId, selected.source, selected.key,
            playingId, route, sourceMask, destinationMask, caller, now);

        if (ShouldTraceCoverageMatrix(selected.body, selected.eventId, now)) {
            TracePayload trace{};
            trace.kind = TraceKind::MatrixRouteCoverage;
            trace.tick = now;
            trace.tid = GetCurrentThreadId();
            trace.route = route;
            trace.playingId = playingId;
            trace.eventId = selected.eventId;
            trace.objectKey = selected.key;
            trace.source = selected.source;
            trace.body = selected.body;
            trace.record = selected.record;
            trace.node = node;
            trace.context = context;
            trace.contextObjectA8 = objectA8;
            trace.contextObject148 = object148;
            trace.renderMatchMask = matchMask;
            trace.sourceMask = sourceMask;
            trace.destinationMask = destinationMask;
            trace.destination = destination;
            trace.fromActiveRender = fromActiveRender ? 1u : 0u;
            trace.matrixCaller = caller;
            EnqueueTrace(trace);
        }

        if ((hrtfRequested || muteRequested) && ShouldEmitMatrixBind(context, now)) {
            TracePayload trace{};
            trace.kind = TraceKind::MatrixDirectBind;
            trace.tick = now;
            trace.tid = GetCurrentThreadId();
            trace.route = route;
            trace.playingId = playingId;
            trace.eventId = selected.eventId;
            trace.objectKey = selected.key;
            trace.source = selected.source;
            trace.body = selected.body;
            trace.record = selected.record;
            trace.node = node;
            trace.context = context;
            trace.contextObjectA8 = objectA8;
            trace.contextObject148 = object148;
            trace.objectA8Match =
                (playingMatch && objectA8Match &&
                 SameIdentity(playingMeta, objectMetaA8)) ? 1u : 0u;
            trace.object148Match =
                (playingMatch && object148Match &&
                 SameIdentity(playingMeta, objectMeta148)) ? 1u : 0u;
            trace.dualIdentityMatch = dualMatch ? 1u : 0u;
            trace.sourceMask = sourceMask;
            trace.destinationMask = destinationMask;
            trace.destination = destination;
            trace.hrtfRequested = hrtfRequested ? 1u : 0u;
            trace.hrtfApplied = hrtfApplied ? 1u : 0u;
            trace.hrtfFrames = hrtfFrames;
            trace.dryRequested = muteRequested ? 1u : 0u;
            trace.dryApplied = muteApplied ? 1u : 0u;
            trace.sourcePeakBits = FloatBits(sourcePeak);
            trace.leftPeakBits = FloatBits(leftPeak);
            trace.rightPeakBits = FloatBits(rightPeak);
            trace.azimuthBits = FloatBits(azimuthDeg);
            trace.elevationBits = FloatBits(elevationDeg);
            trace.distanceBits = FloatBits(distance);
            trace.caller = caller;
            EnqueueTrace(trace);
        }
    }

    const auto priorTls = g_matrixTls;
    if (tracked) {
        g_matrixTls.active = true;
        g_matrixTls.meta = selected;
        g_matrixTls.playingId = playingId;
        g_matrixTls.route = route;
        g_matrixTls.sourceMask = sourceMask;
        g_matrixTls.destinationMask = destinationMask;
        g_matrixTls.caller = caller;
        g_matrixTls.node = node;
        g_matrixTls.context = context;
    }
    else {
        g_matrixTls = MatrixTlsScope{};
    }

    std::uint16_t frames047=0,stride047=0;
    SafeReadValue(sourceBuffer+0x12,frames047);
    const auto mode047=g_worldMode047.load();
    const bool independent047=playingMatch && (matchMask&0x6u)!=0;
    bool processed047=false;
    if(route==2 && frames047) {
        ++g_route2Seen048;
        if(independent047) ++g_route2Dual048;
        ++g_playingStages048[PlayingStage048(playingId,now)];
        ++g_objectStages048[(std::max)(ObjectStage048(objectA8,now),ObjectStage048(object148,now))];
    }
    bool foxMuted052=false;
    if(mode047 && g_nativeMute050.load() && WorldEligible047(independent047,selected.body,playingId,
            route,sourceMask,destinationMask,frames047)) {
        alignas(16) float silent052[64]{}; // up to quad: 4 rows x 16
        g_sourceToDestinationMixOriginal(destinationValue,sourceBufferValue,silent052);
        processed047=true;foxMuted052=true;++g_foxMuted052;
    }
    else if(mode047 && WorldEligible047(independent047,selected.body,playingId,
            route,sourceMask,destinationMask,frames047)) {
        ++g_worldAttempts047;g_lastAttempt048.store(now);
        SafeReadValue(sourceBuffer+0x10,stride047);
        if(frames047==stride047 && stride047<=kBinauralMaxFrames) {
            auto& history=GetBinauralHistory(node,destination);
            const auto epoch=g_worldEpoch047.load();
            PrepareWorldHistory047(history,selected.body,playingId,epoch,now);
            processed047=ApplyWideWorldHrtf(destinationValue,sourceBufferValue,coefficientBlock,
                node,destination,sourceMask,selected,sourcePeak,leftPeak,rightPeak,
                azimuthDeg,elevationDeg,distance,hrtfFrames,false,mode047==2);
        }
        if(processed047) {
            ++g_worldApplied047;g_lastApplied048.store(now);
            if(sourceMask==4) ++g_worldMono047;
            else if(sourceMask==3) ++g_worldStereo047;
            else ++g_worldQuad047;
        } else ++g_worldFallback047;
    } else if(mode047 && independent047 && route==2 && frames047 &&
        (destinationMask!=3 || (sourceMask!=4 && sourceMask!=3 && sourceMask!=0x33))) ++g_worldLayout047;
    bool nativeMuted050=false;
    NativePosition050 native050{};
    const bool nativeLayout051=sourceMask==4 || sourceMask==3 || sourceMask==0x33;
    if(!independent047 && route==2 && frames047) {
        if(!playingId) ++g_gateNoPlaying052;
        else if(destinationMask!=3) ++g_gateDest052;
        else if(sourceMask==8) ++g_gateLfe052;
        else if(!nativeLayout051) ++g_gateLayout052;
    }
    const bool nativeCandidate050=!independent047 && route==2 && playingId &&
        nativeLayout051 && destinationMask==3 && frames047 &&
        ChooseNative050(objectA8,object148,native050);
    if(nativeCandidate050){
        ++g_nativeCandidates050;
        if(sourceMask==4)++g_nativeCandMono051; else if(sourceMask==3)++g_nativeCandStereo051; else ++g_nativeCandQuad051;
    }
    const bool nativeLayoutOn051=sourceMask==4 || g_nativeWide051.load();
    if(!processed047 && nativeCandidate050 && nativeLayoutOn051 && mode047 && g_nativeEnabled050.load()) {
        if(!g_nativeMute050.load()){++g_worldAttempts047;g_lastAttempt048.store(now);}
        SafeReadValue(sourceBuffer+0x10,stride047);
        if(frames047==stride047 && stride047<=kBinauralMaxFrames) {
            if(g_nativeMute050.load()) {
                alignas(16) float silent050[64]{}; // up to quad: 4 rows x 16
                g_sourceToDestinationMixOriginal(destinationValue,sourceBufferValue,silent050);
                nativeMuted050=true;processed047=true;++g_nativeMuted050;
            } else {
                auto& history=GetBinauralHistory(node,destination);
                // Include native construction generation in history identity, independently of Fox bodies.
                if(history.ownerNativeGeneration050!=native050.generation)history.initialized=false;
                history.ownerNativeGeneration050=native050.generation;
                PrepareWorldHistory047(history,native050.object,playingId,g_worldEpoch047.load(),now);
                processed047=ApplyWideWorldHrtf(destinationValue,sourceBufferValue,coefficientBlock,
                    node,destination,sourceMask,selected,sourcePeak,leftPeak,rightPeak,
                    azimuthDeg,elevationDeg,distance,hrtfFrames,false,mode047==2,native050.xyz);
                if(processed047){
                    ++g_nativeApplied050;++g_worldApplied047;g_lastApplied048.store(now);
                    if(sourceMask==4){++g_worldMono047;++g_nativeAppliedMono051;}
                    else if(sourceMask==3){++g_worldStereo047;++g_nativeAppliedStereo051;}
                    else {++g_worldQuad047;++g_nativeAppliedQuad051;}
                }
            }
        }
        if(!processed047){++g_nativeFallback050;if(!g_nativeMute050.load())++g_worldFallback047;}
    }
    bool bedMuted055=false;
    if(!processed047 && mode047 && g_bedEnabled055.load() && route==2 && frames047 &&
        destinationMask==3 && BedLayout055(sourceMask) &&
        !(g_bedSkip71_057.load(std::memory_order_relaxed) && __popcnt(sourceMask)==8)) {
        if(g_nativeMute050.load()) {
            alignas(16) float silent055[128]{}; // up to 8 rows x 16
            g_sourceToDestinationMixOriginal(destinationValue,sourceBufferValue,silent055);
            processed047=true;bedMuted055=true;++g_bedMuted055;
        } else {
            processed047=ApplyBedVirtualizer055(destinationValue,sourceBufferValue,coefficientBlock,node,destination,sourceMask,now,selected.eventId,playingId);
            if(!processed047)++g_bedFail055;
        }
    }
    if(!processed047) g_sourceToDestinationMixOriginal(destinationValue,sourceBufferValue,coefficientBlock);
    Census049 census049{};
    census049.kind=3;census049.key1=playingId;census049.key2=context;census049.key3=node;
    census049.last=now;census049.playing=playingId;census049.body=selected.body;census049.source=selected.source;
    census049.objectKey=selected.key;census049.event=selected.eventId;census049.node=node;
    census049.object=objectA8?objectA8:object148;census049.caller=caller;
    census049.routes=1u<<route;census049.matches=matchMask;census049.srcMasks=sourceMask;census049.dstMasks=destinationMask;
    census049.applied=processed047 && !nativeMuted050 && !foxMuted052 && !bedMuted055?1:0;
    census049.playingStages=1u<<PlayingStage048(playingId,now);
    census049.objectStages=1u<<(std::max)(ObjectStage048(objectA8,now),ObjectStage048(object148,now));
    if(!census049.event) { IdentityMeta hint{};if(LookupPlaying(playingId,hint,now)) census049.event=hint.eventId; }
    ObserveCensus049(census049);
    if(nativeCandidate050) {
        census049.kind=4;census049.objectKey=native050.key;census049.object=native050.object;
        census049.body=0;census049.source=0;
        for(unsigned i=0;i<3;++i)census049.xyzBits050[i]=FloatBits(native050.xyz[i]);
        ObserveCensus049(census049);
    }
    trace040.Emit(1);
    g_matrixTls = priorTls;
}


void __fastcall AlternateMixCoreHook(
    std::int64_t frameInfoValue,
    std::int64_t sourceBufferValue,
    std::int64_t destinationBufferValue,
    char directSameMask,
    const float* coefficientBlock)
{
    g_alternateFamilyCalls.fetch_add(1, std::memory_order_relaxed);

    const auto sourceBuffer = static_cast<std::uintptr_t>(sourceBufferValue);
    const auto destinationBuffer = static_cast<std::uintptr_t>(destinationBufferValue);

    // Read the node relation for telemetry; processing does not depend on it.
    std::uintptr_t node = 0;
    std::uintptr_t wrapper = 0;
    std::uintptr_t context = 0;
    std::uint32_t playingId = 0;
    std::uintptr_t objectA8 = 0;
    std::uintptr_t object148 = 0;
    if (sourceBuffer != 0 &&
        SafeReadValue(sourceBuffer + 0x40, node) && node != 0 &&
        SafeReadValue(node + 0x10, wrapper) && wrapper != 0 &&
        SafeReadValue(wrapper + 0x18, context) && context != 0) {
        SafeReadValue(context + 0x70, playingId);
        SafeReadValue(context + 0xA8, objectA8);
        SafeReadValue(context + 0x148, object148);
        IdentityMeta meta{};
        const auto now = GetTickCount64();
        if ((playingId != 0 && LookupPlaying(playingId, meta, now) && meta.body != 0) ||
            (objectA8 != 0 && LookupObject(objectA8, meta, now) && meta.body != 0) ||
            (object148 != 0 && LookupObject(object148, meta, now) && meta.body != 0)) {
            g_alternateFamilyTrackedContext.fetch_add(1, std::memory_order_relaxed);
        }
    }

    Scope040 trace040(3,reinterpret_cast<std::uintptr_t>(_ReturnAddress()),static_cast<std::uintptr_t>(frameInfoValue),sourceBuffer,destinationBuffer);
    trace040.Emit(0);
    g_alternateMixCoreOriginal(
        frameInfoValue,
        sourceBufferValue,
        destinationBufferValue,
        directSameMask,
        coefficientBlock);
    trace040.Emit(1);
}

void __fastcall LowLevelChannelMixHook(
    std::int64_t sourcePcm,
    std::int64_t destinationPcm,
    float gainStart,
    float gainDelta,
    std::uint32_t frames)
{
    const auto caller = reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    g_lowLevelCalls.fetch_add(1, std::memory_order_relaxed);

    IdentityMeta selected{};
    std::uint32_t playingId = 0;
    bool viaMatrix = false;
    if (g_matrixTls.active && g_matrixTls.meta.body != 0) {
        selected = g_matrixTls.meta;
        playingId = g_matrixTls.playingId;
        viaMatrix = true;
    }
    else if (g_renderTls.active && g_renderTls.meta.body != 0) {
        selected = g_renderTls.meta;
        playingId = g_renderTls.playingId;
    }

    const bool tracked = selected.body != 0;
    ObserveCaller(g_lowCallerCensus, caller, tracked);
    if (tracked) {
        const auto now = GetTickCount64();
        g_lowLevelTrackedCalls.fetch_add(1, std::memory_order_relaxed);
        if (viaMatrix) g_lowLevelTrackedViaMatrix.fetch_add(1, std::memory_order_relaxed);
        else g_lowLevelTrackedViaRender.fetch_add(1, std::memory_order_relaxed);

        CoverageObserveLowLevel(
            selected.body, selected.eventId, selected.source, selected.key,
            playingId, caller, viaMatrix, now);

        if (ShouldTraceCoverageLow(selected.body, selected.eventId, now)) {
            TracePayload trace{};
            trace.kind = TraceKind::LowLevelRoute;
            trace.tick = now;
            trace.tid = GetCurrentThreadId();
            trace.playingId = playingId;
            trace.eventId = selected.eventId;
            trace.objectKey = selected.key;
            trace.source = selected.source;
            trace.body = selected.body;
            trace.record = selected.record;
            trace.lowCaller = caller;
            trace.lowFrames = frames;
            trace.lowViaMatrix = viaMatrix ? 1u : 0u;
            trace.route = viaMatrix ? g_matrixTls.route : 0u;
            trace.sourceMask = viaMatrix ? g_matrixTls.sourceMask : 0u;
            trace.destinationMask = viaMatrix ? g_matrixTls.destinationMask : 0u;
            trace.matrixCaller = viaMatrix ? g_matrixTls.caller : 0u;
            trace.gainStartBits = FloatBits(gainStart);
            trace.gainDeltaBits = FloatBits(gainDelta);
            EnqueueTrace(trace);
        }
    }

    g_lowLevelChannelMixOriginal(
        sourcePcm, destinationPcm, gainStart, gainDelta, frames);
}

void __fastcall ListenerBridgeHook(std::int64_t owner) {
    g_listenerOriginal(owner);

    PublishLatestListenerTransform(owner);

    // no runtime XAudio2 submit detour (research-only, see Install()).
    Control047();
    ControlNative050();
    // Legacy diagnostic controls remain disabled.
    g_holdWorldAuditionMute.store(
        false,
        std::memory_order_release);
    g_holdDirectHrtf.store(
        false,
        std::memory_order_release);
    g_holdDirectDry.store(false, std::memory_order_release);

    FlushTraceRecords();
}


void DumpCoverageCensus() {
    if (!g_log) return;

    std::uint64_t emitters = 0;
    std::uint64_t reachedRender = 0;
    std::uint64_t reachedMatrix = 0;
    std::uint64_t reachedLow = 0;
    std::uint64_t noRender = 0;
    std::uint64_t renderNoMatrix = 0;
    std::uint64_t matrixNoLow = 0;

    for (const auto& slot : g_coverage) {
        if (slot.signature.load(std::memory_order_acquire) == 0) continue;
        const auto body = slot.body.load(std::memory_order_acquire);
        if (body == 0) continue;

        const auto renderCalls = slot.renderCalls.load(std::memory_order_relaxed);
        const auto matrixCalls = slot.matrixCalls.load(std::memory_order_relaxed);
        const auto lowCalls = slot.lowLevelCalls.load(std::memory_order_relaxed);
        ++emitters;
        if (renderCalls != 0) ++reachedRender; else ++noRender;
        if (matrixCalls != 0) ++reachedMatrix;
        if (lowCalls != 0) ++reachedLow;
        if (renderCalls != 0 && matrixCalls == 0) ++renderNoMatrix;
        if (matrixCalls != 0 && lowCalls == 0) ++matrixNoLow;

        g_log->info(
            "ROUTE_CENSUS,body=0x{:016X},event=0x{:08X},source=0x{:08X},key=0x{:016X},"
            "playing=0x{:08X},first_tick={},last_tick={},source_posts={},render_calls={},"
            "render_match_mask=0x{:X},matrix_calls={},route_mask=0x{:X},"
            "source_masks=0x{:08X}|0x{:08X}|0x{:08X}|0x{:08X},"
            "destination_masks=0x{:08X}|0x{:08X}|0x{:08X}|0x{:08X},"
            "matrix_callers=0x{:016X}|0x{:016X}|0x{:016X}|0x{:016X},"
            "low_calls={},low_via_matrix={},low_via_render={},"
            "low_callers=0x{:016X}|0x{:016X}|0x{:016X}|0x{:016X}",
            static_cast<std::uint64_t>(body),
            slot.eventId.load(std::memory_order_relaxed),
            slot.source.load(std::memory_order_relaxed),
            slot.key.load(std::memory_order_relaxed),
            slot.latestPlaying.load(std::memory_order_relaxed),
            slot.firstTick.load(std::memory_order_relaxed),
            slot.lastTick.load(std::memory_order_relaxed),
            slot.sourcePosts.load(std::memory_order_relaxed),
            renderCalls,
            slot.renderMatchMask.load(std::memory_order_relaxed),
            matrixCalls,
            slot.matrixRouteMask.load(std::memory_order_relaxed),
            slot.sourceMasks[0].load(std::memory_order_relaxed),
            slot.sourceMasks[1].load(std::memory_order_relaxed),
            slot.sourceMasks[2].load(std::memory_order_relaxed),
            slot.sourceMasks[3].load(std::memory_order_relaxed),
            slot.destinationMasks[0].load(std::memory_order_relaxed),
            slot.destinationMasks[1].load(std::memory_order_relaxed),
            slot.destinationMasks[2].load(std::memory_order_relaxed),
            slot.destinationMasks[3].load(std::memory_order_relaxed),
            static_cast<std::uint64_t>(slot.matrixCallers[0].load(std::memory_order_relaxed)),
            static_cast<std::uint64_t>(slot.matrixCallers[1].load(std::memory_order_relaxed)),
            static_cast<std::uint64_t>(slot.matrixCallers[2].load(std::memory_order_relaxed)),
            static_cast<std::uint64_t>(slot.matrixCallers[3].load(std::memory_order_relaxed)),
            lowCalls,
            slot.lowViaMatrix.load(std::memory_order_relaxed),
            slot.lowViaRender.load(std::memory_order_relaxed),
            static_cast<std::uint64_t>(slot.lowCallers[0].load(std::memory_order_relaxed)),
            static_cast<std::uint64_t>(slot.lowCallers[1].load(std::memory_order_relaxed)),
            static_cast<std::uint64_t>(slot.lowCallers[2].load(std::memory_order_relaxed)),
            static_cast<std::uint64_t>(slot.lowCallers[3].load(std::memory_order_relaxed)));
    }

    g_log->info(
        "ROUTE_CENSUS_SUMMARY,emitters={},reached_render={},reached_matrix={},reached_low={},"
        "no_render={},render_no_matrix={},matrix_no_low={}",
        emitters, reachedRender, reachedMatrix, reachedLow,
        noRender, renderNoMatrix, matrixNoLow);

    for (const auto& slot : g_matrixCallerCensus) {
        const auto caller = slot.caller.load(std::memory_order_acquire);
        if (caller == 0) continue;
        g_log->info(
            "MATRIX_CALLER_CENSUS,caller=0x{:016X},calls={},tracked={}",
            static_cast<std::uint64_t>(caller),
            slot.calls.load(std::memory_order_relaxed),
            slot.tracked.load(std::memory_order_relaxed));
    }
    for (const auto& slot : g_lowCallerCensus) {
        const auto caller = slot.caller.load(std::memory_order_acquire);
        if (caller == 0) continue;
        g_log->info(
            "LOWLEVEL_CALLER_CENSUS,caller=0x{:016X},calls={},tracked={}",
            static_cast<std::uint64_t>(caller),
            slot.calls.load(std::memory_order_relaxed),
            slot.tracked.load(std::memory_order_relaxed));
    }
}

} // namespace

bool GetAudioStatus(std::string& text) {
    if(!g_installed.load() || !g_overlay062.load()) return false;
    static bool visible=true,prior=false;
    const bool key=AudioKey062(VK_F6);
    if(key && !prior)visible=!visible;
    prior=key;if(!visible)return false;
    const unsigned mode=g_worldMode047.load();
    const auto activity=Activity048(mode,GetTickCount64(),g_lastApplied048.load(),g_lastAttempt048.load());
    const char* state=activity==0?"Original game audio":activity==1?"Processing matched world sounds":
        activity==2?"Matched sounds falling back to native":"No eligible matched sounds recently";
    char buf[1024]{};
    std::snprintf(buf,sizeof(buf),
        "ChoomAudio | HRTF: %s\n%s\nNative: %s | processed %llu | muted %llu\nProcessed blocks: %llu\nSurround beds: %s | virtualised %llu\nElevation: %s\nF6 hide | F8 on/off | F9 original | F10 sources | F11 mode\nF4 elevation | F5 beds | hold F7 mute spatialised audio",
        mode==0?"OFF":(mode==1?"HYBRID":"PURE"),state,
        !g_nativeEnabled050.load()?"OFF":(g_nativeWide051.load()?"MONO+STEREO":"MONO"),
        static_cast<unsigned long long>(g_nativeApplied050.load()),
        static_cast<unsigned long long>(g_nativeMuted050.load()),
        static_cast<unsigned long long>(g_worldApplied047.load()),
        !g_bedEnabled055.load()?"OFF":(g_bedSkip71_057.load()?"AMBIENCE ONLY":"ALL"),
        static_cast<unsigned long long>(g_bedApplied055.load()),g_elevation059.load()?"ON":"OFF");
    text=buf;return true;
}

void ConfigureLogPath(const std::wstring& path) { g_pluginLogPath=path; }

void ConfigureHookGroups(bool nativeHooks,bool listenerHook,bool mixerHook) {
    g_nativeHooks069.store(nativeHooks);
    g_listenerHook069.store(listenerHook);
    g_mixerHook069.store(mixerHook);
}

void Configure(bool overlay,bool hotkeys,float emphasis,bool debugLog,bool bedCentreDirect,bool peakGuard,bool foxHooks) {
    g_peakGuard066.store(peakGuard);
    g_foxHooks068.store(foxHooks);
    g_debugLog063.store(debugLog);
    g_bedCentreDirect064.store(bedCentreDirect);
    {   // arrival tap of the plain front filter (peak of the left+right energy)
        float l[HRIRSET::kTapCount],r[HRIRSET::kTapCount];
        BuildHrirWithEmphasis064(0.0f,0.0f,0.0f,l,r);
        std::uint32_t best=0; float peak=0.0f;
        for(std::uint32_t t=0;t<HRIRSET::kTapCount;++t){const float v=l[t]*l[t]+r[t]*r[t]; if(v>peak){peak=v;best=t;}}
        g_bedCentreDelay064=(std::min)(best,static_cast<std::uint32_t>(kBedTaps055-1));
    }
    g_overlay062.store(overlay);
    g_hotkeys062.store(hotkeys);
    if(!std::isfinite(emphasis)) emphasis=0.65f;
    g_emphasis062.store((std::min)(1.0f,(std::max)(0.0f,emphasis)));
}

bool Install() {
    if (g_installed.exchange(true)) return true;

    try {
        g_log = spdlog::get("choomaudio_audio");
        if (!g_log) {
            g_log = spdlog::basic_logger_mt(
                "choomaudio_audio",
                g_pluginLogPath,
                true);
        }
        g_log->set_pattern("%v");
        g_log->set_level(spdlog::level::info);
        g_log->flush_on(spdlog::level::warn); // fault reports reach disk even if the game dies next
        g_log->info("CHOOMAUDIO_PLUGIN,AUDIO_V0_73_20260920");
        g_log->info("CONFIG069,audioOverlay={},audioHotkeys={},audioSpatialEmphasis={:.2f},audioDebugLog={},audioBedCentreDirect={},audioPeakGuard={},audioFoxHooks={},native={},listener={},mixer={},centre_delay_taps={}",
            g_overlay062.load()?1:0,g_hotkeys062.load()?1:0,g_emphasis062.load(),g_debugLog063.load()?1:0,g_bedCentreDirect064.load()?1:0,g_peakGuard066.load()?1:0,g_foxHooks068.load()?1:0,g_nativeHooks069.load()?1:0,g_listenerHook069.load()?1:0,g_mixerHook069.load()?1:0,g_bedCentreDelay064);
        {
            double hrirSum=0.0;
            for(std::size_t d=0;d<KEMAR360::kDirectionCount;++d)
                for(std::size_t e=0;e<2;++e)
                    for(std::size_t t=0;t<KEMAR360::kTapCount;++t) hrirSum+=std::fabs(KEMAR360::kHrir[d][e][t]);
            double setSum=0.0;
            for(std::size_t d=0;d<HRIRSET::kDirectionCount;++d) for(std::size_t e=0;e<2;++e) for(std::size_t t=0;t<HRIRSET::kTapCount;++t) setSum+=std::fabs(HRIRSET::kHrir[d][e][t]);
            (void)hrirSum;
            g_log->info("HRIR061,set={},directions={},rings={},abs_sum={:.4f}",HRIRSET::kName,HRIRSET::kDirectionCount,HRIRSET::kRingCount,setSum);
        }
        g_log->info("MODE,default=pure_world_hrtf,f8=toggle_world_hrtf,f9=native_audio,f11=switch_hybrid_pure,f6=toggle_status_overlay,f7=hold_mute_all_spatialised_and_marker,f10=cycle_native_stereo_default_on,f5=cycle_beds_all_ambience_off,f4=toggle_elevation_default_on");
        g_log->info("MODE,submit_target=runtime_sink_voice_vtable_plus_0xA8,selection=validated_sink_ring_buffers,global_mix_diagnostic=0,per_emitter_hrtf=verified_world_sources");
    }
    catch (...) {
        g_log = spdlog::default_logger();
        if (g_log) {
            g_log->error(
                "AudioIdentityBridge: could not create dedicated log; using default logger");
        }
    }

    if (!CheckExactExecutable()) {
        if (g_log) {
            g_log->error("INSTALL_ABORTED,unrecognized_executable");
            g_log->flush();
        }
        g_installed.store(false);
        return false;
    }

    // Plugin bootstrap owns its private MinHook instance and initializes it before Install().
    const bool nativeCtor=g_nativeHooks069.load() && InstallOne(0x388590,
        reinterpret_cast<void*>(&NativeCtorHook050),reinterpret_cast<void**>(&g_nativeCtorOriginal050),"NativeObject.Constructor050");
    const bool nativeSet=g_nativeHooks069.load() && InstallOne(0x388e50,
        reinterpret_cast<void*>(&NativeSetHook050),reinterpret_cast<void**>(&g_nativeSetOriginal050),"NativeObject.SetConsumedPosition050");
    const bool nativeDispatch=g_nativeHooks069.load() && InstallOne(0x34d220,
        reinterpret_cast<void*>(&NativeDispatchHook050),reinterpret_cast<void**>(&g_nativeDispatchOriginal050),"NativeObject.DispatchPosition050");
    g_nativeReady050.store(nativeCtor && nativeSet && nativeDispatch);
    if(g_log)g_log->info("NATIVE_INSTALL050,ctor={},setter={},dispatch={},ready={}",nativeCtor?1:0,nativeSet?1:0,nativeDispatch?1:0,g_nativeReady050.load()?1:0);
    const bool sourceEvent = g_foxHooks068.load() && InstallOne(
        kRvaSourcePostEvent,
        reinterpret_cast<void*>(&SourcePostEventHook),
        reinterpret_cast<void**>(&g_sourcePostOriginal),
        "SoundSourceBody.PostEventInternal");

    const bool sourceTransform = g_foxHooks068.load() && InstallOne(
        kRvaSourceTransformSync,
        reinterpret_cast<void*>(&SourceTransformSyncHook),
        reinterpret_cast<void**>(&g_transformOriginal),
        "SoundSourceBody.TransformSync");

    const bool listener = g_listenerHook069.load() && InstallOne(
        kRvaListenerBridge,
        reinterpret_cast<void*>(&ListenerBridgeHook),
        reinterpret_cast<void**>(&g_listenerOriginal),
        "Camera.ActiveToSoundCoreListenerBridge");

    const bool wwisePost = g_foxHooks068.load() && InstallOne(
        kRvaWwisePostGateway,
        reinterpret_cast<void*>(&WwisePostGatewayHook),
        reinterpret_cast<void**>(&g_wwisePostOriginal),
        "Wwise.PostGateway.FUN_14033C050");

    const bool gameObjectLookup = g_foxHooks068.load() && InstallOne(
        kRvaWwiseGameObjectLookup,
        reinterpret_cast<void*>(&WwiseGameObjectLookupHook),
        reinterpret_cast<void**>(&g_gameObjectLookupOriginal),
        "Wwise.GameObjectLookup.FUN_14034CA50");

    // Leave action-tree diagnostics disabled.
    const bool actionDispatch = false;

    const bool playingEventPack = g_foxHooks068.load() && InstallOne(
        kRvaPlayingEventPack,
        reinterpret_cast<void*>(&PlayingEventPackHook),
        reinterpret_cast<void**>(&g_playingEventPackOriginal),
        "Wwise.PlayingEventPack.FUN_140342060");

    const bool voiceRender = g_foxHooks068.load() && InstallOne(
        kRvaVoiceRenderNode,
        reinterpret_cast<void*>(&VoiceRenderNodeHook),
        reinterpret_cast<void**>(&g_voiceRenderOriginal),
        "Wwise.ActiveRenderNode.FUN_140352330");

    // Leave sink, alternate-mix and runtime submission diagnostics disabled.
    const bool sinkPump = false;

    const bool matrixMix = g_mixerHook069.load() && InstallOne(
        kRvaSourceToDestinationMix,
        reinterpret_cast<void*>(&SourceToDestinationMixHook),
        reinterpret_cast<void**>(&g_sourceToDestinationMixOriginal),
        "Wwise.SourceToDestinationMatrixMix.FUN_1403A77B0");

    const bool alternateMix = false;
    // Leave the SIMD leaf unhooked; use the source-to-destination mixer.
    const bool lowLevelMix = false;

    if (g_log) {
        g_log->info(
            "INSTALL_RESULT,source_event={},source_transform={},listener_flush={},"
            "wwise_post={},game_object_lookup={},play_action={},playing_event_pack={},active_render={},sink_pump={},matrix_mix={},alternate_mix={},low_level_mix={}",
            sourceEvent ? 1 : 0,
            sourceTransform ? 1 : 0,
            listener ? 1 : 0,
            wwisePost ? 1 : 0,
            gameObjectLookup ? 1 : 0,
            actionDispatch ? 1 : 0,
            playingEventPack ? 1 : 0,
            voiceRender ? 1 : 0,
            sinkPump ? 1 : 0,
            matrixMix ? 1 : 0,
            alternateMix ? 1 : 0,
            lowLevelMix ? 1 : 0);
        g_log->info(
            "V047_GOAL,all_verified_supported_world_voices=1,unmatched_native=1");
        g_log->info(
            "V042_HARDENING,low_level_hook=0,play_action_hook=0,submit_descriptor_unchanged=1,live_ring_write=0,no_queue_skipping=1");
        if (!g_debugLog063.load()) {
            // Without extended diagnostics, retain startup information and warnings/errors.
            g_log->info("LOG063,diagnostics=off,set audioDebugLog=true in plugins/choomaudio.lua for full logging");
            g_log->set_level(spdlog::level::warn);
        }
        g_log->flush();
    }

    return sourceEvent || sourceTransform || listener ||
           wwisePost || gameObjectLookup || actionDispatch ||
           playingEventPack || voiceRender || sinkPump || matrixMix || alternateMix || lowLevelMix;
}

void Shutdown() {
    if (!g_installed.exchange(false)) return;

    g_capture040.store(false);
    for (unsigned i=0;i<4;++i) Drain040();
    // Flush diagnostics. The plugin remains loaded until process exit.
    FlushTraceRecords();
    if (g_log) {
        FlushCensus049(true); // bounded final snapshots, including unmatched voices
        LogSubmitSummary039();
        g_log->info(
            "SINK_AUDITION_SHUTDOWN,sink_calls={},sink_forced_silence={},sink_skipped={},last_sink=0x{:016X},last_vtable=0x{:016X},last_frames={}",
            g_sinkPumpCalls.load(std::memory_order_relaxed),
            g_sinkForcedSilenceCalls.load(std::memory_order_relaxed),
            g_sinkSkippedCalls.load(std::memory_order_relaxed),
            static_cast<std::uint64_t>(g_lastSinkObject.load(std::memory_order_relaxed)),
            static_cast<std::uint64_t>(g_lastSinkVtable.load(std::memory_order_relaxed)),
            g_lastSinkFrames.load(std::memory_order_relaxed));
        g_log->info(
            "SHUTDOWN,source_events={},source_valid={},source_invalid={},source_transforms={},"
            "wwise_posts={},actions={},playing_matches={},tls_matches={},"
            "render_calls={},render_tracked={},render_playing={},render_object={},render_dual={},render_unidentified={},"
            "matrix_calls={},matrix_active={},matrix_tracked={},route1={},route2={},route3={},route_other={},"
            "low_calls={},low_tracked={},low_via_matrix={},low_via_render={},"
            "trace_queued={},trace_flushed={},trace_dropped={}",
            g_sourceEvents.load(std::memory_order_relaxed),
            g_sourceRecordsValid.load(std::memory_order_relaxed),
            g_sourceRecordsInvalid.load(std::memory_order_relaxed),
            g_sourceTransforms.load(std::memory_order_relaxed),
            g_wwisePosts.load(std::memory_order_relaxed),
            g_actionDispatches.load(std::memory_order_relaxed),
            g_playingIdMatches.load(std::memory_order_relaxed),
            g_tlsEventMatches.load(std::memory_order_relaxed),
            g_renderNodeCalls.load(std::memory_order_relaxed),
            g_renderTrackedCalls.load(std::memory_order_relaxed),
            g_renderPlayingIdentity.load(std::memory_order_relaxed),
            g_renderObjectIdentity.load(std::memory_order_relaxed),
            g_renderDualIdentity.load(std::memory_order_relaxed),
            g_renderUnidentifiedCalls.load(std::memory_order_relaxed),
            g_matrixCalls.load(std::memory_order_relaxed),
            g_matrixActiveCalls.load(std::memory_order_relaxed),
            g_matrixTrackedCalls.load(std::memory_order_relaxed),
            g_matrixTrackedRoute1.load(std::memory_order_relaxed),
            g_matrixTrackedRoute2.load(std::memory_order_relaxed),
            g_matrixTrackedRoute3.load(std::memory_order_relaxed),
            g_matrixTrackedOther.load(std::memory_order_relaxed),
            g_lowLevelCalls.load(std::memory_order_relaxed),
            g_lowLevelTrackedCalls.load(std::memory_order_relaxed),
            g_lowLevelTrackedViaMatrix.load(std::memory_order_relaxed),
            g_lowLevelTrackedViaRender.load(std::memory_order_relaxed),
            g_traceWrite.load(std::memory_order_relaxed),
            g_traceRead.load(std::memory_order_relaxed),
            g_traceDropped.load(std::memory_order_relaxed));
        g_log->info(
            "ROUTE_AUDITION_SHUTDOWN,primary_calls={},primary_muted={},alternate_calls={},alternate_muted={},alternate_tracked_context={}",
            g_primaryFamilyCalls.load(std::memory_order_relaxed),
            g_primaryFamilyMuteCalls.load(std::memory_order_relaxed),
            g_alternateFamilyCalls.load(std::memory_order_relaxed),
            g_alternateFamilyMuteCalls.load(std::memory_order_relaxed),
            g_alternateFamilyTrackedContext.load(std::memory_order_relaxed));
        g_log->flush();
    }
}

} // namespace MGSVAudioIdentityBridge
