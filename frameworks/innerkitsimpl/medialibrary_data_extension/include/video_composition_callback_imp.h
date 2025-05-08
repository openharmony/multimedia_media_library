/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef VIDEO_COMPOSITION_CALLBACK_IMP
#define VIDEO_COMPOSITION_CALLBACK_IMP

#include "video_editor/include/video_editor.h"
#include <queue>
#include <mutex>

using std::string;

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
static const std::string FRAME_STICKER = "FrameSticker";
static const std::string INPLACE_STICKER = "InplaceSticker";
static const std::string TIMING_STICKER = "TimingSticker";
static const std::string FESTIVAL_STICKER = "FestivalSticker";
static const std::string FILTERS_FIELD = "filters";
static const char FILTERS_END = ',';
static const int32_t MAX_CONCURRENT_NUM = 5;
static const int32_t START_DISTANCE = 10;

class EXPORT VideoCompositionCallbackImpl : public CompositionCallback {
public:
    VideoCompositionCallbackImpl();
    virtual ~VideoCompositionCallbackImpl() = default;

    struct Task {
        string sourceVideoPath_;
        string videoPath_;
        string editData_;
        string assetPath_;
        bool isNeedScan_;
        Task(string& sourceVideoPath, string& videoPath, string& editData, const string& assetPath, bool isNeedScan)
            : sourceVideoPath_(sourceVideoPath),
            videoPath_(videoPath),
            editData_(editData),
            assetPath_(assetPath),
            isNeedScan_(isNeedScan)
        {
        }
    };

    void onResult(VEFResult result, VEFError errorCode) override;
    void onProgress(uint32_t progress) override;

    static int32_t CallStartComposite(const std::string& sourceVideoPath, const std::string& videoPath,
        const std::string& effectDescription, const std::string& assetPath, bool isNeedScan);
    static void AddCompositionTask(const std::string& assetPath, std::string& editData, bool isNeedScan);
    static void EraseStickerField(std::string& editData, size_t index, bool isTimingSticker);
    static void InitCallbackImpl(std::shared_ptr<VideoCompositionCallbackImpl>& callBack,
        int32_t inputFileFd, int32_t outputFileFd, const std::string& videoPath, std::string& absSourceVideoPath,
        const std::string& assetPath, bool isNeedScan);

private:
    static std::unordered_map<uint32_t, std::shared_ptr<VideoEditor>> editorMap_;
    static std::queue<Task> waitQueue_;
    static int32_t curWorkerNum_;
    static std::mutex mutex_;
    int32_t inputFileFd_ = 0;
    int32_t outputFileFd_ = 0;
    string videoPath_;
    string tempFilters_;
    string sourceVideoPath_;
    string assetPath_;
    bool isNeedScan_ = false;
};

} // end of namespace
}
#endif