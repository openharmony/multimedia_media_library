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

#include "video_composition_callback_imp.h"

#include "media_log.h"
#include "media_file_utils.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "medialibrary_errno.h"
#include "photo_file_utils.h"

using std::string;

namespace OHOS {
namespace Media {
static const mode_t CHOWN_RW_USR_GRP = 0600;
static const int32_t LOG_FREQUENCY = 10;
std::unordered_map<uint32_t, std::shared_ptr<VideoEditor>> VideoCompositionCallbackImpl::editorMap_;
std::queue<VideoCompositionCallbackImpl::Task> VideoCompositionCallbackImpl::waitQueue_;
int32_t VideoCompositionCallbackImpl::curWorkerNum_ = 0;
std::mutex VideoCompositionCallbackImpl::mutex_;

VideoCompositionCallbackImpl::VideoCompositionCallbackImpl() {}

void VideoCompositionCallbackImpl::onResult(VEFResult result, VEFError errorCode)
{
    editorMap_.erase(inputFileFd_);
    size_t lastSlash = videoPath_.rfind('.');
    string sourceImagePath = videoPath_.substr(0, lastSlash) + ".jpg";
    string sourceVideoPath = MediaFileUtils::GetMovingPhotoVideoPath(sourceImagePath);
    if (errorCode != VEFError::ERR_OK) {
        mutex_.lock();
        --curWorkerNum_;
        mutex_.unlock();
        MEDIA_ERR_LOG("VideoCompositionCallbackImpl onResult error:%{public}d", (int32_t)errorCode);
        // Video Composite failed save sourceVideo to photo directory
        CHECK_AND_RETURN_LOG(MediaFileUtils::CopyFileUtil(sourceVideoPath, videoPath_),
            "Copy sourceVideoPath to videoPath, path:%{private}s", sourceVideoPath.c_str());
        return ;
    }

    mutex_.lock();
    if (waitQueue_.empty()) {
        --curWorkerNum_;
        mutex_.unlock();
    } else {
        Task task = std::move(waitQueue_.front());
        waitQueue_.pop();
        mutex_.unlock();
        CallStartComposite(task.sourceVideoPath_, task.videoPath_, task.editData_);
    }
}

void VideoCompositionCallbackImpl::onProgress(uint32_t progress)
{
    if (!(progress % LOG_FREQUENCY)) {
        MEDIA_INFO_LOG("VideoCompositionCallbackImpl onProcess:%{public}d, tempPath:%{public}s",
            (int32_t)progress, videoPath_.c_str());
    }
}

int32_t VideoCompositionCallbackImpl::CallStartComposite(const std::string& sourceVideoPath,
    const std::string& videoPath, const std::string& effectDescription)
{
    MEDIA_INFO_LOG("Call StartComposite begin, sourceVideoPath:%{public}s", sourceVideoPath.c_str());
    int32_t inputFileFd = open(sourceVideoPath.c_str(), O_RDONLY);
    if (inputFileFd == -1) {
        MEDIA_ERR_LOG("Open failed for inputFileFd file");
        return E_ERR;
    }

    int32_t outputFileFd = open(videoPath.c_str(), O_WRONLY|O_CREAT, CHOWN_RW_USR_GRP);
    if (outputFileFd == -1) {
        MEDIA_ERR_LOG("Open failed for outputFileFd file");
        return E_ERR;
    }

    auto callBack = std::make_shared<VideoCompositionCallbackImpl>();
    auto editor = VideoEditorFactory::CreateVideoEditor();
    if (editor == nullptr) {
        MEDIA_ERR_LOG("CreateEditor failed with error");
        return E_ERR;
    }
    callBack->inputFileFd_ = inputFileFd;
    callBack->videoPath_ = videoPath;

    VEFError error = editor->AppendVideoFile(inputFileFd, effectDescription);
    if (error != VEFError::ERR_OK) {
        editor = nullptr;
        MEDIA_ERR_LOG("AppendVideoFile failed with error: %{public}d", (int32_t)error);
        return E_ERR;
    }
    auto compositionOptions = std::make_shared<CompositionOptions>(outputFileFd, callBack);
    error = editor->StartComposite(compositionOptions);
    if (error != VEFError::ERR_OK) {
        editor = nullptr;
        MEDIA_ERR_LOG("StartComposite failed with error: %{public}d", (int32_t)error);
        return E_ERR;
    }
    callBack->editorMap_[inputFileFd] = editor;
    return E_OK;
}

void VideoCompositionCallbackImpl::AddCompositionTask(std::string& assetPath, std::string& editData)
{
    string sourceImagePath = PhotoFileUtils::GetEditDataSourcePath(assetPath);
    string videoPath = MediaFileUtils::GetMovingPhotoVideoPath(assetPath);
    string sourceVideoPath = MediaFileUtils::GetMovingPhotoVideoPath(sourceImagePath);

    mutex_.lock();
    if (curWorkerNum_ < MAX_CONCURRENT_NUM) {
        ++curWorkerNum_;
        mutex_.unlock();
        CHECK_AND_RETURN_LOG(CallStartComposite(sourceVideoPath, videoPath, editData) == E_OK,
            "Failed to CallStartComposite, path:%{private}s", videoPath.c_str());
    } else {
        Task newWaitTask{sourceVideoPath, videoPath, editData};
        waitQueue_.push(std::move(newWaitTask));
        mutex_.unlock();
    }
}

void VideoCompositionCallbackImpl::EraseStickerField(std::string& editData, size_t index)
{
    auto begin = index - START_DISTANCE;
    auto end = index;
    while (editData[end] != '}') {
        ++end;
    }
    ++end;
    auto len = end - begin + 1;
    editData.erase(begin, len);
}

} // end of namespace
}