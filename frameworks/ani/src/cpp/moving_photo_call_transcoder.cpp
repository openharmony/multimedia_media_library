/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MovingPhotoCallTranscoderAni"
#include "moving_photo_call_transcoder.h"

#include "ani_class_name.h"
#include "ani_error.h"
#include "media_asset_data_handler_ani.h"
#include "medialibrary_ani_log.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_errno.h"
#include "moving_photo_transcoder_observer.h"
#include "progress_handler.h"

namespace OHOS {
namespace Media {
bool MovingPhotoCallTranscoder::DoTranscode(const std::shared_ptr<MovingPhotoProgressHandler> &mppHandler)
{
    ANI_CHECK_RETURN_RET_LOG(mppHandler != nullptr, false, "movingPhotoProgressHandler is null");
    auto transCoder = TransCoderFactory::CreateTransCoder();
    ANI_CHECK_RETURN_RET_LOG(transCoder != nullptr, false, "Failed to create TransCoder");

    auto observer = std::make_shared<MovingPhotoTranscoderObserver>();
    ANI_CHECK_RETURN_RET_LOG(observer != nullptr, false, "Failed to create observer");

    observer->SetMovingPhotoProgressHandler(mppHandler);
    observer->setTransCoder(transCoder);

    ANI_CHECK_RETURN_RET_LOG(transCoder->SetTransCoderCallback(observer) == E_OK, false,
        "Failed to set TransCoder callback");

    auto ret = transCoder->SetInputFile(mppHandler->srcFd.Get(), mppHandler->offset, mppHandler->size);
    ANI_CHECK_RETURN_RET_LOG(ret == E_OK, false, "Failed to set input file for TransCoder");

    ANI_CHECK_RETURN_RET_LOG(transCoder->SetOutputFile(mppHandler->destFd.Get()) == E_OK, false,
        "Failed to set output file for TransCoder");

    ANI_CHECK_RETURN_RET_LOG(transCoder->SetOutputFormat(FORMAT_MPEG_4) == E_OK, false, "Failed to SetOutputFormat");

    if (transCoder->Prepare() != E_OK) {
        ANI_ERR_LOG("Failed to prepare TransCoder");
        observer->DoPrepareError();
        return false;
    }
    if (transCoder->Start() != E_OK) {
        ANI_ERR_LOG("Failed to start TransCoder");
        observer->DoPrepareError();
        return false;
    }
    ANI_INFO_LOG("DoTranscode success");
    return true;
}

void MovingPhotoCallTranscoder::OnProgress(ani_env *env, ProgressHandler *progressHandler)
{
    ANI_CHECK_RETURN_LOG(env != nullptr, "env is null");
    ANI_CHECK_RETURN_LOG(progressHandler != nullptr, "progressHandler is null");
    ANI_CHECK_WARN_LOG(progressHandler->progressRef != nullptr, "Ets processcallback reference is null");

    ani_class cls {};
    static const char *className = PAH_ANI_CLASS_MEDIA_MANAGER.c_str();
    ani_status status = env->FindClass(className, &cls);
    ANI_CHECK_RETURN_LOG(status == ANI_OK, "find class status: %{public}d", static_cast<int>(status));

    static const char *methodName = ON_MEDIA_ASSET_PROGRESS_FUNC;
    ani_static_method etsOnProgress {};
    status = env->Class_FindStaticMethod(cls, methodName, nullptr, &etsOnProgress);
    ANI_CHECK_RETURN_LOG(status == ANI_OK, "find static method status: %{public}d", static_cast<int>(status));

    ani_int processAni = static_cast<ani_int>(progressHandler->retProgressValue.progress);
    ani_object progressHandlerAni = static_cast<ani_object>(progressHandler->progressRef);
    status = env->Class_CallStaticMethod_Void(cls, etsOnProgress, processAni, progressHandlerAni);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to execute static method: %{public}s, ani status: %{public}d",
            methodName, static_cast<int>(status));
        return;
    }
}

MovingPhotoTranscoderObserver::~MovingPhotoTranscoderObserver()
{
    if (mppHandler_ == nullptr) {
        return;
    }
    if (mppHandler_->progressHandlerRef == nullptr || mppHandler_->etsVm == nullptr) {
        return;
    }
    ani_env *env = nullptr;
    ani_options aniArgs {0, nullptr};
    auto status = mppHandler_->etsVm->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env);
    ANI_CHECK_RETURN_LOG(status == ANI_OK && env != nullptr, "AttachCurrentThread failed");
    env->GlobalReference_Delete(mppHandler_->progressHandlerRef);
    mppHandler_->progressHandlerRef = nullptr;
    status = mppHandler_->etsVm->DetachCurrentThread();
    ANI_CHECK_RETURN_LOG(status == ANI_OK, "DetachCurrentThread failed");
    mppHandler_.reset();
}

void MovingPhotoTranscoderObserver::DoPrepareError()
{
    isPrepareError_.store(true);
    if (transCoder_ != nullptr) {
        transCoder_->Release();
    }
}

void MovingPhotoTranscoderObserver::NotifyProcessInfo()
{
    ANI_CHECK_RETURN_LOG(mppHandler_ != nullptr, "mppHandler_ is null");

    if (mppHandler_->isComplete.load()) {
        ANI_CHECK_RETURN_LOG(mppHandler_->callbackFunc != nullptr, "callbackFunc is null");
        mppHandler_->callbackFunc(mppHandler_->contextData, mppHandler_->errCode);
        return;
    }
    ANI_CHECK_RETURN_LOG(mppHandler_->onProgressFunc != nullptr, "onProgressFunc is null");
    auto progressHandler = std::make_unique<ProgressHandler>();
    ANI_CHECK_RETURN_LOG(progressHandler != nullptr, "progressHandler is null");
    progressHandler->progressRef = mppHandler_->progressHandlerRef;
    progressHandler->etsVm = mppHandler_->etsVm;
    progressHandler->retProgressValue.progress = mppHandler_->process;

    std::thread([progressHandler = std::move(progressHandler), this] {
        mppHandler_->onProgressFunc(progressHandler.get());
    }).detach();
}

void MovingPhotoTranscoderObserver::SetMovingPhotoProgressHandler(
    const std::shared_ptr<MovingPhotoProgressHandler> &mppHandler)
{
    mppHandler_ = mppHandler;
}

void MovingPhotoTranscoderObserver::OnInfo(int32_t type, int32_t extra)
{
    ANI_DEBUG_LOG("OnInfo type:%{public}d extra:%{public}d", type, extra);
    ANI_CHECK_RETURN_LOG(mppHandler_ != nullptr, "OnInfo, mppHandler_ is null");
    if (mppHandler_->isComplete.load()) {
        ANI_DEBUG_LOG("Transcoder already completed");
        return;
    }
    if (type == INFO_TYPE_TRANSCODER_COMPLETED) {
        mppHandler_->isComplete.store(true);
        mppHandler_->errCode = E_OK;
        NotifyProcessInfo();
        if (transCoder_ != nullptr) {
            transCoder_->Release();
        }
        return;
    }
    if (mppHandler_->progressHandlerRef == nullptr) {
        ANI_DEBUG_LOG("progressHandlerRef is nullptr");
        return;
    }
    mppHandler_->process = extra;
    if (extra == process_) {
        ANI_DEBUG_LOG("process is same as last time, no need to notify");
        return;
    }
    process_ = extra;
    NotifyProcessInfo();
}

void MovingPhotoTranscoderObserver::OnError(int32_t errCode, const std::string &errorMsg)
{
    ANI_ERR_LOG("OnError errCode:%{public}d errorMsg:%{public}s", errCode, errorMsg.c_str());
    if (transCoder_ != nullptr) {
        transCoder_->Release();
    }
    if (isPrepareError_.load()) {
        return;
    }
    if (mppHandler_ != nullptr) {
        mppHandler_->errCode = E_ERR;
        mppHandler_->isComplete.store(true);
        NotifyProcessInfo();
    }
}
} // namespace Media
} // namespace OHOS
