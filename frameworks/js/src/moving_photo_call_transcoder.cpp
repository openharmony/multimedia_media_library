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

#define MLOG_TAG "MediaCallTranscode"
#include "moving_photo_call_transcoder.h"

#include "js_native_api_types.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "moving_photo_transcoder_observer.h"
#include "native_event.h"
#include "unique_fd.h"

namespace OHOS {
namespace Media {
const char* ON_PROGRESS_FUNC = "onProgress";
bool MovingPhotoCallTranscoder::DoTranscode(const std::shared_ptr<MovingPhotoProgressHandler>
    &movingPhotoProgressHandler)
{
    if (movingPhotoProgressHandler == nullptr) {
        NAPI_ERR_LOG("movingPhotoProgressHandler is null");
        return false;
    }
    auto transCoder = TransCoderFactory::CreateTransCoder();
    if (transCoder == nullptr) {
        NAPI_ERR_LOG("Failed to create TransCoder");
        return false;
    }
    auto transCoderCb = std::make_shared<OHOS::Media::MovingphotoTranscoderObserver>();
    if (transCoderCb == nullptr) {
        NAPI_ERR_LOG("Failed to create transCoderCb");
        return false;
    }
    transCoderCb->SetMovingPhotoProgress(movingPhotoProgressHandler);
    transCoderCb->setTransCoder(transCoder);
    if (transCoder->SetTransCoderCallback(transCoderCb) != E_OK) {
        NAPI_ERR_LOG("Failed to set TransCoder callback");
        return false;
    }
    if (transCoder->SetInputFile(movingPhotoProgressHandler->srcFd.Get(), movingPhotoProgressHandler->offset,
        movingPhotoProgressHandler->size) != E_OK) {
        NAPI_ERR_LOG("Failed to set input file for TransCoder");
        return false;
    }
    if (transCoder->SetOutputFile(movingPhotoProgressHandler->destFd.Get()) != E_OK) {
        NAPI_ERR_LOG("Failed to set output file for TransCoder");
        return false;
    }
    if (transCoder->SetOutputFormat(FORMAT_MPEG_4) != E_OK) {
        NAPI_ERR_LOG("Failed to SetOutputFormat");
        return false;
    }
    if (transCoder->Prepare() != E_OK) {
        NAPI_ERR_LOG("Failed to prepare TransCoder");
        transCoderCb->DoPrepareError();
        return false;
    }
    if (transCoder->Start() != E_OK) {
        NAPI_ERR_LOG("Failed to TransCoder Start");
        return false;
    }
    NAPI_INFO_LOG("DoTranscode success");
    return true;
}

void MovingphotoTranscoderObserver::DoPrepareError()
{
    isPrepareError.store(true);
    ErrorExcute();
}

void MovingphotoTranscoderObserver::CallMovingProgressCallback(bool isComplete)
{
    NAPI_DEBUG_LOG("CallMovingProgressCallback");
    if (movingPhotoProgressHandler_ == nullptr || movingPhotoProgressHandler_->onProgressFunc == nullptr) {
        NAPI_ERR_LOG("CallMovingProgressCallback: movingPhotoProgressHandler_ is null");
        return;
    }

    napi_status status = napi_acquire_threadsafe_function(movingPhotoProgressHandler_->onProgressFunc);
    if (status != napi_ok) {
        NAPI_ERR_LOG("napi_acquire_threadsafe_function fail, status: %{public}d", static_cast<int32_t>(status));
        return;
    }
    auto asyncHandler = std::make_unique<MovingPhotoProgressHandler>();
    if (asyncHandler == nullptr) {
        NAPI_ERR_LOG("CallMovingProgressCallback: asyncHandler is null");
        return;
    }
    asyncHandler->isComplete = isComplete;
    if (isComplete) {
        asyncHandler->env = movingPhotoProgressHandler_->env;
        asyncHandler->contextData = movingPhotoProgressHandler_->contextData;
        asyncHandler->errCode = movingPhotoProgressHandler_->errCode;
    } else {
        asyncHandler->mediaAssetEnv = movingPhotoProgressHandler_->mediaAssetEnv;
        asyncHandler->extra = movingPhotoProgressHandler_->extra;
        asyncHandler->progressHandlerRef = movingPhotoProgressHandler_->progressHandlerRef;
    }

    status = napi_call_threadsafe_function(movingPhotoProgressHandler_->onProgressFunc, (void *)asyncHandler.get(),
        napi_tsfn_blocking);
    if (status != napi_ok) {
        NAPI_ERR_LOG("napi_call_threadsafe_function fail, status: %{public}d", static_cast<int32_t>(status));
    }
    (void)asyncHandler.release();
}

static void OnProgress(napi_env env, napi_value cb, void *context, void *data)
{
    NAPI_DEBUG_LOG("OnProgress");
    auto mpHandler = reinterpret_cast<MovingPhotoProgressHandler *>(data);
    if (mpHandler == nullptr) {
        NAPI_ERR_LOG("Moving photo progress env is null");
        return;
    }
    if (mpHandler->isComplete) {
        if (mpHandler->callbackFunc == nullptr) {
            NAPI_ERR_LOG("OnProgress callbackFunc is null");
            return;
        }
        mpHandler->callbackFunc(mpHandler->env, mpHandler->contextData, mpHandler->errCode);
        return;
    }
    if (mpHandler->mediaAssetEnv == nullptr) {
        NAPI_ERR_LOG("mpHandler mediaAssetEnv is null");
        return;
    }
    napi_value result;
    napi_status status = napi_create_int32(mpHandler->mediaAssetEnv,
        mpHandler->extra, &result);
    if (status != napi_ok) {
        NAPI_ERR_LOG("OnProgress napi_create_int32 fail");
        return;
    }
    napi_value jsCallback = nullptr;
    status = napi_get_reference_value(mpHandler->mediaAssetEnv,
        mpHandler->progressHandlerRef, &jsCallback);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Create reference fail, status: %{public}d", status);
        return;
    }
    napi_value jsOnProgress;
    status = napi_get_named_property(mpHandler->mediaAssetEnv, jsCallback, ON_PROGRESS_FUNC,
        &jsOnProgress);
    if (status != napi_ok) {
        NAPI_ERR_LOG("jsOnProgress napi_get_named_property fail, napi status: %{public}d",
            static_cast<int>(status));
        return;
    }
    const size_t ARGS_ONE = 1;
    napi_value argv[ARGS_ONE];
    napi_value retVal = nullptr;
    argv[0] = result;
    napi_call_function(mpHandler->mediaAssetEnv, nullptr, jsOnProgress, ARGS_ONE, argv, &retVal);
    if (status != napi_ok) {
        NAPI_ERR_LOG("CallJs napi_call_function fail, status: %{public}d", static_cast<int>(status));
    }
}

void MovingphotoTranscoderObserver::SetMovingPhotoProgress(
    const std::shared_ptr<MovingPhotoProgressHandler> &movingPhotoProgressHandler)
{
    movingPhotoProgressHandler_ = movingPhotoProgressHandler;
    if (movingPhotoProgressHandler_ == nullptr) {
        NAPI_ERR_LOG("SetMovingPhotoProgress, movingPhotoProgressHandler_ is null");
        return;
    }
    napi_value jsCallback = nullptr;
    napi_status status = napi_get_reference_value(movingPhotoProgressHandler_->mediaAssetEnv,
        movingPhotoProgressHandler_->progressHandlerRef, &jsCallback);
    if (status != napi_ok) {
        NAPI_ERR_LOG("Create reference fail, status: %{public}d", status);
        return;
    }

    napi_value workName = nullptr;
    auto env = movingPhotoProgressHandler_->mediaAssetEnv;
    napi_create_string_utf8(env, "OnProgress", NAPI_AUTO_LENGTH, &workName);
    status = napi_create_threadsafe_function(env, jsCallback, NULL, workName, 0, 1, NULL, NULL, NULL,
        OnProgress, &movingPhotoProgressHandler_->onProgressFunc);
    if (status != napi_ok) {
        NAPI_ERR_LOG("napi_create_threadsafe_function fail");
        movingPhotoProgressHandler_->onProgressFunc = nullptr;
    }
}

void MovingphotoTranscoderObserver::ErrorExcute()
{
    if (movingPhotoProgressHandler_ == nullptr) {
        NAPI_ERR_LOG("ErrorExcute, movingPhotoProgressHandler_ is null");
        return;
    }
    movingPhotoProgressHandler_->errCode = E_ERR;
    if (isPrepareError.load()) {
        movingPhotoProgressHandler_->errCode = E_INVALID_MODE;
    }
    CallMovingProgressCallback(true);
}

void MovingphotoTranscoderObserver::OnInfo(int32_t type, int32_t extra)
{
    NAPI_INFO_LOG("MediaAssetManagerCallback OnInfo type:%{public}d extra:%{public}d", type, extra);
    if (movingPhotoProgressHandler_ == nullptr) {
        NAPI_ERR_LOG("OnInfo, movingPhotoProgressHandler_ is null");
        return;
    }
    if (type == INFO_TYPE_TRANSCODER_COMPLETED) {
        if (transCoder_ == nullptr) {
            NAPI_ERR_LOG("transCoder_ is null, cannot release resources");
            return;
        }
        movingPhotoProgressHandler_->errCode = E_OK;
        CallMovingProgressCallback(true);
        transCoder_->Release();
        return;
    }
    if (movingPhotoProgressHandler_->progressHandlerRef == nullptr) {
        NAPI_INFO_LOG("progressHandlerRef is nullptr");
        return;
    }
    movingPhotoProgressHandler_->extra = extra;
    CallMovingProgressCallback();
}

void MovingphotoTranscoderObserver::OnError(int32_t errCode, const std::string &errorMsg)
{
    NAPI_ERR_LOG("MediaAssetManagerCallback OnError errCode:%{public}d errorMsg:%{public}s",
        errCode, errorMsg.c_str());
    if (transCoder_ == nullptr) {
        NAPI_ERR_LOG("transCoder_ is null, cannot release resources");
        return;
    }
    transCoder_->Release();
    if (isPrepareError.load()) {
        return;
    }
    ErrorExcute();
}
} // namespace Media
} // namespace OHOS
