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

#define MLOG_TAG "MediaCallTranscode"

#include "media_asset_manager_callback.h"
#include "media_call_transcode.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_errno.h"

namespace OHOS {
namespace Media {

static MediaCallTranscode::CallbackType callback_;
static std::map<std::string, std::shared_ptr<TransCoder>> transCoderMap_;
static const int32_t INFO_TYPE_ERROR = 2;
void MediaCallTranscode::TransCodeError(napi_env env, napi_value &result,
    int srcFd, int destFd, const std::string& errorMsg)
{
    NAPI_ERR_LOG(" %{public}s", errorMsg.c_str());
    close(srcFd);
    close(destFd);
    napi_get_boolean(env, false, &result);
}

void MediaCallTranscode::CallTranscodeHandle(napi_env env, int srcFd, int destFd,
    napi_value &result, off_t &size, std::string requestId)
{
    NAPI_INFO_LOG("CallTranscodeHandle start");
    auto transCoder = TransCoderFactory::CreateTransCoder();
    if (transCoder == nullptr) {
        TransCodeError(env, result, srcFd, destFd, "Failed to create TransCoder");
        return;
    }
    transCoderMap_.insert(std::pair<std::string, std::shared_ptr<TransCoder>>(requestId, transCoder));
    auto transCoderCb = std::make_shared<OHOS::Media::MediaAssetManagerCallback>();
    if (transCoderCb == nullptr) {
        TransCodeError(env, result, srcFd, destFd, "Failed to create MediaAssetManagerCallback");
        return;
    }
    transCoderCb->SetRequestId(requestId);
    int32_t ret = transCoder->SetTransCoderCallback(transCoderCb);
    if (ret != E_OK) {
        TransCodeError(env, result, srcFd, destFd, "Failed to set TransCoder callback");
        return;
    }
    ret = transCoder->SetInputFile(srcFd, 0, size);
    if (ret != E_OK) {
        TransCodeError(env, result, srcFd, destFd, "Failed to set input file for TransCoder");
        return;
    }
    ret = transCoder->SetOutputFile(destFd);
    if (ret != E_OK) {
        TransCodeError(env, result, srcFd, destFd, "Failed to set output file for TransCoder");
        return;
    }
    ret = transCoder->SetOutputFormat(FORMAT_MPEG_4);
    if (ret != E_OK) {
        TransCodeError(env, result, srcFd, destFd, "Failed to SetOutputFormat");
        return;
    }
    ret = transCoder->Prepare();
    if (ret != E_OK) {
        TransCodeError(env, result, srcFd, destFd, "Failed to prepare TransCoder");
        return;
    }
    ret = transCoder->Start();
    if (ret != E_OK) {
        TransCodeError(env, result, srcFd, destFd, "Failed to TransCoder Start");
        return;
    }
    napi_get_boolean(env, true, &result);
}

void MediaCallTranscode::CallTranscodeRelease(const std::string& requestId)
{
    auto tcm = transCoderMap_.find(requestId);
    if (tcm == transCoderMap_.end()) {
        return;
    }
    tcm->second->Release();
    transCoderMap_.erase(tcm);
}

void MediaCallTranscode::RegisterCallback(const CallbackType &cb)
{
    callback_ = cb;
}

void MediaAssetManagerCallback::OnInfo(int32_t type, int32_t extra)
{
    NAPI_INFO_LOG("MediaAssetManagerCallback OnInfo type:%{public}d extra:%{public}d", type, extra);
    if (callback_) {
        callback_(type, extra, requestId_);
    }
}

void MediaAssetManagerCallback::OnError(int32_t errCode, const std::string &errorMsg)
{
    auto tcm = transCoderMap_.find(requestId_);
    transCoderMap_.erase(tcm);
    NAPI_ERR_LOG("MediaAssetManagerCallback OnInfo errorMsg:%{public}s", errorMsg.c_str());
    int32_t type = INFO_TYPE_ERROR;
    if (callback_) {
        callback_(type, 0, requestId_);
    }
}

void MediaAssetManagerCallback::SetRequestId(std::string requestId)
{
    requestId_ = requestId;
}
} // namespace Media
} // namespace OHOS
