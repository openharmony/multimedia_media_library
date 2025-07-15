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

#include "media_call_transcode.h"
#include "media_asset_manager_callback.h"
#include "medialibrary_ani_log.h"
#include "medialibrary_errno.h"
#include "unique_fd.h"

namespace OHOS {
namespace Media {

static MediaCallTranscode::CallbackType callback_;
static std::mutex transCoderMapMutex_;
static std::map<std::string, std::shared_ptr<TransCoder>> transCoderMap_;
static const int32_t INFO_TYPE_ERROR = 2;

static ani_status CreateAniBooleanObject(ani_env *env, bool value, ani_object &aniObj)
{
    if (env == nullptr) {
        ANI_ERR_LOG("env is nullptr");
        return ANI_ERROR;
    }
    ani_class cls {};
    ani_status status = env->FindClass("Lstd/core/Boolean;", &cls);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find class std/core/Boolean");
        return status;
    }
    ani_method ctor {};
    status = env->Class_FindMethod(cls, "<ctor>", "Z:V", &ctor);
    if (status != ANI_OK) {
        ANI_ERR_LOG("Failed to find method: ctor");
        return status;
    }
    ani_boolean aniBool = value ? ANI_TRUE : ANI_FALSE;
    status = env->Object_New(cls, ctor, &aniObj, aniBool);
    if (status != ANI_OK) {
        ANI_ERR_LOG("New bool Object Fail");
        return status;
    }
    return ANI_OK;
}

void MediaCallTranscode::CallTranscodeHandle(ani_env *env, int srcFd, int destFd,
    ani_object &result, off_t &size, std::string requestId)
{
    ANI_INFO_LOG("CallTranscodeHandle start");
    bool ret = DoTranscode(srcFd, destFd, size, requestId);
    CreateAniBooleanObject(env, ret, result);
}

bool MediaCallTranscode::DoTranscode(int srcFd, int destFd, off_t &size, std::string requestId)
{
    UniqueFd uniqueSrcFd(srcFd);
    UniqueFd uniqueDestFd(destFd);
    auto transCoder = TransCoderFactory::CreateTransCoder();
    if (transCoder == nullptr) {
        ANI_ERR_LOG("Failed to create TransCoder");
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(transCoderMapMutex_);
        transCoderMap_.insert(std::pair<std::string, std::shared_ptr<TransCoder>>(requestId, transCoder));
    }
    auto transCoderCb = std::make_shared<OHOS::Media::MediaAssetManagerCallback>();
    if (transCoderCb == nullptr) {
        ANI_ERR_LOG("Failed to create TransCoder");
        return false;
    }
    transCoderCb->SetRequestId(requestId);
    if (transCoder->SetTransCoderCallback(transCoderCb) != E_OK) {
        ANI_ERR_LOG("Failed to set TransCoder callback");
        return false;
    }
    if (transCoder->SetInputFile(uniqueSrcFd.Get(), 0, size) != E_OK) {
        ANI_ERR_LOG("Failed to set input file for TransCoder");
        return false;
    }
    if (transCoder->SetOutputFile(uniqueDestFd.Get()) != E_OK) {
        ANI_ERR_LOG("Failed to set output file for TransCoder");
        return false;
    }
    if (transCoder->SetOutputFormat(FORMAT_MPEG_4) != E_OK) {
        ANI_ERR_LOG("Failed to SetOutputFormat");
        return false;
    }
    if (transCoder->Prepare() != E_OK) {
        ANI_ERR_LOG("Failed to prepare TransCoder");
        transCoder->Release();
        return false;
    }
    if (transCoder->Start() != E_OK) {
        ANI_ERR_LOG("Failed to TransCoder Start");
        return false;
    }
    return true;
}

void MediaCallTranscode::CallTranscodeRelease(const std::string& requestId)
{
    std::lock_guard<std::mutex> lock(transCoderMapMutex_);
    auto it = transCoderMap_.find(requestId);
    if (it == transCoderMap_.end()) {
        return;
    }
    it->second->Release();
    transCoderMap_.erase(it);
}

void MediaCallTranscode::RegisterCallback(const CallbackType &cb)
{
    callback_ = cb;
}

void MediaAssetManagerCallback::OnInfo(int32_t type, int32_t extra)
{
    ANI_INFO_LOG("MediaAssetManagerCallback OnInfo type:%{public}d extra:%{public}d", type, extra);
    if (callback_) {
        callback_(type, extra, requestId_);
    }
}

void MediaAssetManagerCallback::OnError(int32_t errCode, const std::string &errorMsg)
{
    std::lock_guard<std::mutex> lock(transCoderMapMutex_);
    auto it = transCoderMap_.find(requestId_);
    if (it != transCoderMap_.end()) {
        transCoderMap_.erase(it);
    }
    ANI_ERR_LOG("MediaAssetManagerCallback OnError errorMsg:%{public}s", errorMsg.c_str());
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
