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

#include "dfx_manager.h"

#include "media_file_utils.h"
#include "media_log.h"
#include "userfile_manager_types.h"

using namespace std;

namespace OHOS {
namespace Media {

shared_ptr<DfxManager> DfxManager::dfxManagerInstance_{nullptr};
mutex DfxManager::instanceLock_;

shared_ptr<DfxManager> DfxManager::GetInstance()
{
    if (dfxManagerInstance_ == nullptr) {
        lock_guard<mutex> lockGuard(instanceLock_);
        dfxManagerInstance_ = make_shared<DfxManager>();
        if (dfxManagerInstance_ != nullptr) {
            dfxManagerInstance_->Init();
        }
    }
    return dfxManagerInstance_;
}

DfxManager::DfxManager() : isInitSuccess_(false)
{
}

DfxManager::~DfxManager()
{
}

void DfxManager::Init()
{
    MEDIA_INFO_LOG("Init DfxManager");
    dfxReporter_ = make_shared<DfxReporter>();
    isInitSuccess_ = true;
}

void DfxManager::HandleTimeOutOperation(std::string &bundleName, std::string &type, std::string &object, int64_t time)
{
    if (isInitSuccess_) {
        MEDIA_WARN_LOG("DfxManager not init");
        return;
    }
    dfxReporter_->ReportTimeOutOperation(bundleName, type, object, time);
}

void DfxManager::HandleHighMemoryThumbnail(std::string &path, int32_t mediaType, int32_t width,
    int32_t height)
{
    if (isInitSuccess_) {
        MEDIA_WARN_LOG("DfxManager not init");
        return;
    }
    string suffix = MediaFileUtils::GetExtensionFromPath(path);
    if (mediaType == MEDIA_TYPE_IMAGE) {
        dfxReporter_->ReportHighMemoryImageThumbnail(path, suffix, width, height);
    } else {
        dfxReporter_->ReportHighMemoryVideoThumbnail(path, suffix, width, height);
    }
}
} // namespace Media
} // namespace OHOS