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
#define MLOG_TAG "DfxCollector"

#include "dfx_collector.h"

#include "media_file_utils.h"
#include "media_log.h"
#include "preferences.h"
#include "preferences_helper.h"

namespace OHOS {
namespace Media {

using namespace std;

DfxCollector::DfxCollector()
{
}

DfxCollector::~DfxCollector()
{
}

void DfxCollector::CollectThumbnailError(const std::string &path, const std::string method, int32_t errorCode)
{
    lock_guard<mutex> lock(thumbnailErrorLock_);
    ThumbnailErrorInfo thunmbailErrorInfo = { method, errorCode, MediaFileUtils::UTCTimeSeconds() };
    thumbnailErrorMap_[path] = thunmbailErrorInfo;
}

std::unordered_map<std::string, ThumbnailErrorInfo> DfxCollector::GetThumbnailError()
{
    lock_guard<mutex> lock(thumbnailErrorLock_);
    std::unordered_map<std::string, ThumbnailErrorInfo> result = thumbnailErrorMap_;
    thumbnailErrorMap_.clear();
    return result;
}
} // namespace Media
} // namespace OHOS