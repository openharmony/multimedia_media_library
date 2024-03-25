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

void DfxCollector::CollectThumbnailError(const std::string &path, int32_t method, int32_t errorCode)
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

void DfxCollector::AddCommonBahavior(string bundleName, int32_t type)
{
    lock_guard<mutex> lock(commonBehaviorLock_);
    if (commonBehaviorMap_.count(bundleName) == 0) {
        CommonBehavior commonBehavior = { 0 };
        commonBehaviorMap_[bundleName] = commonBehavior;
    }
    commonBehaviorMap_[bundleName].times++;
}

std::unordered_map<string, CommonBehavior> DfxCollector::GetCommonBehavior()
{
    lock_guard<mutex> lock(commonBehaviorLock_);
    std::unordered_map<string, CommonBehavior> result = commonBehaviorMap_;
    commonBehaviorMap_.clear();
    return result;
}

void DfxCollector::CollectDeleteBehavior(std::string bundleName, int32_t type, int32_t size)
{
    if (type == DfxType::TRASH_PHOTO) {
        lock_guard<mutex> lock(deleteToTrashLock_);
        if (deleteToTrashMap_.count(bundleName) == 0) {
            deleteToTrashMap_[bundleName] = 0;
        }
        deleteToTrashMap_[bundleName]++;
    } else if (type == DfxType::ALBUM_DELETE_ASSETS) {
        lock_guard<mutex> lock(deleteFromDiskLock_);
        if (deleteFromDiskMap_.count(bundleName) == 0) {
            deleteFromDiskMap_[bundleName] = 0;
        }
        deleteFromDiskMap_[bundleName]++;
    } else if (type == DfxType::ALBUM_REMOVE_PHOTOS) {
        lock_guard<mutex> lock(removeLock_);
        if (removeMap_.count(bundleName) == 0) {
            removeMap_[bundleName] = 0;
        }
        removeMap_[bundleName]++;
    }
}

std::unordered_map<std::string, int32_t> DfxCollector::GetDeleteBehavior(int32_t type)
{
    std::unordered_map<std::string, int32_t> result;
    if (type == DfxType::TRASH_PHOTO) {
        lock_guard<mutex> lock(deleteToTrashLock_);
        result = deleteToTrashMap_;
        deleteToTrashMap_.clear();
    } else if (type == DfxType::ALBUM_DELETE_ASSETS) {
        lock_guard<mutex> lock(deleteFromDiskLock_);
        result = deleteFromDiskMap_;
        deleteFromDiskMap_.clear();
    } else if (type == DfxType::ALBUM_REMOVE_PHOTOS) {
        lock_guard<mutex> lock(removeLock_);
        result = removeMap_;
        removeMap_.clear();
    }
    return result;
}
} // namespace Media
} // namespace OHOS