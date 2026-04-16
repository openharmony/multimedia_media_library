/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "HighPixelBundleInfoCache"

#include "highpixel_bundle_info_cache.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace {
const uint32_t CAPACITY_BUNDLE_INFO = 50;
}

void HighPixelBundleInfoCache::ClearBundleInfoInCache()
{
    std::lock_guard<std::mutex> lock(cacheMutex50_);
    bundleInfoMap50_.clear();
    bundleInfoList50_.clear();
    
    std::lock_guard<std::mutex> lock200(cacheMutex200_);
    bundleInfoMap200_.clear();
    bundleInfoList200_.clear();
}

bool HighPixelBundleInfoCache::GetBundleCacheInfo(const std::string &bundleName,
    bool &isSupport, HighPixelType pixelType)
{
    if (pixelType == HighPixelType::PIXEL_50) {
        std::lock_guard<std::mutex> lock(cacheMutex50_);
        auto it = bundleInfoMap50_.find(bundleName);
        if (it != bundleInfoMap50_.end() && it->second != bundleInfoList50_.end()) {
            isSupport = it->second->second;
            bundleInfoList50_.splice(bundleInfoList50_.begin(), bundleInfoList50_, it->second);
            return true;
        }
        return false;
    } else {
        std::lock_guard<std::mutex> lock(cacheMutex200_);
        auto it = bundleInfoMap200_.find(bundleName);
        if (it != bundleInfoMap200_.end() && it->second != bundleInfoList200_.end()) {
            isSupport = it->second->second;
            bundleInfoList200_.splice(bundleInfoList200_.begin(), bundleInfoList200_, it->second);
            return true;
        }
        return false;
    }
}

void HighPixelBundleInfoCache::InsertBundleCacheInfo(const std::string &bundleName,
    bool isSupport, HighPixelType pixelType)
{
    if (pixelType == HighPixelType::PIXEL_50) {
        std::lock_guard<std::mutex> lock(cacheMutex50_);
        bundleInfoList50_.push_front(std::make_pair(bundleName, isSupport));
        bundleInfoMap50_[bundleName] = bundleInfoList50_.begin();
        if (bundleInfoMap50_.size() > CAPACITY_BUNDLE_INFO) {
            auto eraseKey = bundleInfoList50_.back().first;
            bundleInfoMap50_.erase(eraseKey);
            bundleInfoList50_.pop_back();
            MEDIA_INFO_LOG("[cache] %{public}s is erased", eraseKey.c_str());
        }
    } else {
        std::lock_guard<std::mutex> lock(cacheMutex200_);
        bundleInfoList200_.push_front(std::make_pair(bundleName, isSupport));
        bundleInfoMap200_[bundleName] = bundleInfoList200_.begin();
        if (bundleInfoMap200_.size() > CAPACITY_BUNDLE_INFO) {
            auto eraseKey = bundleInfoList200_.back().first;
            bundleInfoMap200_.erase(eraseKey);
            bundleInfoList200_.pop_back();
            MEDIA_INFO_LOG("[cache] %{public}s is erased", eraseKey.c_str());
        }
    }
}
} // namespace Media
} // namespace OHOS