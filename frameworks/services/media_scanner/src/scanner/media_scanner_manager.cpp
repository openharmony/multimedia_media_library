/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "media_scanner_manager.h"

#include "media_log.h"

namespace OHOS {
namespace Media {
std::shared_ptr<MediaScannerManager> MediaScannerManager::instance_ = nullptr;
std::mutex MediaScannerManager::instanceMutex_;

shared_ptr<MediaScannerManager> MediaScannerManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> guard(instanceMutex_);
        instance_ = shared_ptr<MediaScannerManager>(new MediaScannerManager());
    }

    return instance_;
}

int32_t MediaScannerManager::ScanFile(std::string &path, const sptr<IRemoteObject> &callback)
{
    MEDIA_INFO_LOG("ScanFile begin");

    if (path.empty()) {
        MEDIA_ERR_LOG("path is empty");
        return ERR_EMPTY_ARGS;
    }

    if (ScannerUtils::GetRealPath(path) != ERR_SUCCESS) {
        MEDIA_ERR_LOG("invalid path %{private}s", path.c_str());
        return ERR_INCORRECT_PATH;
    }

    if (ScannerUtils::IsDirectory(path)) {
        MEDIA_ERR_LOG("path %{private}s is a dir", path.c_str());
        return ERR_INCORRECT_PATH;
    }

    std::unique_ptr<MediaScannerObj> scanner = std::make_unique<MediaScannerObj>(path, callback, false);
    executor_.Commit(move(scanner));

    return 0;
}

int32_t MediaScannerManager::ScanDir(std::string &path, const sptr<IRemoteObject> &callback)
{
    MEDIA_INFO_LOG("begin");

    if (path.empty()) {
        MEDIA_ERR_LOG("path is empty");
        return ERR_EMPTY_ARGS;
    }

    if (ScannerUtils::GetRealPath(path) != ERR_SUCCESS) {
        MEDIA_ERR_LOG("invalid path %{private}s", path.c_str());
        return ERR_INCORRECT_PATH;
    }

    if (!ScannerUtils::IsDirectory(path)) {
        MEDIA_ERR_LOG("path %{private}s isn't a dir", path.c_str());
        return ERR_INCORRECT_PATH;
    }

    std::unique_ptr<MediaScannerObj> scanner = std::make_unique<MediaScannerObj>(path, callback, true);
    executor_.Commit(move(scanner));

    return 0;
}
} // namespace Media
} // namespace OHOS