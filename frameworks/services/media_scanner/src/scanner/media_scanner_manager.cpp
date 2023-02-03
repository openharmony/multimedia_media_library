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

#define MLOG_TAG "Scanner"

#include "media_scanner_manager.h"

#include "directory_ex.h"

#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_data_manager.h"

namespace OHOS {
namespace Media {
std::shared_ptr<MediaScannerManager> MediaScannerManager::instance_ = nullptr;
std::mutex MediaScannerManager::instanceMutex_;

std::shared_ptr<MediaScannerManager> MediaScannerManager::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> guard(instanceMutex_);

        if (instance_ != nullptr) {
            return instance_;
        }

        instance_ = std::shared_ptr<MediaScannerManager>(new (std::nothrow) MediaScannerManager());
    }

    return instance_;
}

string MediaScannerManager::ScanCheck(const std::string &path, bool isDir)
{
    if (path.empty()) {
        MEDIA_ERR_LOG("path is empty");
        return "";
    }

    string realPath;
    if (!PathToRealPath(path, realPath)) {
        MEDIA_ERR_LOG("failed to get real path %{private}s, errno %{public}d", path.c_str(), errno);
        return "";
    }

    if (isDir && !ScannerUtils::IsDirectory(realPath)) {
        MEDIA_ERR_LOG("path %{private}s isn't a dir", realPath.c_str());
        return "";
    }

    if (!isDir && ScannerUtils::IsDirectory(realPath)) {
        MEDIA_ERR_LOG("path %{private}s is a dir", realPath.c_str());
        return "";
    }

    return realPath;
}

int32_t MediaScannerManager::ScanFile(const std::string &path, const std::shared_ptr<IMediaScannerCallback> &callback)
{
    MEDIA_DEBUG_LOG("scan file %{private}s", path.c_str());

    string realPath = ScanCheck(path, false);
    if (realPath.empty()) {
        return E_INVALID_PATH;
    }

    std::unique_ptr<MediaScannerObj> scanner = std::make_unique<MediaScannerObj>(realPath, callback, false);
    executor_.Commit(move(scanner));

    return E_OK;
}

int32_t MediaScannerManager::ScanFileSync(const std::string &path,
    const std::shared_ptr<IMediaScannerCallback> &callback)
{
    MEDIA_DEBUG_LOG("scan file %{private}s", path.c_str());

    string realPath = ScanCheck(path, false);
    if (realPath.empty()) {
        return E_INVALID_PATH;
    }

    MediaScannerObj scanner = MediaScannerObj(realPath, callback, false);
    scanner.Scan();

    return E_OK;
}

int32_t MediaScannerManager::ScanDir(const std::string &path, const std::shared_ptr<IMediaScannerCallback> &callback)
{
    MEDIA_DEBUG_LOG("scan dir %{private}s", path.c_str());

    string realPath = ScanCheck(path, true);
    if (realPath.empty()) {
        return E_INVALID_PATH;
    }

    std::unique_ptr<MediaScannerObj> scanner = std::make_unique<MediaScannerObj>(realPath, callback, true);
    executor_.Commit(move(scanner));

    return E_OK;
}

int32_t MediaScannerManager::Start()
{
    executor_.Start();
    return ScanDir(ROOT_MEDIA_DIR, nullptr);
}

int32_t MediaScannerManager::Stop()
{
    executor_.Stop();
    return E_OK;
}
} // namespace Media
} // namespace OHOS