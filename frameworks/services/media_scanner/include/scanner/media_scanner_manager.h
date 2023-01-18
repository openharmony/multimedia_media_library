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

#ifndef MEDIA_SCANNER_MANAGER_H
#define MEDIA_SCANNER_MANAGER_H

#include <memory>

#include "media_scanner.h"
#include "media_scan_executor.h"

namespace OHOS {
namespace Media {
class MediaScannerManager final {
public:
    static std::shared_ptr<MediaScannerManager> GetInstance();

    virtual ~MediaScannerManager() = default;

    std::string ScanCheck(const std::string &path, bool isDir);
    int32_t ScanFile(const std::string &path, const std::shared_ptr<IMediaScannerCallback> &callback);
    int32_t ScanFileSync(const std::string &path, const std::shared_ptr<IMediaScannerCallback> &callback);
    int32_t ScanDir(const std::string &path, const std::shared_ptr<IMediaScannerCallback> &callback);

    int32_t Start();
    int32_t Stop();

private:
    MediaScannerManager() = default;

    static std::shared_ptr<MediaScannerManager> instance_;
    static std::mutex instanceMutex_;

    MediaScanExecutor executor_;
};
} // namespace Media
} // namespace OHOS

#endif // MEDIA_SCANNER_MANAGER_H