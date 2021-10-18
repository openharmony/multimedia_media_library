/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef IMEDIA_SCANNER_CLIENT_H
#define IMEDIA_SCANNER_CLIENT_H

#include <string>

namespace OHOS {
namespace Media {
/**
 * @brief Enumerates Scan operation states
 */
enum ScanState : int32_t {
    SCAN_ERROR = -1,
    SCAN_SUCCESS,
    SCAN_SERVICE_NOT_READY,
    SCAN_INV_CB_ERR,
    SCAN_NO_MEMORY_ERR
};

class IMediaScannerAppCallback {
public:
    virtual ~IMediaScannerAppCallback() = default;

    /**
     * OnScanFinished will be executed when client recieves callback from service
     * @param status Scan result code see {@link ScanState}
     * @param uri File uri
     * @param uri File path which was requested for scanning
     * @since 1.0
     * @version 1.0
     */
    virtual void OnScanFinished(const int32_t status, const std::string &uri, const std::string &path) = 0;
};

class IMediaScannerClient {
public:
    virtual ~IMediaScannerClient() = default;

    /**
     * @brief Helps to connect to scanner service ability. Use scanner instance to call this API
     *
     * @return int32_t
     */
    virtual void Release() = 0;

    /**
     * @brief This API will help to scan the specified directory and updates the metadata to database
     *
     * @param scanDirPath Valid path to a directory {/data/media}
     * @param appCb Callback object to be passed along with request
     * @return int32_t Returns the request ID of scanDir
     */
    virtual ScanState ScanDir(std::string &scanDirPath, const std::shared_ptr<IMediaScannerAppCallback> &appCb) = 0;

    /**
     * @brief This API will help to scan the specified file and updates the metadata to database
     *
     * @param scanFilePath Valid path to a file along with filename{/data/media/sample.mp3}
     * @param appCb Callback object to be passed along with request
     * @return int32_t Returns the request ID of scanFile
     */
    virtual ScanState ScanFile(std::string &scanFilePath, const std::shared_ptr<IMediaScannerAppCallback> &appCb) = 0;
};

class __attribute__((visibility("default"))) MediaScannerHelperFactory {
public:
    static std::shared_ptr<IMediaScannerClient> CreateScannerHelper();

private:
    MediaScannerHelperFactory() = default;
    ~MediaScannerHelperFactory() = default;
};
} // namespace Media
} // namespace OHOS
#endif // IMEDIA_SCANNER_CLIENT_H