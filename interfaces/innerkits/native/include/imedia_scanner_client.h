/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
    SCAN_EMPTY_ARGS,
    SCAN_NOT_ACCESSIBLE,
    SCAN_INCORRECT_PATH,
    SCAN_MEM_ALLOC_FAIL,
    SCAN_MIMETYPE_NOTSUPPORT,
    SCAN_SCAN_NOT_INIT,
    SCAN_SERVICE_NOT_READY,
    SCAN_INV_CB_ERR
};

class IMediaScannerAppCallback {
public:
    virtual ~IMediaScannerAppCallback() = default;

    /**
     * @brief OnScanFinished will be executed when client receives callback from service after scan is finished/error
     *
     * @param status scan result
     * @param uri file uri generated after database updation. For scanDir(), uri will be empty
     * @param path The path which was requested for scanning
     */
    virtual void OnScanFinished(const int32_t status, const std::string &uri, const std::string &path) = 0;
};

class IMediaScannerClient {
public:
    virtual ~IMediaScannerClient() = default;

    /**
     * @brief Helps to release the current client instance from scanner service ability.
     *
     */
    virtual void Release() = 0;

    /**
     * @brief This API will help to scan the specified directory and updates the metadata to database
     *
     * @param scanDirPath Valid path to a directory {/storage/media/local/files}
     * @param appCb Callback object to be passed along with request
     * @return int32_t Returns the request ID of scanDir
     */
    virtual ScanState ScanDir(std::string &scanDirPath, const std::shared_ptr<IMediaScannerAppCallback> &appCb) = 0;

    /**
     * @brief This API will help to scan the specified file and updates the metadata to database
     *
     * @param scanFilePath Valid path to a file along with filename{/storage/media/local/files/sample.mp3}
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
