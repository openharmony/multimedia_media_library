/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_JS_INCLUDE_CLONE_TO_ALBUM_CALLBACK_NAPI_H
#define INTERFACES_KITS_JS_INCLUDE_CLONE_TO_ALBUM_CALLBACK_NAPI_H

#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <chrono>
#include <condition_variable>

#include "clone_to_album_callback_stub.h"

#include "napi/native_api.h"

namespace OHOS {
namespace Media {

enum CopyResult {
    PENDING = 0,
    SUCCESS = 1,
    FAILED = 2,
    CANCELLED = 3,
};

class CloneToAlbumCallbackNapi : public CloneToAlbumCallbackStub {
public:
    CloneToAlbumCallbackNapi(napi_env env, napi_ref sizeProgressListener,
        napi_ref countProgressListener, napi_ref resultListener);
    virtual ~CloneToAlbumCallbackNapi();

    int32_t OnProgress(uint64_t processedSize, uint64_t totalSize,
        uint32_t processedCount, uint32_t totalCount) override;
    int32_t OnComplete(int32_t errorCode, const std::vector<std::string> &successUris,
        std::shared_ptr<DataShare::DataShareResultSet> &resultSet) override;
    void SetCancelled(int32_t requestId);
    int WaitForCloneResult();
    int GetErrorCode() const { return errorCode_; }
    std::vector<std::string> GetSuccessUris() const { return successUris_; }
    std::shared_ptr<DataShare::DataShareResultSet> GetResultSet() const { return resultSet_; }
private:
    void TriggerSizeProgressCallback(uint64_t processedSize, uint64_t totalSize);
    void TriggerCountProgressCallback(uint32_t processedCount, uint32_t totalCount);
    void TriggerResultListenerCallback(int32_t code, const std::vector<std::string> &resultUris);

    napi_env env_;
    napi_ref sizeProgressListener_;
    napi_ref countProgressListener_;
    napi_ref resultListener_;
    std::atomic<bool> cancelled_{false};
    std::atomic<uint32_t> taskSize_{0};
    
    std::mutex callbackMutex_;
    
    std::mutex cvMutex_;
    std::condition_variable cv_;
    int32_t errorCode_ {0};
    bool isCompleted_ {false};
    std::vector<std::string> successUris_ {};
    std::shared_ptr<DataShare::DataShareResultSet> resultSet_ = nullptr;
    std::chrono::steady_clock::time_point lastHeartbeatTime_;
};

} // namespace Media
} // namespace OHOS

#endif // INTERFACES_KITS_JS_INCLUDE_CLONE_TO_ALBUM_CALLBACK_NAPI_H
