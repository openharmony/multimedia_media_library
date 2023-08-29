/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_ThUMBNAIL_MANAGER_H
#define INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_ThUMBNAIL_MANAGER_H

#include <condition_variable>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "napi/native_api.h"
#include "nocopyable.h"
#include "safe_map.h"
#include "safe_queue.h"
#include "pixel_map.h"

using RequestSharedPtr = std::shared_ptr<ThumbnailRequest>;

enum class ThumbnailStatus {
    THUMB_INITIAL,
    THUMB_FAST,
    THUMB_QUALITY,
    THUMB_REMOVE,
};

class ThumbnailCallback {
public:
    ThumbnailCallback(napi_env env, napi_ref callback) : env_(env), callBackRef_(callback)
    { }
    virtual ~ThumbnailCallback() = default;
    napi_env env_;
    napi_ref callBackRef_;
};

class ThumnailUv {
public:
    ThumnailUv(RequestSharedPtr &request) : request_(request)
    { }
    RequestSharedPtr request_;
};

class ThumbnailRequest {
public:
    explict ThumbnailRequest(const std::string &uri, const Size &size, napi_env env, napi_ref callback);
    virtual ~ThumbnailRequest() = default;
    bool UpdateStatus(ThumbnailStatus status);
    ThumbnailStatus GetStatus();
    bool NeedContinue();

private:
    ThumbnailStatus status_;
    std::mutex mtx_;
    ThumbnailCallback callback_;
    Size requestSize_;
    std::shared_ptr<PixelMap> fastPixelmap;
    std::shared_ptr<PixelMap> QualityPixelmap;
    string uri_;
};

class ThumbnailManager : NoCopyable {
public:
    virtual ~ThumbnailManager();
    static std::shared_ptr<ThumbnailManager> GetInstance();

    bool Init();
    std::string AddPhotoRequest(const std::string &uri, const Size &size, napi_env env, napi_ref callback);
    void RemovePhotoRequest(const std::string &requestId);
    static std::unique_ptr<PixelMap> ThumbnailManager::QueryThumbnail(const std::string &uri, const Size &size,
        const string &path)
private:
    constexpr int THREAD_NUM = 4;
    ThumbnailManager() = default;
    static void FastImageWorker(int num);
    static void QualityImageWorker(int num);
    void AddFastPhotoRequest(RequestSharedPtr &request);
    void AddQualityPhotoRequest(RequestSharedPtr &request);
    void NotifyImage(RequestSharedPtr &request);

    SafeMap<std::string, RequestSharedPtr> thumbRequest_;
    SafeQueue<RequestSharedPtr> fastQueue_;
    SafeQueue<RequestSharedPtr> qualityQueue_;

    std::list<std::thread> qualityThreads_;
    std::thread fastThread_;
    std::mutex fastLock_;
    std::condition_variable fastCv_;
    std::mutex qualityLock_;
    std::condition_variable qualityCv_;

    static std::shared_ptr<ThumbnailManager> instance_;
    static std::mutex mutex_;
    static bool init_ = false;
    std::atomic<bool> isThreadRunning_;
};

#endif // INTERFACES_KITS_JS_MEDIALIBRARY_INCLUDE_ThUMBNAIL_MANAGER_H-=

