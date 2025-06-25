/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_ANI_SRC_INCLUDE_THUMBNAIL_MANAGER_H
#define FRAMEWORKS_ANI_SRC_INCLUDE_THUMBNAIL_MANAGER_H

#include <memory>
#include <string>
#include <vector>
#include <utility>

#include "ani.h"
#include "safe_map.h"
#include "safe_queue.h"
#include "pixel_map.h"
#include "unique_fd.h"
#include "userfile_manager_types.h"

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))

class ThumbnailRequestAni;
class ThumbnailManagerAni;

using RequestSharedPtr = std::shared_ptr<ThumbnailRequestAni>;
using PixelMapPtr = std::unique_ptr<PixelMap>;

enum class ThumbnailStatus : int32_t {
    THUMB_INITIAL = 0,
    THUMB_FAST,
    THUMB_QUALITY,
    THUMB_REMOVE,
};

struct RequestPhotoParams {
    std::string uri;
    std::string path;
    Size size;
    RequestPhotoType type;
};

class ThumbnailCallback {
public:
    ThumbnailCallback(ani_env *env, ani_ref callback) : env_(env), callBackRef_(callback) {}
    virtual ~ThumbnailCallback() = default;
    ani_env *env_ = nullptr;
    ani_ref callBackRef_ = nullptr;
};

class ThumnailUv {
public:
    ThumnailUv(const RequestSharedPtr &request, ThumbnailManagerAni *manager) : request_(request),
        manager_(manager) {}
    RequestSharedPtr request_;
    ThumbnailManagerAni *manager_;
};

class ThumbnailRequestAni {
public:
    explicit ThumbnailRequestAni(const RequestPhotoParams &params, ani_env *env, ani_ref callback);
    virtual ~ThumbnailRequestAni();
    bool UpdateStatus(ThumbnailStatus status);
    void ReleaseCallbackRef();
    ThumbnailStatus GetStatus();
    bool NeedContinue();
    std::string GetUri() const
    {
        return uri_;
    }

    std::string GetPath() const
    {
        return path_;
    }

    Size GetRequestSize() const
    {
        return requestSize_;
    }

    PixelMapPtr GetPixelMap()
    {
        return std::move(pixelMap);
    }

    void SetPixelMap(PixelMapPtr ptr)
    {
        pixelMap = std::move(ptr);
    }

    PixelMapPtr GetFastPixelMap()
    {
        return std::move(fastPixelMap);
    }

    void SetFastPixelMap(PixelMapPtr ptr)
    {
        fastPixelMap = std::move(ptr);
    }

    void SetUUID(const std::string &uuid)
    {
        uuid_ = uuid;
    }

    std::string GetUUID() const
    {
        return uuid_;
    }

    void SetFd(int32_t fd)
    {
        fd_ = UniqueFd(fd);
    }

    const UniqueFd &GetFd() const
    {
        return fd_;
    }

    ThumbnailCallback callback_;
    RequestPhotoType requestPhotoType;
    int32_t error = 0;
private:
    std::string uri_;
    std::string path_;
    Size requestSize_;
    ThumbnailStatus status_ = ThumbnailStatus::THUMB_INITIAL;
    std::mutex mutex_;
    std::string uuid_;
    UniqueFd fd_;

    PixelMapPtr fastPixelMap;
    PixelMapPtr pixelMap;
};

class MMapFdPtr {
public:
    explicit MMapFdPtr(int32_t fd, bool isNeedRelease);
    ~MMapFdPtr();
    void* GetFdPtr();
    off_t GetFdSize();
    bool IsValid();
private:
    void* fdPtr_ = nullptr;
    off_t size_ = 0;
    bool isValid_ = false;
    bool isNeedRelease_ = false;
};

constexpr int THREAD_NUM = 5;
class ThumbnailManagerAni : NoCopyable {
public:
    ThumbnailManagerAni() = default;
    virtual ~ThumbnailManagerAni();
    static std::shared_ptr<ThumbnailManagerAni> GetInstance();
    void Init();
    std::string AddPhotoRequest(const RequestPhotoParams &params, ani_env *env, ani_ref callback);
    void RemovePhotoRequest(const std::string &requestId);
    EXPORT static std::unique_ptr<PixelMap> QueryThumbnail(const std::string &uriStr,
        const Size &size, const std::string &path);
    EXPORT static ani_object QueryThumbnailData(ani_env *env, const std::string &uriStr, const int &type,
        const std::string &path);
    EXPORT static std::unique_ptr<PixelMap> QueryKeyFrameThumbnail(const std::string &uriStr, const int &beginStamp,
        const int &type, const std::string &path);
    void DeleteRequestIdFromMap(const std::string &requestId);
    void AddQualityPhotoRequest(const RequestSharedPtr &request);
private:
    void DealWithFastRequest(const RequestSharedPtr &request);
    void DealWithQualityRequest(const RequestSharedPtr &request);

    void ImageWorker(int num);
    void AddFastPhotoRequest(const RequestSharedPtr &request);
    static void ExecuteThreadWork(ani_env* env, ThumnailUv* msg);
    void NotifyImage(const RequestSharedPtr &request);
    bool RequestFastImage(const RequestSharedPtr &request);

    SafeMap<std::string, RequestSharedPtr> thumbRequest_;
    SafeQueue<RequestSharedPtr> fastQueue_;
    SafeQueue<RequestSharedPtr> qualityQueue_;

    std::mutex queueLock_;
    std::condition_variable queueCv_;
    std::vector<std::thread> threads_;

    static std::shared_ptr<ThumbnailManagerAni> instance_;
    static std::mutex mutex_;
    static bool init_;
    std::atomic<bool> isThreadRunning_;
};
} // namespace Media
} // namespace OHOS
#endif // FRAMEWORKS_ANI_SRC_INCLUDE_THUMBNAIL_MANAGER_H
