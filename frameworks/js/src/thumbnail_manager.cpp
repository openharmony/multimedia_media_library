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

#include "thumbnail_manager.h"

#include <memory>
#include <mutex>
#include <sys/stat.h>
#include <uuid/uuid.h>

#include "image_source.h"
#include "js_native_api.h"
#include "media_file_uri.h"
#include "medialibrary_errno.h"
#include "medialibrary_napi_log.h"
#include "medialibrary_napi_utils.h"
#include "medialibrary_tracer.h"
#include "pixel_map_napi.h"
#include "post_proc.h"
#include "string_ex.h"
#include "thumbnail_const.h"
#include "unique_fd.h"
#include "uv.h"
#include "userfile_client.h"

using namespace std;
#define UUID_STR_LENGTH 37

namespace OHOS {
namespace Media {
shared_ptr<ThumbnailManager> ThumbnailManager::instance_ = nullptr;
mutex ThumbnailManager::mutex_;
bool ThumbnailManager::init_ = false;

ThumbnailRequest::ThumbnailRequest(const string &uri, const string &path, const Size &size,
    napi_env env, napi_ref callback) : callback_(env, callback), uri_(uri),
    path_(path), requestSize_(size)
{
}

bool ThumbnailRequest::UpdateStatus(ThumbnailStatus status)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (status <= status_) {
        return false;
    }
    status_ = status;
    return true;
}

ThumbnailStatus ThumbnailRequest::GetStatus()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return status_;
}

bool ThumbnailRequest::NeedContinue()
{
    return GetStatus() < ThumbnailStatus::THUMB_REMOVE;
}

static bool IsPhotoNeedFastThumb(const Size &size)
{
    return (size.width >= DEFAULT_THUMB_SIZE || size.height >= DEFAULT_THUMB_SIZE);
}

bool ThumbnailRequest::NeedQualityPhoto()
{
    return IsPhotoNeedFastThumb(requestSize_);
}

static string GenerateRequestId()
{
    uuid_t uuid;
    uuid_generate(uuid);
    char str[UUID_STR_LENGTH] = {};
    uuid_unparse(uuid, str);
    return str;
}

shared_ptr<ThumbnailManager> ThumbnailManager::GetInstance()
{
    if (instance_ == nullptr) {
        lock_guard<mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = shared_ptr<ThumbnailManager>(new ThumbnailManager());
        }
    }

    return instance_;
}

void ThumbnailManager::Init()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (init_) {
        return;
    }
    init_ = true;
    isThreadRunning_ = true;
    fastThread_ = thread(bind(&ThumbnailManager::FastImageWorker, this, 0));
    fastThread_.detach();
    for (auto i = 0; i < THREAD_NUM; i++) {
        threads_.emplace_back(bind(&ThumbnailManager::QualityImageWorker, this, i));
        threads_[i].detach();
    }
    return;
}

string ThumbnailManager::AddPhotoRequest(const string &uri, const string &path, const Size &size,
    napi_env env, napi_ref callback)
{
    shared_ptr<ThumbnailRequest> request = make_shared<ThumbnailRequest>(uri, path, size, env, callback);
    string requestId = GenerateRequestId();
    if (!thumbRequest_.Insert(requestId, request)) {
        return "";
    }
    // judge from request option
    if (IsPhotoNeedFastThumb(size)) {
        AddFastPhotoRequest(request);
    } else {
        AddQualityPhotoRequest(request);
    }
    return requestId;
}

void ThumbnailManager::RemovePhotoRequest(const string &requestId)
{
    RequestSharedPtr ptr;
    if (thumbRequest_.Find(requestId, ptr)) {
        if (ptr == nullptr) {
            return;
        }
        // do not need delete from queue, just update remove status.
        lock_guard<mutex> deleteLock(ptr->quitMutex_);
        ptr->UpdateStatus(ThumbnailStatus::THUMB_REMOVE);
        napi_delete_reference(ptr->callback_.env_, ptr->callback_.callBackRef_);
    }
    thumbRequest_.Erase(requestId);
}

ThumbnailManager::~ThumbnailManager()
{
    isThreadRunning_ = false;
    fastCv_.notify_all();
    qualityCv_.notify_all();
    if (fastThread_.joinable()) {
        fastThread_.join();
    }
    for (auto &thread : qualityThreads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

void SetThreadName(const string &threadName, int num)
{
    string name = threadName;
    name.append(to_string(num));
    pthread_setname_np(pthread_self(), name.c_str());
}

void ThumbnailManager::AddFastPhotoRequest(const RequestSharedPtr &request)
{
    request->UpdateStatus(ThumbnailStatus::THUMB_FAST);
    fastQueue_.Push(request);
    fastCv_.notify_one();
}

void ThumbnailManager::AddQualityPhotoRequest(const RequestSharedPtr &request)
{
    request->UpdateStatus(ThumbnailStatus::THUMB_QUALITY);
    qualityQueue_.Push(request);
    qualityCv_.notify_one();
}

static inline void GetFastThumbNewSize(const Size &size, Size &newSize)
{
    if (size.width > DEFAULT_THUMB_SIZE || size.height > DEFAULT_THUMB_SIZE) {
        newSize.height = DEFAULT_THUMB_SIZE;
        newSize.width = DEFAULT_THUMB_SIZE;
    } else if (size.width > DEFAULT_MTH_SIZE || size.height > DEFAULT_MTH_SIZE) {
        newSize.height = DEFAULT_MTH_SIZE;
        newSize.width = DEFAULT_MTH_SIZE;
    } else if (size.width > DEFAULT_YEAR_SIZE || size.height > DEFAULT_YEAR_SIZE) {
        newSize.height = DEFAULT_YEAR_SIZE;
        newSize.width = DEFAULT_YEAR_SIZE;
    } else {
        // Size is small enough, do not need to smaller
        return;
    }
}

static int OpenThumbnail(const string &path, ThumbnailType type)
{
    if (!path.empty()) {
        string sandboxPath = GetSandboxPath(path, type);
        int fd = -1;
        if (!sandboxPath.empty()) {
            fd = open(sandboxPath.c_str(), O_RDONLY);
        }
        if (fd > 0) {
            return fd;
        }
    }
    return E_ERR;
}

static bool IfSizeEqualsRatio(const Size &imageSize, const Size &targetSize)
{
    if (imageSize.height == 0 || targetSize.height == 0) {
        return false;
    }

    return imageSize.width / imageSize.height == targetSize.width / targetSize.height;
}

static unique_ptr<PixelMap> DecodeThumbnail(UniqueFd& uniqueFd, const Size& size)
{
    MediaLibraryTracer tracer;
    tracer.Start("ImageSource::CreateImageSource");
    SourceOptions opts;
    uint32_t err = 0;
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(uniqueFd.Get(), opts, err);
    if (imageSource  == nullptr) {
        NAPI_ERR_LOG("CreateImageSource err %{public}d", err);
        return nullptr;
    }

    ImageInfo imageInfo;
    err = imageSource->GetImageInfo(0, imageInfo);
    if (err != E_OK) {
        NAPI_ERR_LOG("GetImageInfo err %{public}d", err);
        return nullptr;
    }

    bool isEqualsRatio = IfSizeEqualsRatio(imageInfo.size, size);
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = isEqualsRatio ? size : imageInfo.size;
    decodeOpts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, err);
    if (pixelMap == nullptr) {
        NAPI_ERR_LOG("CreatePixelMap err %{public}d", err);
        return nullptr;
    }
#ifdef IMAGE_PURGEABLE_PIXELMAP
    PurgeableBuilder::MakePixelMapToBePurgeable(pixelMap, uniqueFd.Get(), opts, decodeOpts);
#endif
    PostProc postProc;
    if (!isEqualsRatio && !postProc.CenterScale(size, *pixelMap)) {
        return nullptr;
    }
    return pixelMap;
}

static PixelMapPtr GetPixelMapWithoutDecode(UniqueFd &uniqueFd, const Size &size)
{
    struct stat statInfo;
    if (fstat(uniqueFd.Get(), &statInfo) == E_ERR) {
        return nullptr;
    }
    uint32_t *buffer = static_cast<uint32_t*>(malloc(statInfo.st_size));
    if (buffer == nullptr) {
        return nullptr;
    }
    read(uniqueFd.Get(), buffer, statInfo.st_size);
    InitializationOptions option;
    option.size = size;
    
    PixelMapPtr pixelMap = PixelMap::Create(buffer, statInfo.st_size, option);
    free(buffer);
    return pixelMap;
}

unique_ptr<PixelMap> ThumbnailManager::QueryThumbnail(const string &uriStr, const Size &size, const string &path)
{
    MediaLibraryTracer tracer;
    tracer.Start("QueryThumbnail uri:" + uriStr);
    tracer.Start("DataShare::OpenFile");
    ThumbnailType thumbType = GetThumbType(size.width, size.height);
    if (MediaFileUri::GetMediaTypeFromUri(uriStr) == MediaType::MEDIA_TYPE_AUDIO &&
        (thumbType == ThumbnailType::MTH || thumbType == ThumbnailType::YEAR)) {
        thumbType = ThumbnailType::THUMB;
    }
    UniqueFd uniqueFd(OpenThumbnail(path, thumbType));
    if (uniqueFd.Get() == E_ERR) {
        string openUriStr = uriStr + "?" + MEDIA_OPERN_KEYWORD + "=" + MEDIA_DATA_DB_THUMBNAIL + "&" +
            MEDIA_DATA_DB_WIDTH + "=" + to_string(size.width) + "&" + MEDIA_DATA_DB_HEIGHT + "=" +
            to_string(size.height);
        if (IsAsciiString(path)) {
            openUriStr += "&" + THUMBNAIL_PATH + "=" + path;
        }
        Uri openUri(openUriStr);
        uniqueFd = UniqueFd(UserFileClient::OpenFile(openUri, "R"));
    }
    if (uniqueFd.Get() < 0) {
        NAPI_ERR_LOG("queryThumb is null, errCode is %{public}d", uniqueFd.Get());
        return nullptr;
    }
    tracer.Finish();
    if (thumbType == ThumbnailType::MTH || thumbType == ThumbnailType::YEAR) {
        return GetPixelMapWithoutDecode(uniqueFd, size);
    } else {
        return DecodeThumbnail(uniqueFd, size);
    }
}

bool ThumbnailManager::RequestFastImage(const RequestSharedPtr &request)
{
    Size fastSize;
    GetFastThumbNewSize(request->GetRequestSize(), fastSize);
    UniqueFd uniqueFd(OpenThumbnail(request->GetPath(), GetThumbType(fastSize.width, fastSize.height)));
    if (uniqueFd.Get() < 0) {
        return false;
    }
    
    PixelMapPtr pixelMap = GetPixelMapWithoutDecode(uniqueFd, fastSize);
    request->SetPixelMap(move(pixelMap));
    return true;
}

void ThumbnailManager::DealWithFastRequest(const RequestSharedPtr &request)
{
    if (request == nullptr) {
        return;
    }
    if (!RequestFastImage(request)) {
        // when local pixelmap not exit, must add QualityThread
        AddQualityPhotoRequest(request);
        return;
    }
    // callback
    NotifyImage(request);
    if (!request->NeedContinue()) {
        return;
    }
    if (request->NeedQualityPhoto()) {
        AddQualityPhotoRequest(request);
    } else {
        napi_delete_reference(request->callback_.env_, request->callback_.callBackRef_);
    }
}

void ThumbnailManager::FastImageWorker(int num)
{
    SetThreadName("FastImageWorker", num);
    while (true) {
        if (!isThreadRunning_) {
            return;
        }
        if (fastQueue_.Empty()) {
            std::unique_lock<std::mutex> lock(fastLock_);
            fastCv_.wait(lock, [this]() {
                return !isThreadRunning_ || !fastQueue_.Empty();
            });
        } else {
            RequestSharedPtr request;
            if (fastQueue_.Pop(request) && request->NeedContinue()) {
                DealWithFastRequest(request);
            }
        }
    }
}

void ThumbnailManager::QualityImageWorker(int num)
{
    SetThreadName("QualityImageWorker", num);
    while (true) {
        if (!isThreadRunning_) {
            return;
        }
        if (qualityQueue_.Empty()) {
            std::unique_lock<std::mutex> lock(qualityLock_);
            qualityCv_.wait(lock, [this]() {
                return !isThreadRunning_ || !qualityQueue_.Empty();
            });
        } else {
            RequestSharedPtr request;
            if (qualityQueue_.Pop(request) && request->NeedContinue()) {
                // request quality image
                request->SetPixelMap(QueryThumbnail(request->GetUri(),
                    request->GetRequestSize(), request->GetPath()));
                // callback
                NotifyImage(request);
            }
        }
    }
}

static void UvJsExecute(uv_work_t *work)
{
    // js thread
    if (work == nullptr) {
        return;
    }

    ThumnailUv *uvMsg = reinterpret_cast<ThumnailUv *>(work->data);
    do {
        if (uvMsg == nullptr || uvMsg->request_ == nullptr) {
            break;
        }
        napi_env env = uvMsg->request_->callback_.env_;
        if (!uvMsg->request_->NeedContinue()) {
            break;
        }
        lock_guard<mutex> quitLock(uvMsg->request_->quitMutex_);
        napi_value jsCallback = nullptr;
        napi_status status = napi_get_reference_value(env, uvMsg->request_->callback_.callBackRef_,
            &jsCallback);
        if (status != napi_ok) {
            NAPI_ERR_LOG("Create reference fail, status: %{public}d", status);
            break;
        }
        napi_value retVal = nullptr;
        napi_value result[ARGS_ONE];
        result[PARAM0] = Media::PixelMapNapi::CreatePixelMap(env,
            shared_ptr<PixelMap>(uvMsg->request_->GetPixelMap()));
        if (uvMsg->request_->GetStatus() == ThumbnailStatus::THUMB_REMOVE) {
            napi_delete_reference(env, uvMsg->request_->callback_.callBackRef_);
        }
        if (result[PARAM0] == nullptr) {
            break;
        }
        napi_call_function(env, nullptr, jsCallback, ARGS_ONE, result, &retVal);
        if (status != napi_ok) {
            NAPI_ERR_LOG("CallJs napi_call_function fail, status: %{public}d", status);
            break;
        }
    } while (0);
    delete uvMsg;
    delete work;
}

void ThumbnailManager::NotifyImage(const RequestSharedPtr &request)
{
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(request->callback_.env_, &loop);
    if (loop == nullptr) {
        return;
    }

    uv_work_t *work = new (nothrow) uv_work_t;
    if (work == nullptr) {
        return;
    }

    ThumnailUv *msg = new (nothrow) ThumnailUv(request);
    if (msg == nullptr) {
        delete work;
        return;
    }

    work->data = reinterpret_cast<void *>(msg);
    int ret = uv_queue_work(loop, work, [](uv_work_t *w) {}, [](uv_work_t *w, int s) {
        UvJsExecute(w);
    });
    if (ret != 0) {
        NAPI_ERR_LOG("Failed to execute libuv work queue, ret: %{public}d", ret);
        delete msg;
        delete work;
    }
}
}
}
