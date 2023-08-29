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
#include <sys/stat.h>
#include <uuid/uuid.h>

#include "medialibrary_napi_log.h"
#include "medialibrary_napi_utils.h"
#include "thumbnail_const.h"
#include "uv.h"
#include "userfile_client.h"

using namespace std;
#define UUID_STR_LENGTH 37

shared_ptr<ThumbnailManager> ThumbnailManager::instance_ = nullptr;
mutex ThumbnailManager::mutex_;

ThumbnailRequest::ThumbnailRequest(const string &uri, const Size &size, napi_env env, napi_ref callback) : uri_(uri),
    requestSize_(size), callback_(env, callback)
{
}

bool ThumbnailRequest::UpdateStatus(ThumbnailStatus status)
{
    std::lock_guard<std::mutex> lock;
    if (status <= status_) {
        return false;
    }
    status_ = status;
    return true;
}

ThumbnailStatus ThumbnailRequest::GetStatus()
{
    std::lock_guard<std::mutex> lock;
    return status_;
}

bool ThumbnailRequest::NeedContinue()
{
    return GetStatus() < ThumbnailStatus::THUMB_REMOVE;
}

bool ThumbnailRequest::NeedQualityPhoto()
{
    return !IsThumbnail(requestSize_.width, requestSize_.height);
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
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = make_shared<ThumbnailManager>(new ThumbnailManager());
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
    fastThread_ = move(thread(bind(ThumbnailManager::FastImageWorker, this, 0)));
    fastThread_.detach();
    for (auto i = 0; i < THREAD_NUM; i++) {
        threads_.emplace_back(bind(&ThumbnailManager::QualityImageWorker, this, i));
    }
    init_ = true;
    isThreadRunning_ = true;
    return;
}

string ThumbnailManager::AddPhotoRequest(const string &uri, const Size &size, napi_env env, napi_ref callback)
{
    shared_ptr<ThumbnailRequest> request = make_shared<ThumbnailRequest>(uri, size, env, callback);
    // TODO callback;
    string requestId = GenerateRequestId();
    if (!thumbRequest_.Insert(requestId, request)) {
        return "";
    }
    // judge from request option
    if (!IsThumbnail(size.width, size.height)) {
        AddFastPhotoRequest(thumbRequest_);
    } else {
        AddQualityPhotoRequest(thumbRequest_);
    }
    return requestId;
}

void ThumbnailManager::RemovePhotoRequest(const string &requestId)
{
    RequestSharedPtr ptr;
    if (thumbRequest_.Find(requestId, ptr)) {
        // do not need delete from queue, just update remove status.
        ptr->UpdateStatus(ThumbnailStatus::THUMB_REMOVE);
    }
    thumbRequest_.Erase(requestId);
}

~ThumbnailManager::ThumbnailManager()
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

void ThumbnailManager::AddFastPhotoRequest(RequestSharedPtr &request)
{
    request->UpdateStatus(ThumbnailStatus::THUMB_FAST);
    fastQueue_.Push(request);
    fastCv_.notify_one();
}

void ThumbnailManager::AddQualityPhotoRequest(RequestSharedPtr &request)
{
    request->UpdateStatus(ThumbnailStatus::THUMB_QUALITY);
    qualityQueue_.Push(request);
    qualityCv_.notify_one();
}

static int OpenThumbnail(string &uriStr, const string &path, const Size &size)
{
    if (!path.empty()) {
        string sandboxPath = GetSandboxPath(path, GetThumbType(size.width, size.height));
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

unique_ptr<PixelMap> ThumbnailManager::QueryThumbnail(const string &uri, const Size &size, const string &path)
{
    MediaLibraryTracer tracer;
    tracer.Start("QueryThumbnail uri:" + uri);
    tracer.Start("DataShare::OpenFile");
    UniqueFd uniqueFd = OpenThumbnail(openUriStr, path, size);
    if (uniqueFd.Get() == E_ERR) {
        string openUriStr = uri + "?" + MEDIA_OPERN_KEYWORD + "=" + MEDIA_DATA_DB_THUMBNAIL + "&" + MEDIA_DATA_DB_WIDTH +
            "=" + to_string(size.width) + "&" + MEDIA_DATA_DB_HEIGHT + "=" + to_string(size.height);
        if (IsAsciiString(path)) {
            uriStr += "&" + THUMBNAIL_PATH + "=" + path;
        }
        Uri openUri(uriStr);
        uniqueFd = UserFileClient::OpenFile(openUri, "R")
    }
    if (uniqueFd.Get() < 0) {
        NAPI_ERR_LOG("queryThumb is null, errCode is %{public}d", uniqueFd.Get());
        return nullptr;
    }
    tracer.Finish();
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
        imageInfo.size = size;
    }

    bool isEqualsRatio = IfSizeEqualsRatio(imageInfo.size, size);
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = isEqualsRatio ? size : imageInfo.size;
    decodeOpts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, err);
#ifdef IMAGE_PURGEABLE_PIXELMAP
    PurgeableBuilder::MakePixelMapToBePurgeable(pixelMap, uniqueFd.Get(), opts, decodeOpts);
#endif
    PostProc postProc;
    if (!isEqualsRatio && !postProc.CenterScale(size, *pixelMap)) {
        return nullptr;
    }
    return pixelMap;
}

bool ThumbnailManager::RequestFastImage(RequestSharedPtr &request)
{
    // TODO need get downgrade size
    UniqueFd uniqueFd = OpenThumbnail(request->uri, path, request->size);
    if (uniqueFd.Get() < 0) {
        return false;
    }
    struct stat statInfo;
    if (fstat(uniqueFd.Get(), &statInfo) == E_ERR) {
        return false;
    }
    uint32_t *buffer = static_cast<uint32_t*>(malloc(statInfo.st_size)); // TODO maybe need free
    if (buffer == nullptr) {
        return false;
    }
    read(uniqueFd.Get(), buffer, statInfo.st_size);
    InitalizationOptions option;
    option.size = request->size;
    request->fastPixelmap = PixelMap::Create(buffer, statInfo.st_size, option);
    return true;
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
            fastCv_.wait(lock,
            [this]() { return !isThreadRunning_ || !fastQueue_.Empty(); });
        } else {
            RequestSharedPtr request;
            if (fastQueue_.Pop(request) && request->NeedContinue()) {
                // request fast image
                if (!request->RequestFastImage()) { // when local pixelmap not exit ,must add QualityThread
                    AddQualityPhotoRequest(request);
                    continue;
                }
                // callback
                NotifyImage(request);
                if (!request->NeedContinue()) {
                    continue;
                }
                if (NeedQualityPhoto()) {
                    AddQualityPhotoRequest(request);
                } else {
                    napi_delete_reference(request_->callback_.env_, request_->callback_.callBackRef_); // release 
                }
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
            qualityCv_.wait(lock,
            [this]() { return !isThreadRunning_ || !qualityQueue_.Empty(); });
        } else {
            RequestSharedPtr request;
            if (qualityQueue_.Pop(request) && request->NeedContinue()) {
                // request quality image
                request->qualityPixelmap = QueryThumbnail(uri, size, path);  // do not need path
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
        napi_ev env = uvMsg->request_->callback_.env_;
        napi_value jsCallback = nullptr;
        napi_status status = napi_get_reference_value(env, uvMsg->request_->callback_.callBackRef_, &jsCallback);
        if (status != napi_ok) {
            NAPI_ERR_LOG("Create reference fail, status: %{public}d", status);
            break;
        }
        napi_value retVal = nullptr;
        napi_value result[ARGS_ONE];
        result[PARAM0] = Media::PixelMapNapi::CreatePixelMap(env, uvMsg->request_->fastPixelmap); // TODO need get different pixelmap
        uvMsg->request_->fastPixelmap = nullptr; // release
        if (uvMsg->request_->GetStatus >= ThumbnailStatus::THUMB_QUALITY) { // release callback ref
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
    delete UvMsg;
    delete work;
}

void ThumbnailManager::NotifyImage(RequestSharedPtr &request)
{
    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(request->env_, &loop);
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