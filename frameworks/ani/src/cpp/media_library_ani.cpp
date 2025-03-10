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

#define MLOG_TAG "MediaLibraryAni"
#include "media_library_ani.h"
#include "medialibrary_ani_log.h"
#include "medialibrary_ani_utils.h"

using namespace std;
namespace OHOS {
namespace Media {

static SafeMap<int32_t, std::shared_ptr<ThumbnailBatchGenerateObserver>> thumbnailGenerateObserverMap;
static SafeMap<int32_t, std::shared_ptr<ThumbnailGenerateHandler>> thumbnailGenerateHandlerMap;

static void UnregisterThumbnailGenerateObserver(int32_t requestId)
{
    std::shared_ptr<ThumbnailBatchGenerateObserver> dataObserver;
    if (!thumbnailGenerateObserverMap.Find(requestId, dataObserver)) {
        ANI_DEBUG_LOG("UnregisterThumbnailGenerateObserver with RequestId: %{public}d not exist in observer map",
            requestId);
        return;
    }

    const std::string PHOTO_URI_PREFIX = "file://media/Photo/";
    std::string observerUri = PHOTO_URI_PREFIX + std::to_string(requestId);
    UserFileClient::UnregisterObserverExt(Uri(observerUri), dataObserver);
    thumbnailGenerateObserverMap.Erase(requestId);
}

static void DeleteThumbnailHandler(int32_t requestId)
{
    std::shared_ptr<ThumbnailGenerateHandler> dataHandler;
    if (!thumbnailGenerateHandlerMap.Find(requestId, dataHandler)) {
        ANI_DEBUG_LOG("DeleteThumbnailHandler with RequestId: %{public}d not exist in handler map", requestId);
        return;
    }
    thumbnailGenerateHandlerMap.Erase(requestId);
}

static void ReleaseThumbnailTask(int32_t requestId)
{
    UnregisterThumbnailGenerateObserver(requestId);
    DeleteThumbnailHandler(requestId);
}

void MediaLibraryAni::PhotoAccessStopCreateThumbnailTask([[maybe_unused]] ani_env *env,
    [[maybe_unused]] ani_object object, ani_int taskId)
{
    ANI_DEBUG_LOG("PhotoAccessStopCreateThumbnailTask with taskId: %{public}d", taskId);
    std::unique_ptr<MediaLibraryAsyncContext> asyncContext = std::make_unique<MediaLibraryAsyncContext>();

    int32_t requestId = taskId;
    if (requestId <= 0) {
        ANI_ERR_LOG("PhotoAccessStopCreateThumbnailTask with Invalid requestId: %{public}d", requestId);
        return;
    }

    ReleaseThumbnailTask(requestId);

    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(THUMBNAIL_BATCH_GENERATE_REQUEST_ID, requestId);
    string updateUri = PAH_STOP_GENERATE_THUMBNAILS;
    MediaLibraryAniUtils::UriAppendKeyValue(updateUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));
    Uri uri(updateUri);
    int changedRows = UserFileClient::Update(uri, asyncContext->predicates, valuesBucket);
    if (changedRows < 0) {
        asyncContext->SaveError(changedRows);
        ANI_ERR_LOG("Stop create thumbnail task, update failed, err: %{public}d", changedRows);
    }
    ANI_DEBUG_LOG("MediaLibraryAni::PhotoAccessStopCreateThumbnailTask Finished");
}


} // namespace Media
} // namespace OHOS
