/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#include "medialibrary_album_refresh.h"

#include "cpu_utils.h"
#include "media_file_utils.h"
#include "medialibrary_notify.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_rdbstore.h"
#include "photo_album_column.h"

using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS::Media {
static void NotifyAnalysisAlbum(PhotoAlbumSubType subtype, int32_t albumId)
{
    const static set<PhotoAlbumSubType> NEED_FLUSH_ANALYSIS_ALBUM = {
        PhotoAlbumSubType::SHOOTING_MODE,
    };
    if (NEED_FLUSH_ANALYSIS_ALBUM.find(subtype) != NEED_FLUSH_ANALYSIS_ALBUM.end()) {
        auto watch = MediaLibraryNotify::GetInstance();
        if (watch == nullptr) {
            MEDIA_ERR_LOG("Can not get MediaLibraryNotify Instance");
            return;
        }
        if (albumId > 0) {
            watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX,
                std::to_string(albumId)), NotifyType::NOTIFY_ADD);
        } else {
            watch->Notify(PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX, NotifyType::NOTIFY_ADD);
        }
    }
}

static void NotifySystemAlbumFunc(PhotoAlbumType albumtype, PhotoAlbumSubType subtype, int32_t albumId)
{
    if (albumtype == PhotoAlbumType::SMART) {
        NotifyAnalysisAlbum(subtype, albumId);
        return;
    }
    const static set<PhotoAlbumSubType> NEED_FLUSH_PHOTO_ALBUM = {
        PhotoAlbumSubType::IMAGE,
        PhotoAlbumSubType::VIDEO,
        PhotoAlbumSubType::USER_GENERIC,
        PhotoAlbumSubType::SOURCE_GENERIC,
    };
    if (NEED_FLUSH_PHOTO_ALBUM.find(subtype) != NEED_FLUSH_PHOTO_ALBUM.end()) {
        auto watch = MediaLibraryNotify::GetInstance();
        if (watch == nullptr) {
            MEDIA_ERR_LOG("Can not get MediaLibraryNotify Instance");
            return;
        }
        if (albumId > 0) {
            watch->Notify(MediaFileUtils::GetUriByExtrConditions(PhotoAlbumColumns::ALBUM_URI_PREFIX,
                std::to_string(albumId)), NotifyType::NOTIFY_ADD);
        } else {
            watch->Notify(PhotoAlbumColumns::ALBUM_URI_PREFIX, NotifyType::NOTIFY_ADD);
        }
    }
}

static void RefreshCallbackFunc()
{
    auto watch = MediaLibraryNotify::GetInstance();
    if (watch == nullptr) {
        MEDIA_ERR_LOG("Can not get MediaLibraryNotify Instance");
        return;
    }
    watch->Notify(PhotoAlbumColumns::ALBUM_URI_PREFIX, NotifyType::NOTIFY_ADD);
    watch->Notify(PhotoAlbumColumns::ANALYSIS_ALBUM_URI_PREFIX, NotifyType::NOTIFY_ADD);
}

static void RefreshAlbumAsyncTask(AsyncTaskData *data)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Medialibrary rdbStore is nullptr!");
        return;
    }

    int32_t ret = MediaLibraryRdbUtils::RefreshAllAlbums(rdbStore,
        NotifySystemAlbumFunc, RefreshCallbackFunc);
    if (ret != E_OK) {
        MEDIA_ERR_LOG("RefreshAllAlbums failed ret:%{public}d", ret);
    }
}

void RefreshAlbums(bool forceRefresh)
{
    if (MediaLibraryRdbUtils::IsNeedRefreshAlbum() && (forceRefresh || !MediaLibraryRdbUtils::IsInRefreshTask())) {
        shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
        if (asyncWorker == nullptr) {
            MEDIA_ERR_LOG("Can not get asyncWorker");
            return;
        }

        asyncWorker->ClearRefreshTaskQueue();
        shared_ptr<MediaLibraryAsyncTask> notifyAsyncTask = make_shared<MediaLibraryAsyncTask>(
            RefreshAlbumAsyncTask, nullptr, REFRESH_ALBUM);
        if (notifyAsyncTask != nullptr) {
            asyncWorker->AddTask(notifyAsyncTask, true);
        } else {
            MEDIA_ERR_LOG("Start UpdateAlbumsAndSendNotifyInTrash failed");
        }
    }
}
} // namespace OHOS::Media
