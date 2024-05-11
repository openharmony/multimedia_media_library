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
#define MLOG_TAG "Thumbnail"

#include "thumbnail_service.h"

#include "display_manager.h"
#include "ipc_skeleton.h"
#include "ithumbnail_helper.h"
#include "media_column.h"
#include "medialibrary_async_worker.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_kvstore_manager.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_type_const.h"
#include "media_log.h"
#include "result_set_utils.h"
#include "thumbnail_aging_helper.h"
#include "thumbnail_const.h"
#include "thumbnail_generate_helper.h"
#include "thumbnail_generate_worker_manager.h"
#include "thumbnail_uri_utils.h"
#include "post_event_utils.h"

using namespace std;
using namespace OHOS::DistributedKv;
using namespace OHOS::NativeRdb;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace Media {
std::shared_ptr<ThumbnailService> ThumbnailService::thumbnailServiceInstance_{nullptr};
std::mutex ThumbnailService::instanceLock_;
ThumbnailService::ThumbnailService(void)
{
    rdbStorePtr_ = nullptr;
#ifdef DISTRIBUTED
    kvStorePtr_ = nullptr;
#endif
}

shared_ptr<ThumbnailService> ThumbnailService::GetInstance()
{
    if (thumbnailServiceInstance_ == nullptr) {
        std::lock_guard<std::mutex> lockGuard(instanceLock_);
        if (thumbnailServiceInstance_ != nullptr) {
            return thumbnailServiceInstance_;
        }
        thumbnailServiceInstance_ = shared_ptr<ThumbnailService>(new ThumbnailService());
    }

    return thumbnailServiceInstance_;
}

static bool GetDefaultWindowSize(Size &size)
{
    auto &displayMgr = OHOS::Rosen::DisplayManager::GetInstance();
    auto display = displayMgr.GetDefaultDisplay();
    if (display == nullptr) {
        MEDIA_ERR_LOG("Get display window size failed");
        return false;
    }
    size.width = display->GetWidth();
    size.height = display->GetHeight();
    if (size.width <= 0) {
        MEDIA_WARN_LOG("Get Default display width is invalid %{public}d", size.width);
        size.width = DEFAULT_LCD_SIZE;
    }
    if (size.height <= 0) {
        MEDIA_WARN_LOG("Get Default display height is invalid %{public}d", size.height);
        size.height = DEFAULT_LCD_SIZE;
    }
    MEDIA_INFO_LOG("display window size::w %{public}d, h %{public}d", size.width, size.height);

    return true;
}

bool ThumbnailService::CheckSizeValid()
{
    if (!isScreenSizeInit_) {
        if (!GetDefaultWindowSize(screenSize_)) {
            return false;
        }
        isScreenSizeInit_ = true;
    }
    return true;
}

void ThumbnailService::Init(const shared_ptr<RdbStore> &rdbStore,
#ifdef DISTRIBUTED
    const shared_ptr<SingleKvStore> &kvStore,
#endif
    const shared_ptr<Context> &context)
{
    rdbStorePtr_ = rdbStore;
#ifdef DISTRIBUTED
    kvStorePtr_ = kvStore;
#endif
    context_ = context;

    if (!GetDefaultWindowSize(screenSize_)) {
        MEDIA_ERR_LOG("GetDefaultWindowSize failed");
    } else {
        isScreenSizeInit_ = true;
    }
}

void ThumbnailService::ReleaseService()
{
    StopAllWorker();
    rdbStorePtr_ = nullptr;
#ifdef DISTRIBUTED
    kvStorePtr_ = nullptr;
#endif
    context_ = nullptr;
    thumbnailServiceInstance_ = nullptr;
}

#ifdef MEDIALIBRARY_COMPATIBILITY
static int32_t GetPathFromDb(const shared_ptr<NativeRdb::RdbStore> &rdbStorePtr, const string &fileId,
    const string &table, string &path)
{
    if (rdbStorePtr == nullptr) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return E_HAS_DB_ERROR;
    }
    if (!all_of(fileId.begin(), fileId.end(), ::isdigit)) {
        return E_INVALID_FILEID;
    }
    string querySql = "SELECT " + MediaColumn::MEDIA_FILE_PATH + " FROM " + table +
        " WHERE " + MediaColumn::MEDIA_ID + "=?";
    vector<string> selectionArgs = { fileId };
    auto resultSet = rdbStorePtr->QuerySql(querySql, selectionArgs);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_HAS_DB_ERROR},
            {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
        return E_HAS_DB_ERROR;
    }
    path = GetStringVal(MediaColumn::MEDIA_FILE_PATH, resultSet);
    if (path.empty()) {
        return E_INVALID_PATH;
    }
    return E_OK;
}
#endif

int ThumbnailService::GetThumbFd(const string &path, const string &table, const string &id, const string &uri,
    const Size &size, bool isAstc)
{
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .path = path,
        .table = table,
        .row = id,
        .uri = uri,
    };
    ThumbnailType thumbType = GetThumbType(size.width, size.height, isAstc);
    if (thumbType != ThumbnailType::THUMB && thumbType != ThumbnailType::THUMB_ASTC) {
        opts.screenSize = screenSize_;
    }
    int fd = ThumbnailGenerateHelper::GetThumbnailPixelMap(opts, thumbType);
    if (fd < 0) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, fd},
            {KEY_OPT_FILE, uri}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        MEDIA_ERR_LOG("GetThumbnailPixelMap failed : %{public}d", fd);
    }
    return fd;
}

int ThumbnailService::GetThumbnailFd(const string &uri, bool isAstc)
{
    if (!CheckSizeValid()) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_THUMBNAIL_INVALID_SIZE},
            {KEY_OPT_FILE, uri}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return E_THUMBNAIL_INVALID_SIZE;
    }
    string id;
    string path;
    string table;
    Size size;
    if (!ThumbnailUriUtils::ParseThumbnailInfo(uri, id, size, path, table)) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_FAIL},
            {KEY_OPT_FILE, uri}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return E_FAIL;
    }
#ifdef MEDIALIBRARY_COMPATIBILITY
    if (path.empty()) {
        int32_t errCode = GetPathFromDb(rdbStorePtr_, id, table, path);
        if (errCode != E_OK) {
            VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, errCode},
                {KEY_OPT_TYPE, OptType::THUMB}};
            PostEventUtils::GetInstance().PostErrorProcess(ErrType::DB_OPT_ERR, map);
            MEDIA_ERR_LOG("GetPathFromDb failed, errCode = %{public}d", errCode);
            return errCode;
        }
    }
#endif
    return GetThumbFd(path, table, id, uri, size, isAstc);
}

int32_t ThumbnailService::ParseThumbnailParam(const std::string &uri, string &fileId, string &networkId,
    string &tableName)
{
    if (!CheckSizeValid()) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_THUMBNAIL_INVALID_SIZE},
            {KEY_OPT_FILE, uri}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return E_THUMBNAIL_INVALID_SIZE;
    }
    if (!ThumbnailUriUtils::ParseFileUri(uri, fileId, networkId, tableName)) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_ERR},
            {KEY_OPT_FILE, uri}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        MEDIA_ERR_LOG("ParseThumbnailInfo faild");
        return E_ERR;
    }
    return E_OK;
}

int32_t ThumbnailService::CreateThumbnail(const std::string &uri, const string &path, bool isSync)
{
    string fileId;
    string networkId;
    string tableName;

    int err = ParseThumbnailParam(uri, fileId, networkId, tableName);
    if (err != E_OK) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_ERR},
            {KEY_OPT_FILE, uri}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return err;
    }

    std::string dateAdded = ThumbnailUriUtils::GetDateAddedFromUri(uri);
    std::string fileUri = ThumbnailUriUtils::GetFileUriFromUri(uri);
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .path = path,
        .table = tableName,
        .row = fileId,
        .dateAdded = dateAdded,
        .fileUri = fileUri,
        .screenSize = screenSize_
    };

    err = ThumbnailGenerateHelper::CreateThumbnails(opts, isSync);
    if (err != E_OK) {
        MEDIA_ERR_LOG("CreateThumbnails failed : %{public}d", err);
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_FILE, uri}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return err;
    }
    return E_OK;
}

void ThumbnailService::InterruptBgworker()
{
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker != nullptr) {
        asyncWorker->Interrupt();
    }

    std::shared_ptr<ThumbnailGenerateWorker> thumbnailWorker =
        ThumbnailGenerateWorkerManager::GetInstance().GetThumbnailWorker(ThumbnailTaskType::BACKGROUND);
    if (thumbnailWorker == nullptr) {
        MEDIA_ERR_LOG("thumbnailWorker is null");
        return;
    }
    thumbnailWorker->ReleaseTaskQueue(ThumbnailTaskPriority::LOW);
}

void ThumbnailService::StopAllWorker()
{
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker != nullptr) {
        asyncWorker->Stop();
    }

    ThumbnailGenerateWorkerManager::GetInstance().ClearAllTask();
}

int32_t ThumbnailService::GenerateThumbnails()
{
    if (!CheckSizeValid()) {
        return E_THUMBNAIL_INVALID_SIZE;
    }
    int32_t err = 0;
    vector<string> tableList;
    tableList.emplace_back(PhotoColumn::PHOTOS_TABLE);
    tableList.emplace_back(AudioColumn::AUDIOS_TABLE);
    tableList.emplace_back(MEDIALIBRARY_TABLE);

    for (const auto &tableName : tableList) {
        ThumbRdbOpt opts = {
            .store = rdbStorePtr_,
#ifdef DISTRIBUTED
            .kvStore = kvStorePtr_,
#endif
            .table = tableName
        };

        if ((tableName == PhotoColumn::PHOTOS_TABLE) && ThumbnailUtils::IsSupportGenAstc()) {
            // CreateAstcBatch contains thumbnails created.
            err = ThumbnailGenerateHelper::CreateAstcBatch(opts);
            if (err != E_OK) {
                MEDIA_ERR_LOG("CreateAstcBatch failed : %{public}d", err);
            }
        } else {
            err = ThumbnailGenerateHelper::CreateThumbnailBatch(opts);
            if (err != E_OK) {
                MEDIA_ERR_LOG("CreateThumbnailBatch failed : %{public}d", err);
            }
        }

        if (tableName != AudioColumn::AUDIOS_TABLE) {
            err = ThumbnailGenerateHelper::CreateLcdBatch(opts);
            if (err != E_OK) {
                MEDIA_ERR_LOG("CreateLcdBatch failed : %{public}d", err);
            }
        }
    }

    return err;
}

int32_t ThumbnailService::LcdAging()
{
    int32_t err = 0;
    vector<string> tableList;
    tableList.emplace_back(PhotoColumn::PHOTOS_TABLE);
    tableList.emplace_back(AudioColumn::AUDIOS_TABLE);
    tableList.emplace_back(MEDIALIBRARY_TABLE);

    for (const auto &tableName : tableList) {
        ThumbRdbOpt opts = {
            .store = rdbStorePtr_,
#ifdef DISTRIBUTED
            .kvStore = kvStorePtr_,
#endif
            .table = tableName,
        };
        err = ThumbnailAgingHelper::AgingLcdBatch(opts);
        if (err != E_OK) {
            MEDIA_ERR_LOG("AgingLcdBatch failed : %{public}d", err);
        }
    }

    return E_OK;
}

#ifdef DISTRIBUTED
int32_t ThumbnailService::LcdDistributeAging(const string &udid)
{
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .kvStore = kvStorePtr_,
        .udid = udid
    };
    int32_t err = ThumbnailAgingHelper::AgingDistributeLcdBatch(opts);
    if (err != E_OK) {
        MEDIA_ERR_LOG("AgingDistributeLcdBatch failed : %{public}d", err);
        return err;
    }
    return E_OK;
}

int32_t ThumbnailService::InvalidateDistributeThumbnail(const string &udid)
{
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .kvStore = kvStorePtr_,
        .udid = udid
    };
    int32_t err = ThumbnailAgingHelper::InvalidateDistributeBatch(opts);
    if (err != E_OK) {
        MEDIA_ERR_LOG("InvalidateDistributeBatch failed : %{public}d", err);
    }
    return err;
}
#endif

void ThumbnailService::InvalidateThumbnail(const std::string &id,
    const std::string &tableName, const std::string &path, const std::string &dateAdded)
{
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .path = path,
        .table = tableName,
        .row = id,
        .dateAdded = dateAdded,
    };
    ThumbnailData thumbnailData;
    ThumbnailUtils::DeleteOriginImage(opts);
    if (opts.path.find(ROOT_MEDIA_DIR + PHOTO_BUCKET) != string::npos) {
        MediaLibraryPhotoOperations::RemoveThumbnailSizeRecord(id);
    }
}

int32_t ThumbnailService::GetAgingDataSize(const int64_t &time, int &count)
{
    int32_t err = 0;
    vector<string> tableList;
    tableList.emplace_back(PhotoColumn::PHOTOS_TABLE);
    tableList.emplace_back(AudioColumn::AUDIOS_TABLE);
    tableList.emplace_back(MEDIALIBRARY_TABLE);

    for (const auto &tableName : tableList) {
        ThumbRdbOpt opts = {
            .store = rdbStorePtr_,
#ifdef DISTRIBUTED
            .kvStore = kvStorePtr_,
#endif
            .table = tableName,
        };
        int tempCount = 0;
        err = ThumbnailAgingHelper::GetAgingDataCount(time, true, opts, tempCount);
        if (err != E_OK) {
            MEDIA_ERR_LOG("AgingLcdBatch failed : %{public}d", err);
            return err;
        }
        count += tempCount;
    }

    return err;
}

int32_t ThumbnailService::QueryNewThumbnailCount(const int64_t &time, int32_t &count)
{
    int32_t err = 0;
    vector<string> tableList;
    tableList.emplace_back(PhotoColumn::PHOTOS_TABLE);
    tableList.emplace_back(AudioColumn::AUDIOS_TABLE);
    tableList.emplace_back(MEDIALIBRARY_TABLE);

    for (const auto &tableName : tableList) {
        ThumbRdbOpt opts = {
            .store = rdbStorePtr_,
#ifdef DISTRIBUTED
            .kvStore = kvStorePtr_,
#endif
            .table = tableName
        };
        int32_t tempCount = 0;
        err = ThumbnailGenerateHelper::GetNewThumbnailCount(opts, time, tempCount);
        if (err != E_OK) {
            MEDIA_ERR_LOG("CreateThumbnailBatch failed : %{public}d", err);
            return err;
        }
        count += tempCount;
    }
    return E_OK;
}

int32_t ThumbnailService::CreateAstcFromFileId(const string &id)
{
    ThumbnailData data;
    data.isCloudLoading = true;
    ThumbnailUtils::RecordStartGenerateStats(data.stats, GenerateScene::CLOUD,
        LoadSourceType::CLOUD_THUMB);
    int err = 0;
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
#ifdef DISTRIBUTED
        .kvStore = kvStorePtr_,
#endif
        .table = PhotoColumn::PHOTOS_TABLE
    };

    ThumbnailUtils::QueryThumbnailDataFromFileId(opts, id, data, err);
    if (err != E_OK) {
        return err;
    }

    IThumbnailHelper::AddThumbnailGenerateTask(
        IThumbnailHelper::CreateAstc, opts, data, ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::HIGH);
    return E_OK;
}

} // namespace Media
} // namespace OHOS
