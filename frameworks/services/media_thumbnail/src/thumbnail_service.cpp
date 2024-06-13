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
#include "media_file_utils.h"
#include "medialibrary_async_worker.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_kvstore_manager.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_type_const.h"
#include "medialibrary_unistore_manager.h"
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

static void UpdateAstcInfo(ThumbRdbOpt &opts, std::string id)
{
    if (id.empty()) {
        return;
    }

    ValuesBucket values;
    int changedRows;
    values.PutLong(PhotoColumn::PHOTO_HAS_ASTC, static_cast<int64_t>(ThumbnailReady::GENERATE_THUMB_COMPLETED));
    int32_t err = opts.store->Update(changedRows, opts.table, values, MEDIA_DATA_DB_ID + " = ?", vector<string> { id });
    if (err != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("RdbStore Update failed! %{public}d", err);
    }
}

static void PerformKvStoreUpdateTask(std::shared_ptr<ThumbnailTaskData> &data)
{
    vector<ThumbnailData> infos;
    if (!ThumbnailUtils::QueryOldAstcInfos(data->opts_.store, PhotoColumn::PHOTOS_TABLE, infos)) {
        return;
    }
    MEDIA_INFO_LOG("Old astc data size: %{public}d", static_cast<int>(infos.size()));
    if (infos.empty()) {
        return;
    }

    std::shared_ptr<MediaLibraryKvStore> monthOldKvStore = std::make_shared<MediaLibraryKvStore>();
    int32_t status = monthOldKvStore->Init(
        KvStoreRoleType::OWNER, KvStoreValueType::MONTH_ASTC_OLD_VERSION, KV_STORE_OWNER_DIR_OLD_VERSION);
    auto monthNewKvStore = MediaLibraryKvStoreManager::GetInstance()
        .GetKvStore(KvStoreRoleType::OWNER, KvStoreValueType::MONTH_ASTC);
    if (status != E_OK || monthNewKvStore == nullptr) {
        MEDIA_ERR_LOG("Init month kvStore failed, status %{public}d", status);
        return;
    }
    std::shared_ptr<MediaLibraryKvStore> yearOldKvStore = std::make_shared<MediaLibraryKvStore>();
    status = yearOldKvStore->Init(
        KvStoreRoleType::OWNER, KvStoreValueType::YEAR_ASTC_OLD_VERSION, KV_STORE_OWNER_DIR_OLD_VERSION);
    auto yearNewKvStore = MediaLibraryKvStoreManager::GetInstance()
        .GetKvStore(KvStoreRoleType::OWNER, KvStoreValueType::YEAR_ASTC);
    if (status != E_OK || yearNewKvStore == nullptr) {
        MEDIA_ERR_LOG("Init year kvStore failed, status %{public}d", status);
        return;
    }
    for (uint32_t i = 0; i < infos.size(); i++) {
        std::string oldKey;
        std::string newKey;
        if (!ThumbnailUtils::GenerateOldKvStoreKey(infos[i].id, infos[i].dateAdded, oldKey) ||
            !ThumbnailUtils::GenerateKvStoreKey(infos[i].id, infos[i].dateAdded, newKey)) {
            continue;
        }
        std::vector<uint8_t> monthValue;
        if (monthOldKvStore->Query(oldKey, monthValue) != E_OK || monthNewKvStore->Insert(newKey, monthValue) != E_OK) {
            MEDIA_ERR_LOG("MonthValue update failed, fileID %{public}s", infos[i].id.c_str());
            continue;
        }
        std::vector<uint8_t> yearValue;
        if (yearOldKvStore->Query(oldKey, yearValue) != E_OK || yearNewKvStore->Insert(newKey, yearValue) != E_OK) {
            MEDIA_ERR_LOG("YearValue update failed, fileID %{public}s", infos[i].id.c_str());
            continue;
        }
        UpdateAstcInfo(data->opts_, infos[i].id);
    }
    monthOldKvStore->Close();
    yearOldKvStore->Close();
    MEDIA_INFO_LOG("PerformKvStoreUpdateTask End");
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

    std::shared_ptr<ThumbnailGenerateWorker> thumbnailWorker =
        ThumbnailGenerateWorkerManager::GetInstance().GetThumbnailWorker(ThumbnailTaskType::BACKGROUND);
    if (thumbnailWorker == nullptr || rdbStorePtr_ == nullptr) {
        MEDIA_ERR_LOG("thumbnailWorker or rdbStorePtr_ is null");
        return;
    }
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .table = PhotoColumn::PHOTOS_TABLE,
    };
    ThumbnailData data;
    std::shared_ptr<ThumbnailTaskData> taskData = std::make_shared<ThumbnailTaskData>(opts, data);
    std::shared_ptr<ThumbnailGenerateTask> kvStoreUpdateTask =
        std::make_shared<ThumbnailGenerateTask>(PerformKvStoreUpdateTask, taskData);
    thumbnailWorker->AddTask(kvStoreUpdateTask, ThumbnailTaskPriority::HIGH);
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
        MEDIA_ERR_LOG("GetThumbnailPixelMap failed : %{public}d", fd);
    }
    return fd;
}

int ThumbnailService::GetThumbnailFd(const string &uri, bool isAstc)
{
    if (!CheckSizeValid()) {
        MEDIA_ERR_LOG("GetThumbnailFd failed for invaild size, uri: %{public}s", uri.c_str());
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

int32_t ThumbnailService::CreateThumbnailFileScaned(const std::string &uri, const string &path, bool isSync)
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

    err = ThumbnailGenerateHelper::CreateThumbnailFileScaned(opts, isSync);
    if (err != E_OK) {
        MEDIA_ERR_LOG("CreateThumbnailFileScaned failed : %{public}d", err);
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

int32_t ThumbnailService::GenerateThumbnailBackground()
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
            // CreateAstcBackground contains thumbnails created.
            err = ThumbnailGenerateHelper::CreateAstcBackground(opts);
            if (err != E_OK) {
                MEDIA_ERR_LOG("CreateAstcBackground failed : %{public}d", err);
            }
        } else {
            err = ThumbnailGenerateHelper::CreateThumbnailBackground(opts);
            if (err != E_OK) {
                MEDIA_ERR_LOG("CreateThumbnailBackground failed : %{public}d", err);
            }
        }

        if (tableName != AudioColumn::AUDIOS_TABLE) {
            err = ThumbnailGenerateHelper::CreateLcdBackground(opts);
            if (err != E_OK) {
                MEDIA_ERR_LOG("CreateLcdBackground failed : %{public}d", err);
            }
        }
    }

    return err;
}

int32_t ThumbnailService::UpgradeThumbnailBackground()
{
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .table = PhotoColumn::PHOTOS_TABLE
    };
    int32_t err = ThumbnailGenerateHelper::UpgradeThumbnailBackground(opts);
    if (err != E_OK) {
        MEDIA_ERR_LOG("UpgradeThumbnailBackground failed : %{public}d", err);
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
        MediaLibraryPhotoOperations::DropThumbnailSize(id);
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
            MEDIA_ERR_LOG("GetNewThumbnailCount failed : %{public}d", err);
            return err;
        }
        count += tempCount;
    }
    return E_OK;
}

int32_t ThumbnailService::CreateAstcCloudDownload(const string &id)
{
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .table = PhotoColumn::PHOTOS_TABLE,
        .fileId = id,
    };

    int err = ThumbnailGenerateHelper::CreateAstcCloudDownload(opts);
    if (err != E_OK) {
        MEDIA_ERR_LOG("CreateAstcCloudDownload failed : %{public}d", err);
        return err;
    }
    return err;
}

int32_t ThumbnailService::CreateAstcBatchOnDemand(NativeRdb::RdbPredicates &rdbPredicate, int32_t requestId)
{
    CancelAstcBatchTask(requestId - 1);
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .table = PhotoColumn::PHOTOS_TABLE
    };
    return ThumbnailGenerateHelper::CreateAstcBatchOnDemand(opts, rdbPredicate, requestId);
}

void ThumbnailService::CancelAstcBatchTask(int32_t requestId)
{
    MEDIA_INFO_LOG("CancelAstcBatchTask requestId: %{public}d", requestId);
    std::shared_ptr<ThumbnailGenerateWorker> thumbnailWorker =
        ThumbnailGenerateWorkerManager::GetInstance().GetThumbnailWorker(ThumbnailTaskType::FOREGROUND);
    if (thumbnailWorker == nullptr) {
        MEDIA_ERR_LOG("thumbnailWorker is null");
        return;
    }
    thumbnailWorker->IgnoreTaskByRequestId(requestId);
}

void ThumbnailService::DeleteAstcWithFileIdAndDateAdded(const std::string &fileId, const std::string &dateAdded)
{
    ThumbnailData data;
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .table = PhotoColumn::PHOTOS_TABLE,
        .row = fileId,
        .dateAdded = dateAdded
    };

    IThumbnailHelper::AddThumbnailGenerateTask(IThumbnailHelper::DeleteMonthAndYearAstc,
        opts, data, ThumbnailTaskType::BACKGROUND, ThumbnailTaskPriority::HIGH);
}
} // namespace Media
} // namespace OHOS
