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

#include "background_task_mgr_helper.h"
#include "ipc_skeleton.h"
#include "display_manager.h"
#include "media_column.h"
#include "medialibrary_async_worker.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_unistore_manager.h"
#include "media_log.h"
#include "result_set_utils.h"
#include "thumbnail_aging_helper.h"
#include "thumbnail_const.h"
#include "thumbnail_generate_helper.h"
#include "thumbnail_helper_factory.h"
#include "thumbnail_uri_utils.h"
#include "post_event_utils.h"
#include "resource_type.h"

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

static void CreateAstcBackground(AsyncTaskData *data)
{
    BackgroundTaskMgr::EfficiencyResourceInfo resourceInfo = BackgroundTaskMgr::EfficiencyResourceInfo(
        BackgroundTaskMgr::ResourceType::CPU, true, 0, "apply", true, true);
    BackgroundTaskMgr::BackgroundTaskMgrHelper::ApplyEfficiencyResources(resourceInfo);
    auto rdbStoreRaw = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStoreRaw == nullptr) {
        MEDIA_ERR_LOG("Can not get rdbStoreRaw");
        return;
    }

    auto rdbStore = rdbStoreRaw->GetRaw();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("Can not get rdbStore");
        return;
    }

    ThumbnailData thumbnailData;
    ThumbRdbOpt opts = {
        .store = rdbStore,
        .table = PhotoColumn::PHOTOS_TABLE,
    };
    ThumbnailGenerateHelper::CreateAstcBatch(opts);
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

    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker == nullptr) {
        MEDIA_ERR_LOG("Can not get asyncWorker");
        return;
    }
    shared_ptr<MediaLibraryAsyncTask> astcBackgroundTask =
        make_shared<MediaLibraryAsyncTask>(CreateAstcBackground, nullptr);
    if (astcBackgroundTask != nullptr) {
        asyncWorker->AddTask(astcBackgroundTask, false);
    } else {
        MEDIA_ERR_LOG("Can not create astc batch task");
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
    bool isThumbnail = IsThumbnail(size.width, size.height);
    shared_ptr<IThumbnailHelper> thumbnailHelper =
        ThumbnailHelperFactory::GetThumbnailHelper(isThumbnail
            ? ThumbnailHelperType::DEFAULT : ThumbnailHelperType::LCD);
    if (thumbnailHelper == nullptr) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, E_NO_MEMORY},
            {KEY_OPT_FILE, uri}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return E_NO_MEMORY;
    }
    if (!isThumbnail) {
        opts.screenSize = screenSize_;
    }
    int fd = thumbnailHelper->GetThumbnailPixelMap(opts, size, isAstc);
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

int32_t ThumbnailService::CreateThumbnailInfo(const string &path, const string &tableName, const string &fileId,
    const string &uri, const bool &isSync)
{
    int32_t err = CreateDefaultThumbnail(path, tableName, fileId, uri, isSync);
    if (err != E_OK) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_FILE, uri}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        MEDIA_ERR_LOG("CreateDefaultThumbnail failed");
        return err;
    }

    err = CreateLcdThumbnail(path, tableName, fileId, isSync);
    if (err != E_OK) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_FILE, uri}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        MEDIA_ERR_LOG("CreateLcdThumbnail failed");
        return err;
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
    }

    err = CreateThumbnailInfo(path, tableName, fileId, uri, isSync);
    if (err != E_OK) {
        VariantMap map = {{KEY_ERR_FILE, __FILE__}, {KEY_ERR_LINE, __LINE__}, {KEY_ERR_CODE, err},
            {KEY_OPT_FILE, uri}, {KEY_OPT_TYPE, OptType::THUMB}};
        PostEventUtils::GetInstance().PostErrorProcess(ErrType::FILE_OPT_ERR, map);
        return err;
    }

    return E_OK;
}

int32_t ThumbnailService::CreateDefaultThumbnail(const std::string &path,
    const std::string &tableName, const std::string &fileId, const std::string &uri, const bool &isSync)
{
    std::string dateAdded = ThumbnailUriUtils::GetDateAddedFromUri(uri);
    std::string fileUri = ThumbnailUriUtils::GetFileUriFromUri(uri);
    shared_ptr<IThumbnailHelper> thumbnailHelper =
        ThumbnailHelperFactory::GetThumbnailHelper(ThumbnailHelperType::DEFAULT);
    if (thumbnailHelper == nullptr) {
        MEDIA_ERR_LOG("thumbnailHelper nullptr");
        return E_ERR;
    }
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .path = path,
        .table = tableName,
        .row = fileId,
        .dateAdded = dateAdded,
        .fileUri = fileUri,
        .screenSize = screenSize_
    };
    int32_t err = thumbnailHelper->CreateThumbnail(opts, isSync);
    if (err != E_OK) {
        MEDIA_ERR_LOG("CreateThumbnail failed : %{public}d", err);
        return err;
    }
    return E_OK;
}

int32_t ThumbnailService::CreateLcdThumbnail(const std::string &path,
    const std::string &tableName, const std::string &fileId, const bool &isSync)
{
    shared_ptr<IThumbnailHelper> lcdHelper = ThumbnailHelperFactory::GetThumbnailHelper(ThumbnailHelperType::LCD);
    if (lcdHelper == nullptr) {
        MEDIA_ERR_LOG("lcdHelper nullptr");
        return E_ERR;
    }
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .path = path,
        .table = tableName,
        .row = fileId,
        .screenSize = screenSize_
    };
    int32_t err = lcdHelper->CreateThumbnail(opts, isSync);
    if (err != E_OK) {
        MEDIA_ERR_LOG("CreateLcd failed : %{public}d", err);
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
}

void ThumbnailService::StopAllWorker()
{
    shared_ptr<MediaLibraryAsyncWorker> asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    if (asyncWorker != nullptr) {
        asyncWorker->Stop();
    }
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

void ThumbnailService::InvalidateThumbnail(const std::string &id, const std::string &tableName, const std::string &path)
{
    ThumbRdbOpt opts = {
        .store = rdbStorePtr_,
        .path = path,
        .table = tableName,
        .row = id,
    };
    ThumbnailData thumbnailData;
    ThumbnailUtils::DeleteOriginImage(opts);
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

    IThumbnailHelper::AddAsyncTask(IThumbnailHelper::CreateAstc, opts, data, true);
    return E_OK;
}

} // namespace Media
} // namespace OHOS
